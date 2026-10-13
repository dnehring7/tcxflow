// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file tcxflow.bpf.c
 * @brief BPF program: flow metering on tcx ingress and egress
 *
 * Every IPv4/IPv6 packet on an attached interface is added to one of two flow maps;
 * active[0] points to the one being written. Once per second the exporter points
 * active[0] at the other map and drains the idle one. active is an array of maps: the
 * kernel waits for every running program to finish before an update of it returns, so
 * the idle map is never written while it is being read. Packets are never modified or
 * dropped: every path returns TCX_NEXT, so other tcx programs on the same hook still run.
 */

#include <linux/types.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "flow.h"

static constexpr __u16 IP_MF = 0x2000;         ///< more fragments flag of iphdr.frag_off
static constexpr __u16 IP_OFFSET = 0x1fff;     ///< fragment offset bits of iphdr.frag_off
static constexpr __u8 ECN_MASK = 0x03;         ///< ECN bits of the TOS / traffic class byte
static constexpr int VLAN_MAX = 2;             ///< VLAN tags in the packet parsed at most (QinQ)
static constexpr __u16 VLAN_VID_MASK = 0x0fff; ///< VLAN ID bits of a tag control information field
static constexpr int IPV6_EXT_MAX = 6;         ///< IPv6 extension headers parsed: each once, destination options twice
static constexpr __u32 BIG_LEN = 65535;        ///< longest packet a length field can describe
static constexpr int CAS_TRIES = 8;            ///< compare-and-swap attempts on a timestamp before giving up
static constexpr __u8 NEXTHDR_HOP = 0;         ///< IPv6 hop-by-hop options header
static constexpr __u8 NEXTHDR_ROUTING = 43;    ///< IPv6 routing header
static constexpr __u8 NEXTHDR_FRAG = 44;       ///< IPv6 fragment header
static constexpr __u8 NEXTHDR_AUTH = 51;       ///< IPv6 authentication header
static constexpr __u8 NEXTHDR_DEST = 60;       ///< IPv6 destination options header
static constexpr __u8 PROTO_ICMPV6 = 58;       ///< IPPROTO_ICMPV6

static_assert(sizeof(struct flow_key) == 56, "flow_key layout");
static_assert(sizeof(struct flow_val) == 40, "flow_val layout");

/*
 * Maps: flows0 and flows1 hold the flows of one interval each, active[0] points to the one
 * the program writes to (set by the exporter), stats holds per-CPU counters. Hidden from
 * Doxygen (libbpf macros).
 *
 * Two maps, swapped once per second, instead of userspace reading and deleting entries in
 * the live map: the kernel and the exporter never touch the same entry, a whole map is
 * emptied with a few batch calls, and the maps only need to hold one second of flows.
 * Hash maps are preallocated (the default), so the packet path never allocates memory.
 */
/// @cond BPF_MAPS
struct flow_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072); // set by the exporter (max-flows)
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flows0 SEC(".maps"), flows1 SEC(".maps");

// Inner map template of active: the kernel compares type, key and value size, not max_entries,
// so one entry keeps the template libbpf creates (and frees) during loading small.
struct flow_map_template {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct flow_map_template);
} active SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct flow_stats);
} stats SEC(".maps");

/*
 * The kernel's struct sk_buff, only the fields read here: CO-RE takes their offsets from the
 * running kernel's BTF. bpf_cast_to_kern_ctx() makes them readable; the verifier turns the call
 * into a register copy.
 */
struct [[clang::preserve_access_index]] sk_buff {
    unsigned char *head;
    unsigned char *data;
    __u16 network_header;
};

extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;
/// @endcond

/* Add to two per-CPU counters: per CPU, so that no atomic operation is needed. */
static __always_inline void count(__u32 idx, __u64 n, __u32 idx2, __u64 n2) {
    __u32 zero = 0;
    struct flow_stats *st = bpf_map_lookup_elem(&stats, &zero);

    if (st && idx < STAT_MAX && idx2 < STAT_MAX) {
        st->c[idx] += n;
        st->c[idx2] += n2;
    }
}

static __always_inline void count_one(__u32 idx) { count(idx, 1, idx, 0); }

/*
 * Move a timestamp forward (later) or backward (earlier) to now. Another CPU can store between the
 * read and the compare-and-swap: then try again from the value it stored, until ours sticks or
 * the stored one is already beyond now.
 */
static __always_inline void cas_time(__u64 *t, __u64 now, bool later) {
    __u64 seen = *t;

#pragma unroll
    for (int i = 0; i < CAS_TRIES && (later ? seen < now : now < seen); i++) {
        const __u64 prev = __sync_val_compare_and_swap(t, seen, now);

        if (prev == seen)
            break;
        seen = prev;
    }
}

static __always_inline bool ipv6_ext(__u8 nh) {
    return nh == NEXTHDR_HOP || nh == NEXTHDR_ROUTING || nh == NEXTHDR_DEST || nh == NEXTHDR_FRAG || nh == NEXTHDR_AUTH;
}

/**
 * Load sizeof(*dst) bytes at offset @p off from skb->data. Copies instead of direct packet
 * access: bpf_skb_load_bytes() also reads headers that some drivers (mlx4, gve) leave in paged
 * data, without changing the packet, and copying needs no bounds proofs for the verifier.
 */
#define LOAD(off, dst) bpf_skb_load_bytes(skb, (off), (dst), sizeof(*(dst)))

static __always_inline int account(struct __sk_buff *skb, enum flow_dir dir) {
    const struct sk_buff *kskb = bpf_cast_to_kern_ctx(skb);
    struct flow_key key = {};
    struct flow_val *val = nullptr;
    __be16 proto = (__be16)skb->protocol; // the upper 16 bits are always 0
    __u32 off = 0;
    __u32 l4off = 0;
    __u32 hdrs = 0;
    __u32 transient = 0;
    __u32 tcpfl = 0;
    __u32 need = 0;
    __u32 zero = 0;
    __u64 headroom = 0;
    __u64 l3len = 0;
    __u64 end = 0;
    __u64 pkts = 0;
    __u64 bytes = 0;
    __u64 now = 0;
    __u8 l4proto = 0;
    __u8 ecn = 0;
    // int, not bool: clang builds 7% more instructions around bool flags here, 2-3 ns per packet.
    int has_l4 = 1;
    int first_frag = 0;
    void *flows = nullptr;

    // Offsets count from skb->data, like skb->len, so that the lengths in the IP header can be
    // checked against the bytes really there. tc runs with skb->data at the link layer header, or
    // at the IP header on devices without one (WireGuard, tun, PPP): the network header tells.
    // The verifier allows the difference of two pointers only in 64 bits: barrier_var() keeps the
    // compiler from narrowing it.
    headroom = (__u64)kskb->data - (__u64)kskb->head;
    barrier_var(headroom);
    off = (__u32)(kskb->network_header - headroom);

    // The VLAN IDs are part of the key, so VLANs that reuse the same addresses never merge. The
    // outer tag is usually in the skb metadata: stripped by the NIC or the stack on ingress, not
    // inserted yet on egress. Tags still in the packet (QinQ) come after it.
    key.vlan = (__u16)(skb->vlan_tci & VLAN_VID_MASK);

    // VLAN tags left in the packet (QinQ, stacked VLAN devices): where the network header points
    // differs between ingress (the first tag) and egress (past the tags), so parse from the
    // Ethernet header at skb->data, whose ethertype at offset 12 is the first tag's TPID.
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        off = ETH_HLEN;
#pragma unroll
        for (int i = 0; i < VLAN_MAX; i++) {
            __be16 tag[2]; // TCI, then the ethertype it encapsulates

            if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
                break;
            if (LOAD(off, &tag))
                goto trunc;
            if (!key.vlan)
                key.vlan = bpf_ntohs(tag[0]) & VLAN_VID_MASK;
            else if (!key.vlan_inner)
                key.vlan_inner = bpf_ntohs(tag[0]) & VLAN_VID_MASK;
            proto = tag[1];
            off += sizeof(tag);
        }
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr ip;

        if (LOAD(off, &ip) || ip.version != 4 || ip.ihl < 5)
            goto trunc;
        key.ipver = 4;
        __builtin_memcpy(key.src, &ip.saddr, 4);
        __builtin_memcpy(key.dst, &ip.daddr, 4);
        key.tos = ip.tos & (__u8)~ECN_MASK; // ECN marks change within a flow: not part of the key
        ecn = ip.tos & ECN_MASK;
        l4proto = ip.protocol;
        l3len = bpf_ntohs(ip.tot_len);
        hdrs = ip.ihl * 4;
        l4off = off + hdrs;
        // Only a BIG TCP super-packet (GSO, over 64 KiB) has no length. Any other length that
        // contradicts the header or the packet is malformed: the stack drops such packets, and
        // fields read past the IP length would come from padding.
        if (!l3len && skb->gso_size && skb->len - off > BIG_LEN)
            l3len = skb->len - off;
        else if (l3len < hdrs || l3len > skb->len - off)
            goto trunc;
        if (ip.frag_off & bpf_htons(IP_OFFSET))
            has_l4 = 0; // only the first fragment carries the ports: later ones form their own flow
        else if (ip.frag_off & bpf_htons(IP_MF))
            first_frag = 1;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr ip6;
        __u8 tclass;
        __u8 nh;

        if (LOAD(off, &ip6) || ip6.version != 6)
            goto trunc;
        key.ipver = 6;
        __builtin_memcpy(key.src, &ip6.saddr, 16);
        __builtin_memcpy(key.dst, &ip6.daddr, 16);
        tclass = (__u8)((ip6.priority << 4) | (ip6.flow_lbl[0] >> 4));
        key.tos = tclass & (__u8)~ECN_MASK;
        ecn = tclass & ECN_MASK;
        l3len = bpf_ntohs(ip6.payload_len) + sizeof(ip6);
        l4off = off + sizeof(ip6);
        nh = ip6.nexthdr;
        // Payload length 0: an empty payload, a jumbogram (RFC 2675) or a BIG TCP super-packet. The
        // last two carry the length in a Jumbo Payload option, except BIG TCP of newer kernels.
        if (!ip6.payload_len) {
            __u8 jh[8]; // a Hop-by-Hop header with just that option: next, length 0, type, 4, length

            if (nh == NEXTHDR_HOP && !LOAD(l4off, &jh) && jh[1] == 0 && jh[2] == IPV6_TLV_JUMBO && jh[3] == 4) {
                l3len = sizeof(ip6) + (((__u32)jh[4] << 24) | ((__u32)jh[5] << 16) | ((__u32)jh[6] << 8) | jh[7]);
                if (l3len <= sizeof(ip6) + BIG_LEN) // a jumbo length must exceed 65535
                    goto trunc;
                // Linux puts this header on its BIG TCP super-packets and removes it before
                // segmentation: no segment on the wire carries it.
                if (skb->gso_size && jh[0] == IPPROTO_TCP)
                    transient = 8;
            } else if (skb->gso_size && skb->len - off > BIG_LEN) {
                l3len = skb->len - off;
            }
        }
        if (l3len > skb->len - off)
            goto trunc;
#pragma unroll
        for (int i = 0; i < IPV6_EXT_MAX; i++) {
            __u8 eh[8];

            if (!ipv6_ext(nh))
                break;
            if (l4off + sizeof(eh) > off + l3len || LOAD(l4off, &eh))
                goto trunc;
            if (nh == NEXTHDR_FRAG) {
                l4off += 8;
                if (((eh[2] << 8) | eh[3]) & 0xfff8) {
                    has_l4 = 0; // not the first fragment
                    nh = eh[0];
                    break;
                }
            } else if (nh == NEXTHDR_AUTH) {
                if (!eh[1]) // shorter than its SPI and sequence number (RFC 4302)
                    goto trunc;
                l4off += (eh[1] + 2U) * 4U;
            } else {
                l4off += (eh[1] + 1U) * 8U;
            }
            nh = eh[0];
            if (l4off > off + l3len)
                goto trunc;
        }
        // RFC 8200 asks receivers to accept longer chains, though senders should not build them:
        // counted without ports, with the header where parsing stopped as the protocol.
        if (has_l4 && ipv6_ext(nh))
            has_l4 = 0;
        l4proto = nh;
        hdrs = l4off - off;
    } else {
        count_one(STAT_NONIP);
        return TCX_NEXT;
    }
    key.proto = l4proto;
    end = off + l3len;

    // The transport header must fit into the IP length: fields read past it would come from
    // padding, and a flow with ports from padding (or none) would mix unrelated packets. Only the
    // first fragment of an IPv4 datagram may end inside it (fragments need just 8 bytes): it is
    // counted without ports, like the fragments after it. IPv6 has to carry the whole header chain
    // in the first fragment (RFC 8200), and the kernel drops first fragments that do not.
    if (has_l4) {
        if (l4proto == IPPROTO_TCP)
            need = 20;
        else if (l4proto == IPPROTO_SCTP || l4proto == IPPROTO_DCCP)
            need = 12;
        else if (l4proto == IPPROTO_UDP || l4proto == IPPROTO_UDPLITE)
            need = 8;
        else if (l4proto == IPPROTO_ICMP || l4proto == PROTO_ICMPV6)
            need = 4; // type, code, checksum
        if (l4off + need > end) {
            if (!first_frag)
                goto trunc;
            has_l4 = 0;
            need = 0;
        }
    }
    if (has_l4 && l4proto == IPPROTO_TCP) {
        __u8 th[14]; // ports, sequence, acknowledgment, data offset, flags

        if (LOAD(l4off, &th))
            goto trunc;
        need = (th[12] >> 4) * 4U;
        // A data offset below 5 words is no TCP header. Options past the IP length are padding,
        // except in a first fragment, which may end inside them.
        if (need < 20 || (l4off + need > end && !first_frag))
            goto trunc;
        __builtin_memcpy(&key.sport, &th[0], 2);
        __builtin_memcpy(&key.dport, &th[2], 2);
        tcpfl = th[13] | ((th[12] & 0x0fU) << 8); // all 12 bits besides the data offset
    } else if (has_l4 && (l4proto == IPPROTO_ICMP || l4proto == PROTO_ICMPV6)) {
        __u8 tc[2];

        if (LOAD(l4off, &tc))
            goto trunc;
        key.dport = bpf_htons((tc[0] << 8) | tc[1]);
    } else if (has_l4 && need) { // UDP, UDP-Lite, SCTP and DCCP start with the ports
        __be16 ports[4];         // UDP: then its length and checksum
        __u32 ulen = 0;

        if (LOAD(l4off, &ports))
            goto trunc;
        // The kernel drops UDP whose length is shorter than the header or longer than the IP
        // payload. Length 0 in IPv6 means a jumbogram (RFC 2675); the length in a first fragment
        // covers all fragments, in a GRO/GSO packet it is the stack's.
        ulen = bpf_ntohs(ports[2]);
        if (l4proto == IPPROTO_UDP &&
            ((ulen < 8 && (ulen || key.ipver != 6)) || (ulen > end - l4off && !first_frag && !skb->gso_size)))
            goto trunc;
        key.sport = ports[0];
        key.dport = ports[1];
    }
    hdrs += need;

    // GRO/TSO super-packets: count every segment with its own headers. Untrusted GSO packets
    // (virtio-net, tun/tap) come with gso_segs 0: derive the count from gso_size like the kernel.
    pkts = skb->gso_segs;
    if (!pkts && skb->gso_size && l3len > hdrs)
        pkts = (l3len - hdrs + skb->gso_size - 1) / skb->gso_size;
    if (!pkts)
        pkts = 1;
    bytes = l3len - transient + ((pkts - 1) * (hdrs - transient));

    // Interfaces are part of the key: one record per interface and direction, like the NetFlow
    // of a hardware router, so the same traffic seen on two interfaces is never merged.
    key.dir = dir;
    if (dir == FLOW_DIR_IN) {
        key.in_if = skb->ifindex;
    } else {
        key.out_if = skb->ifindex;
        key.in_if = skb->ingress_ifindex; // 0 if sent by this host
    }

    flows = bpf_map_lookup_elem(&active, &zero);
    if (!flows) // not set yet: the exporter fills active[0] before attaching
        return TCX_NEXT;
    now = bpf_ktime_get_coarse_ns(); // cheaper than a clock read; jiffies resolution suits flow times

    // Most packets belong to a known flow: one lookup. A new flow is inserted with BPF_NOEXIST, so
    // when the first packets arrive on two CPUs at once, the loser adds to the winner's entry.
    val = bpf_map_lookup_elem(flows, &key);
    if (!val) {
        struct flow_val nv = {
            .first_ns = now,
            .last_ns = now,
            .packets = pkts,
            .bytes = bytes,
            .tcp_flags = tcpfl,
            .ecn = ecn, // the key has only the DSCP: the TOS byte exported is that of the first packet
        };

        if (!bpf_map_update_elem(flows, &key, &nv, BPF_NOEXIST))
            return TCX_NEXT;
        val = bpf_map_lookup_elem(flows, &key); // lost a race, or the map is full
        if (!val) {
            count(STAT_FULL_PKTS, pkts, STAT_FULL_BYTES, bytes);
            return TCX_NEXT;
        }
        // Lost the race: the winner's clock reading may be later than this packet's.
        cas_time(&val->first_ns, now, false);
    }
    // Atomic: one flow can be counted on several CPUs at once (egress of local traffic, RSS).
    __sync_fetch_and_add(&val->packets, pkts);
    __sync_fetch_and_add(&val->bytes, bytes);
    // last_ns only moves forward: CPUs read the coarse clock at slightly different moments, and a
    // plain store could put an older time over a newer one, even before first_ns. The clock ticks
    // once per jiffy, so the compare-and-swap runs about once per jiffy per flow, not per packet.
    if (val->last_ns < now)
        cas_time(&val->last_ns, now, true);
    if ((val->tcp_flags | tcpfl) != val->tcp_flags) // flags rarely change: skip the atomic OR
        __sync_fetch_and_or(&val->tcp_flags, tcpfl);
    return TCX_NEXT;

trunc:
    count_one(STAT_TRUNC);
    return TCX_NEXT;
}

int tcxflow_ingress(struct __sk_buff *skb);
int tcxflow_egress(struct __sk_buff *skb);

/**
 * tcx ingress program: account the packet as inbound.
 *
 * @param skb  the packet
 * @return TCX_NEXT: the packet always continues unchanged
 */
SEC("tcx/ingress")
int tcxflow_ingress(struct __sk_buff *skb) { return account(skb, FLOW_DIR_IN); }

/**
 * tcx egress program: account the packet as outbound.
 *
 * @param skb  the packet
 * @return TCX_NEXT: the packet always continues unchanged
 */
SEC("tcx/egress")
int tcxflow_egress(struct __sk_buff *skb) { return account(skb, FLOW_DIR_OUT); }

/**
 * Program license as seen by the kernel: "GPL" means GPL v2 or later, as for kernel modules,
 * matching the SPDX identifier above. It also lets the program use GPL-only helpers.
 */
char LICENSE[] SEC("license") = "GPL";
