// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file test_bpf.c
 * @brief BPF program tests: hand-built packets through BPF_PROG_TEST_RUN
 *
 * Loads the embedded BPF program like the daemon does, feeds it packets with
 * bpf_prog_test_run_opts() and checks the flow maps and statistics. Needs root
 * (CAP_BPF + CAP_NET_ADMIN) but no interfaces: `sudo make test-bpf`.
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/sockios.h> // IWYU pragma: keep (SIOCGIFFLAGS: glibc versions differ in where it comes from)
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>

#include "flow.h"
#include "meter.h"
#include "test.h"

static constexpr uint32_t MAX_FLOWS = 1024; // smallest allowed flow table, makes the overflow test quick
static constexpr int LO_IFINDEX = 1;        // BPF_PROG_TEST_RUN runs the program on the loopback device

static struct meter m;

/* ------------------------------------------------------------------ */
/* Packet builder                                                     */

struct pkt {
    uint8_t data[256];
    size_t len;
};

static void put(struct pkt *p, const void *src, size_t len) {
    if (p->len + len > sizeof(p->data))
        abort(); // a test builds a packet too large for the buffer
    memcpy(p->data + p->len, src, len);
    p->len += len;
}

static void put8(struct pkt *p, uint8_t v) { put(p, &v, 1); }

static void put16(struct pkt *p, uint16_t v) {
    const uint16_t be = htons(v);

    put(p, &be, 2);
}

static void put32(struct pkt *p, uint32_t v) {
    const uint32_t be = htonl(v);

    put(p, &be, 4);
}

static void put_zero(struct pkt *p, size_t len) {
    if (p->len + len > sizeof(p->data))
        abort();
    memset(p->data + p->len, 0, len);
    p->len += len;
}

static void put_addr(struct pkt *p, int af, const char *addr) {
    uint8_t buf[16];

    (void)inet_pton(af, addr, buf);
    put(p, buf, af == AF_INET ? 4 : 16);
}

static void eth(struct pkt *p, uint16_t ethertype) {
    static const uint8_t macs[12] = {2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2};

    p->len = 0;
    put(p, macs, sizeof(macs));
    put16(p, ethertype);
}

/* IPv4 header; payload_len bytes must follow. */
static void ipv4(struct pkt *p, uint8_t proto, uint8_t tos, uint16_t frag_off, uint16_t payload_len) {
    put8(p, 0x45);
    put8(p, tos);
    put16(p, (uint16_t)(20 + payload_len));
    put16(p, 1);
    put16(p, frag_off);
    put8(p, 64);
    put8(p, proto);
    put16(p, 0); // checksum: not checked by the program
    put_addr(p, AF_INET, "192.0.2.1");
    put_addr(p, AF_INET, "198.51.100.2");
}

static void ipv6(struct pkt *p, uint8_t nexthdr, uint8_t tclass, uint16_t payload_len) {
    put32(p, (6U << 28) | ((uint32_t)tclass << 20));
    put16(p, payload_len);
    put8(p, nexthdr);
    put8(p, 64);
    put_addr(p, AF_INET6, "2001:db8::1");
    put_addr(p, AF_INET6, "2001:db8::2");
}

static void tcp(struct pkt *p, uint16_t sport, uint16_t dport, uint8_t flags, size_t payload) {
    put16(p, sport);
    put16(p, dport);
    put32(p, 1); // sequence
    put32(p, 0); // acknowledgment
    put8(p, 5 << 4);
    put8(p, flags);
    put16(p, 65535);
    put32(p, 0); // checksum, urgent pointer
    put_zero(p, payload);
}

static void udp(struct pkt *p, uint16_t sport, uint16_t dport, size_t payload) {
    put16(p, sport);
    put16(p, dport);
    put16(p, (uint16_t)(8 + payload));
    put16(p, 0);
    put_zero(p, payload);
}

/* ------------------------------------------------------------------ */
/* Running the program and reading the result                         */

/* Run one packet through the ingress or egress program. */
static void run_gso(const struct pkt *p, enum flow_dir dir, uint32_t gso_segs, uint32_t gso_size,
                    uint32_t ingress_ifindex) {
    struct __sk_buff ctx;
    LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = p->data, .data_size_in = (uint32_t)p->len, .ctx_in = &ctx,
                .ctx_size_in = sizeof(ctx), .repeat = 1);
    int err = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.gso_segs = gso_segs;
    ctx.gso_size = gso_size;
    ctx.ingress_ifindex = ingress_ifindex;
    err = bpf_prog_test_run_opts(bpf_program__fd(m.prog[dir]), &opts);
    CHECK_EQ(err, 0);
    CHECK_EQ(opts.retval, (uint32_t)TCX_NEXT); // never drops, never stops other programs
}

static void run(const struct pkt *p, enum flow_dir dir, uint32_t gso_segs, uint32_t ingress_ifindex) {
    run_gso(p, dir, gso_segs, 0, ingress_ifindex);
}

static constexpr int MAX_SEEN = 2048;
static struct {
    struct flow_key key;
    struct flow_val val;
} seen[MAX_SEEN];
static int n_seen;

static void collect([[maybe_unused]] void *ctx, const struct flow_key *key, const struct flow_val *val) {
    if (n_seen < MAX_SEEN) {
        seen[n_seen].key = *key;
        seen[n_seen].val = *val;
    }
    n_seen++;
}

/* Drain both flow maps; the flows are then in seen[0..n_seen). */
static void drain(void) {
    n_seen = 0;
    CHECK(meter_drain(&m, 0, collect, nullptr) >= 0);
    CHECK(meter_drain(&m, 1, collect, nullptr) >= 0);
}

static uint64_t stat(enum flow_stat idx) {
    uint64_t st[STAT_MAX];

    CHECK_EQ(meter_stats(&m, st), 0);
    return st[idx];
}

/* ------------------------------------------------------------------ */
/* Tests                                                              */

static void test_ipv4_tcp(void) {
    struct pkt p;
    uint8_t addr[4];

    eth(&p, 0x0800);
    ipv4(&p, 6, 0x28, 0, 20 + 100);
    tcp(&p, 40000, 443, 0x02, 100);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.ipver, 4);
    CHECK_EQ(seen[0].key.proto, 6);
    CHECK_EQ(ntohs(seen[0].key.sport), 40000);
    CHECK_EQ(ntohs(seen[0].key.dport), 443);
    CHECK_EQ(seen[0].key.tos, 0x28);
    CHECK_EQ(seen[0].key.dir, FLOW_DIR_IN);
    CHECK_EQ(seen[0].key.in_if, LO_IFINDEX);
    CHECK_EQ(seen[0].key.out_if, 0);
    CHECK_EQ(seen[0].key.vlan, 0); // untagged
    CHECK_EQ(seen[0].key.pad, 0);
    (void)inet_pton(AF_INET, "192.0.2.1", addr);
    CHECK(memcmp(seen[0].key.src, addr, 4) == 0);
    CHECK_EQ(seen[0].val.packets, 1);
    CHECK_EQ(seen[0].val.bytes, 20 + 20 + 100); // layer 3 bytes
    CHECK_EQ(seen[0].val.tcp_flags, 0x02);
    CHECK(seen[0].val.first_ns > 0 && seen[0].val.last_ns >= seen[0].val.first_ns);
}

static void test_tcp_flags_accumulate(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 20);
    tcp(&p, 1000, 80, 0x02, 0); // SYN
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 20);
    tcp(&p, 1000, 80, 0x11, 0); // FIN + ACK
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 20);
    tcp(&p, 1000, 80, 0x10, 0);
    p.data[14 + 20 + 12] |= 0x0e; // the three reserved bits, kept like the others
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].val.packets, 3);
    CHECK_EQ(seen[0].val.bytes, 3 * 40);
    CHECK_EQ(seen[0].val.tcp_flags, 0xe13);
}

static void test_ipv4_udp_and_icmp(void) {
    struct pkt p;
    int udp_idx = 0;

    eth(&p, 0x0800);
    ipv4(&p, 17, 0, 0, 8 + 50);
    udp(&p, 5353, 53, 50);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800);
    ipv4(&p, 1, 0, 0, 8);
    put8(&p, 8); // echo request
    put8(&p, 0);
    put_zero(&p, 6);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 2);
    udp_idx = seen[0].key.proto == 17 ? 0 : 1;
    CHECK_EQ(ntohs(seen[udp_idx].key.dport), 53);
    CHECK_EQ(seen[udp_idx].val.bytes, 20 + 8 + 50);
    CHECK_EQ(seen[1 - udp_idx].key.proto, 1);
    CHECK_EQ(ntohs(seen[1 - udp_idx].key.dport), 0x0800); // ICMP type << 8 | code
    CHECK_EQ(seen[1 - udp_idx].key.sport, 0);
}

static constexpr uint16_t IP_MF = 0x2000; // more fragments

static void test_ipv4_fragment(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 17, 0, 100, 40); // fragment offset 100 * 8: no UDP header in this packet
    put_zero(&p, 40);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 17);
    CHECK_EQ(seen[0].key.sport, 0);
    CHECK_EQ(seen[0].key.dport, 0);
    CHECK_EQ(seen[0].val.bytes, 60);
}

/* The first fragment has the ports; IPv4 also allows one that ends inside the transport header. */
static void test_ipv4_first_fragments(void) {
    struct pkt p;
    int full = 0;

    eth(&p, 0x0800);
    ipv4(&p, 17, 0, IP_MF, 8 + 32);
    udp(&p, 5353, 53, 32);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800);
    ipv4(&p, 6, 0, IP_MF, 16); // 16 of the 20 bytes of a TCP header
    tcp(&p, 1000, 80, 0x02, 0);
    p.len -= 4;
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 2);
    full = seen[0].key.proto == 17 ? 0 : 1;
    CHECK_EQ(ntohs(seen[full].key.dport), 53);
    CHECK_EQ(seen[full].val.bytes, 20 + 8 + 32);
    CHECK_EQ(seen[1 - full].key.proto, 6); // counted, but without ports
    CHECK_EQ(seen[1 - full].key.dport, 0);
    CHECK_EQ(seen[1 - full].val.bytes, 20 + 16);
}

/* DCCP has its ports where UDP has them. */
static void test_dccp_ports(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 33, 0, 0, 12);
    put16(&p, 5004);
    put16(&p, 6004);
    put_zero(&p, 8);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 33);
    CHECK_EQ(ntohs(seen[0].key.sport), 5004);
    CHECK_EQ(ntohs(seen[0].key.dport), 6004);
}

static void test_ipv6_icmpv6(void) {
    struct pkt p;

    eth(&p, 0x86dd);
    ipv6(&p, 58, 0xb8, 64);
    put8(&p, 128); // echo request
    put8(&p, 0);
    put_zero(&p, 62);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.ipver, 6);
    CHECK_EQ(seen[0].key.proto, 58);
    CHECK_EQ(seen[0].key.tos, 0xb8); // traffic class
    CHECK_EQ(ntohs(seen[0].key.dport), 0x8000);
    CHECK_EQ(seen[0].val.bytes, 40 + 64);
}

static void test_ipv6_extension_header(void) {
    struct pkt p;

    eth(&p, 0x86dd);
    ipv6(&p, 0, 0, 8 + 20 + 100); // hop-by-hop options, then TCP
    put8(&p, 6);
    put8(&p, 0);
    put_zero(&p, 6);
    tcp(&p, 40000, 443, 0x02, 100);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 6);
    CHECK_EQ(ntohs(seen[0].key.sport), 40000);
    CHECK_EQ(ntohs(seen[0].key.dport), 443);
    CHECK_EQ(seen[0].val.bytes, 40 + 8 + 20 + 100);
}

static void test_ipv6_fragments(void) {
    struct pkt p;
    int first = 0;

    eth(&p, 0x86dd);
    ipv6(&p, 44, 0, 8 + 8 + 48); // first fragment: carries the UDP header
    put8(&p, 17);
    put8(&p, 0);
    put16(&p, 1); // offset 0, more fragments
    put32(&p, 0x1234);
    udp(&p, 5353, 53, 48);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x86dd);
    ipv6(&p, 44, 0, 8 + 32); // later fragment: no ports
    put8(&p, 17);
    put8(&p, 0);
    put16(&p, 7 << 3);
    put32(&p, 0x1234);
    put_zero(&p, 32);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 2);
    first = seen[0].key.dport ? 0 : 1;
    CHECK_EQ(seen[first].key.proto, 17);
    CHECK_EQ(ntohs(seen[first].key.dport), 53);
    CHECK_EQ(seen[first].val.bytes, 40 + 8 + 8 + 48);
    CHECK_EQ(seen[1 - first].key.proto, 17);
    CHECK_EQ(seen[1 - first].key.dport, 0);
    CHECK_EQ(seen[1 - first].val.bytes, 40 + 8 + 32);
}

/*
 * RFC 8200 asks receivers to accept chains longer than recommended: counted without ports, with
 * the header where parsing stopped as the protocol.
 */
static void test_ipv6_long_extension_chain(void) {
    struct pkt p;

    eth(&p, 0x86dd);
    ipv6(&p, 60, 0, (7 * 8) + 8); // seven destination options headers, then UDP
    for (int i = 0; i < 7; i++) {
        put8(&p, i < 6 ? 60 : 17);
        put_zero(&p, 7);
    }
    udp(&p, 1, 2, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 60);
    CHECK_EQ(seen[0].key.dport, 0);
    CHECK_EQ(seen[0].val.bytes, 40 + (7 * 8) + 8);
}

static void test_vlan_tag_in_packet(void) {
    struct pkt p;

    eth(&p, 0x8100); // e.g. the inner tag of a QinQ frame
    put16(&p, 200);
    put16(&p, 0x0800);
    ipv4(&p, 17, 0, 0, 8 + 50);
    udp(&p, 7777, 7777, 50);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 17);
    CHECK_EQ(ntohs(seen[0].key.dport), 7777);
    CHECK_EQ(seen[0].key.vlan, 200);
    CHECK_EQ(seen[0].key.vlan_inner, 0);
    CHECK_EQ(seen[0].val.bytes, 20 + 8 + 50);
}

/* Both tags of a QinQ frame in the packet (no VLAN offload): parsed from the Ethernet header. */
static void test_qinq_two_tags_in_packet(void) {
    struct pkt p;

    eth(&p, 0x88a8); // service tag
    put16(&p, 100);
    put16(&p, 0x8100); // customer tag
    put16(&p, 200);
    put16(&p, 0x0800);
    ipv4(&p, 17, 0, 0, 8 + 50);
    udp(&p, 7777, 8888, 50);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 17);
    CHECK_EQ(ntohs(seen[0].key.sport), 7777);
    CHECK_EQ(ntohs(seen[0].key.dport), 8888);
    CHECK_EQ(seen[0].key.vlan, 100);       // service tag
    CHECK_EQ(seen[0].key.vlan_inner, 200); // customer tag
    CHECK_EQ(seen[0].val.bytes, 20 + 8 + 50);
}

/* The same addresses and ports in two VLANs (tenants reusing a network) stay two flows. */
static void test_vlans_do_not_merge(void) {
    struct pkt p;
    int first = 0;

    for (uint16_t vid = 10; vid <= 20; vid += 10) {
        eth(&p, 0x8100);
        put16(&p, vid);
        put16(&p, 0x0800);
        ipv4(&p, 17, 0, 0, 8);
        udp(&p, 5000, 6000, 0);
        run(&p, FLOW_DIR_IN, 0, 0);
    }
    drain();
    CHECK_EQ(n_seen, 2);
    first = seen[0].key.vlan == 10 ? 0 : 1;
    CHECK_EQ(seen[first].key.vlan, 10);
    CHECK_EQ(seen[1 - first].key.vlan, 20);
    CHECK_EQ(seen[0].val.packets + seen[1].val.packets, 2);
}

/* ECN marks (ECT(0), not-ECT, CE, ECT(1)) do not split a flow; the first packet's are kept. */
static void test_ecn_same_flow(void) {
    static const uint8_t tos[] = {0x02, 0x00, 0x03, 0x01};
    struct pkt p;

    for (size_t i = 0; i < sizeof(tos); i++) {
        eth(&p, 0x0800);
        ipv4(&p, 6, (uint8_t)(0xb8 | tos[i]), 0, 20);
        tcp(&p, 1000, 80, 0x10, 0);
        run(&p, FLOW_DIR_IN, 0, 0);
    }
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.tos, 0xb8); // DSCP EF, ECN bits cleared
    CHECK_EQ(seen[0].val.ecn, 0x02);
    CHECK_EQ(seen[0].val.packets, 4);
}

static void test_gso_segments(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 20 + 100);
    tcp(&p, 1000, 80, 0x10, 100);
    run(&p, FLOW_DIR_OUT, 4, 0); // a GSO packet that becomes 4 segments on the wire
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].val.packets, 4);
    CHECK_EQ(seen[0].val.bytes, 140 + (3 * 40)); // every segment has its own IP + TCP header
}

/* Untrusted GSO packets (virtio-net, tun) have gso_segs 0: the count comes from gso_size. */
static void test_gso_untrusted(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 20 + 150);
    tcp(&p, 1000, 80, 0x10, 150);
    run_gso(&p, FLOW_DIR_IN, 0, 60, 0); // 150 bytes of payload in segments of 60: 3 packets
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].val.packets, 3);
    CHECK_EQ(seen[0].val.bytes, 190 + (2 * 40));
}

/* Overwrite a 16-bit field of a built packet (network byte order). */
static void set16(struct pkt *p, size_t off, uint16_t v) {
    p->data[off] = (uint8_t)(v >> 8);
    p->data[off + 1] = (uint8_t)v;
}

static constexpr size_t IP_TOT_LEN = 14 + 2; // offset of iphdr.tot_len in an Ethernet frame

/*
 * Lengths that contradict the header or the frame: counted as malformed, never as a flow, and
 * nothing is read from the padding behind the IP length.
 */
static void test_malformed_packets(void) {
    const uint64_t trunc = stat(STAT_TRUNC);
    struct pkt p;

    eth(&p, 0x0800); // 0: tot_len as long as the whole frame, but 14 bytes of it are Ethernet
    ipv4(&p, 17, 0, 0, 8 + 14);
    udp(&p, 1, 2, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 1: tot_len 65535 in a 60 byte frame
    ipv4(&p, 17, 0, 0, 65535 - 20);
    udp(&p, 1, 2, 18);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 2: tot_len shorter than the IP header
    ipv4(&p, 17, 0, 0, 8);
    udp(&p, 1, 2, 0);
    set16(&p, IP_TOT_LEN, 10);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 3: tot_len 0 without GSO (only BIG TCP super-packets have that)
    ipv4(&p, 17, 0, 0, 8);
    udp(&p, 1, 2, 0);
    set16(&p, IP_TOT_LEN, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 4: TCP data offset 4 words
    ipv4(&p, 6, 0, 0, 20);
    tcp(&p, 1000, 80, 0x10, 0);
    p.data[14 + 20 + 12] = 4 << 4;
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 5: tot_len ends inside the TCP header; padding behind it looks like one
    ipv4(&p, 6, 0, 0, 10);
    tcp(&p, 1000, 80, 0x10, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 6: tot_len ends inside the UDP header
    ipv4(&p, 17, 0, 0, 4);
    udp(&p, 1, 2, 0);
    put_zero(&p, 60 - p.len);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x86dd); // 7: IPv6 extension header longer than the payload length
    ipv6(&p, 60, 0, 8);
    put8(&p, 17);
    put8(&p, 1); // 16 bytes, but the payload is 8
    put_zero(&p, 30);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 0);
    CHECK_EQ(stat(STAT_TRUNC) - trunc, 8);
}

static constexpr size_t UDP_LEN = 14 + 20 + 4; // offset of udphdr.len behind Ethernet and IPv4

/*
 * The UDP length: below 8 or beyond the IP payload, the kernel drops the datagram. 0 in IPv6
 * stands for a jumbogram, a first fragment's covers all fragments, and bytes behind it count.
 */
static void test_udp_length(void) {
    const uint64_t trunc = stat(STAT_TRUNC);
    struct pkt p;
    int seen6 = 0;

    for (uint16_t len = 0; len < 8; len++) {
        eth(&p, 0x0800);
        ipv4(&p, 17, 0, 0, 8);
        udp(&p, 1, 2, 0);
        set16(&p, UDP_LEN, len);
        run(&p, FLOW_DIR_IN, 0, 0);
    }
    eth(&p, 0x0800); // beyond the IP payload
    ipv4(&p, 17, 0, 0, 8);
    udp(&p, 1, 2, 0);
    set16(&p, UDP_LEN, 20);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 0);
    CHECK_EQ(stat(STAT_TRUNC) - trunc, 9);

    eth(&p, 0x0800); // first fragment: the length covers the whole datagram
    ipv4(&p, 17, 0, IP_MF, 8 + 32);
    udp(&p, 5000, 5001, 32);
    set16(&p, UDP_LEN, 8 + 1000);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // 4 bytes behind the datagram: the IP length counts
    ipv4(&p, 17, 0, 0, 8 + 4);
    udp(&p, 6000, 6001, 4);
    set16(&p, UDP_LEN, 8);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x86dd); // IPv6 with length 0
    ipv6(&p, 17, 0, 8);
    udp(&p, 7000, 7001, 0);
    set16(&p, 14 + 40 + 4, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 3);
    CHECK_EQ(stat(STAT_TRUNC) - trunc, 9);
    for (int i = 0; i < n_seen; i++) {
        if (ntohs(seen[i].key.sport) == 5000)
            CHECK_EQ(seen[i].val.bytes, 20 + 8 + 32);
        if (ntohs(seen[i].key.sport) == 6000)
            CHECK_EQ(seen[i].val.bytes, 20 + 8 + 4);
        seen6 += ntohs(seen[i].key.sport) == 7000;
    }
    CHECK_EQ(seen6, 1);
}

/* An IPv6 Authentication Header needs 12 bytes at least (RFC 4302): 8 is malformed. */
static void test_ipv6_auth_header(void) {
    const uint64_t trunc = stat(STAT_TRUNC);
    struct pkt p;

    eth(&p, 0x86dd);
    ipv6(&p, 51, 0, 8 + 8); // AH with payload length 0: 8 bytes, then what looks like UDP
    put8(&p, 17);
    put_zero(&p, 7);
    udp(&p, 1, 2, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x86dd);
    ipv6(&p, 51, 0, 12 + 8); // AH with payload length 1: 12 bytes, then UDP
    put8(&p, 17);
    put8(&p, 1);
    put_zero(&p, 10);
    udp(&p, 3000, 3001, 0);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(stat(STAT_TRUNC) - trunc, 1);
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 17);
    CHECK_EQ(ntohs(seen[0].key.sport), 3000);
    CHECK_EQ(seen[0].val.bytes, 40 + 12 + 8);
}

/* The longest valid TCP header (data offset 15 words), exactly filling tot_len: a flow. */
static void test_tcp_options_exact(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 60);
    tcp(&p, 1000, 80, 0x10, 40); // 20 byte header + 40 bytes that become options
    p.data[14 + 20 + 12] = 15 << 4;
    run_gso(&p, FLOW_DIR_IN, 2, 0, 0);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].val.packets, 2);
    CHECK_EQ(seen[0].val.bytes, 80 + 80); // both segments carry the 80 bytes of headers
}

static void test_egress_interfaces(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 17, 0, 0, 8);
    udp(&p, 1, 2, 0);
    run(&p, FLOW_DIR_OUT, 0, 7); // forwarded: arrived on interface 7
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.dir, FLOW_DIR_OUT);
    CHECK_EQ(seen[0].key.out_if, LO_IFINDEX);
    CHECK_EQ(seen[0].key.in_if, 7);
    CHECK_EQ(seen[0].val.bytes, 28);
}

/* Packets without payload in a frame padded to the Ethernet minimum: only layer 3 bytes count. */
static void test_zero_payload_padding(void) {
    struct pkt p;

    eth(&p, 0x0800);
    ipv4(&p, 6, 0, 0, 20);
    tcp(&p, 1000, 80, 0x10, 0); // pure ACK
    put_zero(&p, 60 - p.len);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800);
    ipv4(&p, 17, 0, 0, 8);
    udp(&p, 1, 2, 0); // empty datagram
    put_zero(&p, 60 - p.len);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 2);
    for (int i = 0; i < n_seen; i++)
        CHECK_EQ(seen[i].val.bytes, seen[i].key.proto == 6 ? 40 : 28);
}

static void test_ignored_packets(void) {
    const uint64_t nonip = stat(STAT_NONIP);
    const uint64_t trunc = stat(STAT_TRUNC);
    struct pkt p;

    eth(&p, 0x0806); // ARP
    put_zero(&p, 28);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x0800); // IPv4 header with an impossible header length (IHL 1)
    put8(&p, 0x41);
    put_zero(&p, 39);
    run(&p, FLOW_DIR_IN, 0, 0);
    eth(&p, 0x86dd); // IPv6 header announcing a hop-by-hop header that is cut off
    ipv6(&p, 0, 0, 8);
    run(&p, FLOW_DIR_IN, 0, 0);
    drain();
    CHECK_EQ(n_seen, 0);
    CHECK_EQ(stat(STAT_NONIP) - nonip, 1);
    CHECK_EQ(stat(STAT_TRUNC) - trunc, 2);
}

static void test_map_swap(void) {
    struct pkt p;
    int idle = 0;

    eth(&p, 0x0800);
    ipv4(&p, 17, 0, 0, 8);
    udp(&p, 1, 2, 0);
    idle = meter_swap(&m); // the program now writes into the other map
    run(&p, FLOW_DIR_IN, 0, 0);
    n_seen = 0;
    CHECK_EQ(meter_drain(&m, idle, collect, nullptr), 0);
    CHECK_EQ(meter_drain(&m, 1 - idle, collect, nullptr), 1);
    (void)meter_swap(&m);
}

/* A failed batch call passes on no flows: its buffers still hold the flows of an earlier call. */
static void test_drain_error(void) {
    struct meter bad = m;

    bad.flows_fd[0] = -1;
    n_seen = 0;
    CHECK(meter_drain(&bad, 0, collect, nullptr) < 0);
    CHECK_EQ(n_seen, 0);
}

/* Bring the loopback device of the current network namespace up. */
static int loopback_up(void) {
    struct ifreq ifr = {.ifr_name = "lo"};
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int rc = -1;

    if (fd >= 0 && !ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        ifr.ifr_flags |= IFF_UP;
        rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    if (fd >= 0)
        (void)close(fd);
    return rc;
}

/* Send one UDP datagram over the loopback device and wait until it has arrived. */
static void loopback_datagram(uint16_t port) {
    const struct timeval timeout = {.tv_sec = 1};
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    const int rx = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    const int tx = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    char buf[8];

    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (rx < 0 || tx < 0) {
        CHECK(0);
        if (rx >= 0)
            (void)close(rx);
        if (tx >= 0)
            (void)close(tx);
        return;
    }
    CHECK_EQ(setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);
    CHECK_EQ(bind(rx, (const struct sockaddr *)&to, sizeof(to)), 0); // no ICMP port unreachable
    CHECK_EQ(sendto(tx, "x", 1, 0, (const struct sockaddr *)&to, sizeof(to)), 1);
    CHECK_EQ(recv(rx, buf, sizeof(buf), 0), 1); // it passed the tcx ingress hook
    (void)close(tx);
    (void)close(rx);
}

/*
 * A tcx program already on the hook that ends the chain (TCX_PASS, as Cilium's do) must not hide
 * the packets from tcxflow, which attaches in front of it. Real interfaces, so in a network
 * namespace of its own: only the test's datagram crosses its loopback device.
 */
static void test_attach_before_other_programs(void) {
    const struct bpf_insn pass[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = TCX_PASS},
        {.code = BPF_JMP | BPF_EXIT},
    };
    const int home = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    struct bpf_link *link = nullptr;
    int prog = -1;

    CHECK(home >= 0);
    if (home < 0 || unshare(CLONE_NEWNET)) {
        CHECK(0);
        return;
    }
    CHECK_EQ(loopback_up(), 0);
    prog = bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS, "pass", "GPL", pass, 2, nullptr);
    CHECK(prog >= 0);
    CHECK_EQ(bpf_prog_attach_opts(prog, LO_IFINDEX, BPF_TCX_INGRESS, nullptr), 0);
    link = meter_attach(&m, LO_IFINDEX, FLOW_DIR_IN);
    CHECK(link != nullptr);
    CHECK_EQ(meter_link_ifindex(link), LO_IFINDEX);
    drain();
    loopback_datagram(4242);
    drain();
    CHECK_EQ(n_seen, 1);
    CHECK_EQ(seen[0].key.proto, 17);
    CHECK_EQ(ntohs(seen[0].key.dport), 4242);
    (void)bpf_link__destroy(link);
    (void)bpf_prog_detach_opts(prog, LO_IFINDEX, BPF_TCX_INGRESS, nullptr);
    (void)close(prog);
    CHECK_EQ(setns(home, CLONE_NEWNET), 0);
    (void)close(home);
}

static void test_map_full(void) {
    const uint64_t lost = stat(STAT_FULL_PKTS);
    struct pkt p;

    for (uint16_t port = 1; port <= MAX_FLOWS + 76; port++) {
        eth(&p, 0x0800);
        ipv4(&p, 17, 0, 0, 8);
        udp(&p, port, 9, 0);
        run(&p, FLOW_DIR_IN, 0, 0);
    }
    drain();
    CHECK_EQ(n_seen, MAX_FLOWS);
    CHECK_EQ(stat(STAT_FULL_PKTS) - lost, 76);
}

int main(void) {
    int err = 0;

    if (geteuid() != 0) {
        (void)fprintf(stderr, "test_bpf: needs root (sudo make test-bpf)\n");
        return 1;
    }
    meter_set_verbose(false);
    err = meter_open(&m, MAX_FLOWS);
    if (err) {
        (void)fprintf(stderr, "test_bpf: cannot load the BPF program: %s\n", strerror(-err));
        return 1;
    }
    RUN_TEST(test_ipv4_tcp);
    RUN_TEST(test_tcp_flags_accumulate);
    RUN_TEST(test_ipv4_udp_and_icmp);
    RUN_TEST(test_ipv4_fragment);
    RUN_TEST(test_ipv4_first_fragments);
    RUN_TEST(test_dccp_ports);
    RUN_TEST(test_ipv6_icmpv6);
    RUN_TEST(test_ipv6_extension_header);
    RUN_TEST(test_ipv6_fragments);
    RUN_TEST(test_ipv6_long_extension_chain);
    RUN_TEST(test_vlan_tag_in_packet);
    RUN_TEST(test_qinq_two_tags_in_packet);
    RUN_TEST(test_vlans_do_not_merge);
    RUN_TEST(test_ecn_same_flow);
    RUN_TEST(test_gso_segments);
    RUN_TEST(test_gso_untrusted);
    RUN_TEST(test_malformed_packets);
    RUN_TEST(test_udp_length);
    RUN_TEST(test_ipv6_auth_header);
    RUN_TEST(test_tcp_options_exact);
    RUN_TEST(test_egress_interfaces);
    RUN_TEST(test_zero_payload_padding);
    RUN_TEST(test_ignored_packets);
    RUN_TEST(test_map_swap);
    RUN_TEST(test_drain_error);
    RUN_TEST(test_map_full);
    RUN_TEST(test_attach_before_other_programs);
    meter_close(&m);
    return test_summary();
}
