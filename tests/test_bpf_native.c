// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file test_bpf_native.c
 * @brief The BPF program compiled as ordinary C, for what BPF_PROG_TEST_RUN cannot produce
 *
 * Packets beyond 64 KiB (BIG TCP, jumbograms) and other CPUs changing a flow between a read and
 * a compare-and-swap. The helpers the program calls are implemented here, with one flow map
 * of a few entries. It checks the program's logic; tests/test_bpf.c checks it in the kernel.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "flow.h"
#include "test.h"

// Another CPU may store into a timestamp between the program's read and its compare-and-swap.
static __u64 cas(__u64 *ptr, __u64 old, __u64 val);
#define __sync_val_compare_and_swap cas // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp): the builtin
#include "../src/tcxflow.bpf.c"         // NOLINT(bugprone-suspicious-include): the program under test
#undef __sync_val_compare_and_swap

static constexpr int MAP_SLOTS = 4;

static uint8_t packet[200000];
static struct sk_buff kctx;
static struct flow_stats counters;
static struct {
    struct flow_key key;
    struct flow_val val;
} slot[MAP_SLOTS];
static int n_slots;
static __u64 clock_now;
static __u64 *race_ptr; // the timestamp another CPU changes ...
static __u64 race_val;  // ... to this value, once
static int race_insert; // another CPU inserts the flow just before the program
static __u64 race_first;

static __u64 cas(__u64 *ptr, __u64 old, __u64 val) {
    if (ptr == race_ptr) {
        *ptr = race_val;
        race_ptr = nullptr;
    }
    return __sync_val_compare_and_swap(ptr, old, val);
}

void *bpf_cast_to_kern_ctx([[maybe_unused]] void *obj) { return &kctx; }

long bpf_skb_load_bytes(const void *skb, __u32 offset, void *to, __u32 len) {
    const struct __sk_buff *s = skb;

    if (offset > s->len || len > s->len - offset)
        return -1;
    memcpy(to, packet + offset, len);
    return 0;
}

void *bpf_map_lookup_elem(void *map, const void *key) {
    if (map == &active)
        return &flows0;
    if (map == &stats)
        return &counters;
    for (int i = 0; i < n_slots; i++)
        if (!memcmp(&slot[i].key, key, sizeof(slot[i].key)))
            return &slot[i].val;
    return nullptr;
}

long bpf_map_update_elem([[maybe_unused]] void *map, const void *key, const void *value, [[maybe_unused]] __u64 flags) {
    if (n_slots == MAP_SLOTS)
        return -1;
    memcpy(&slot[n_slots].key, key, sizeof(slot[n_slots].key));
    memcpy(&slot[n_slots].val, value, sizeof(slot[n_slots].val));
    if (race_insert) { // the other CPU won: its entry, with its clock reading, is in the map
        race_insert = 0;
        slot[n_slots].val.first_ns = slot[n_slots].val.last_ns = race_first;
        slot[n_slots].val.packets = slot[n_slots].val.bytes = 0;
        n_slots++;
        return -1;
    }
    n_slots++;
    return 0;
}

__u64 bpf_ktime_get_coarse_ns(void) { return clock_now; }

/* A fresh packet of len bytes: Ethernet header, protocol and GSO metadata. */
static struct __sk_buff reset(uint16_t proto, uint32_t len, uint32_t gso_segs, uint32_t gso_size) {
    memset(packet, 0, sizeof(packet));
    memset(&counters, 0, sizeof(counters));
    memset(slot, 0, sizeof(slot));
    n_slots = 0;
    clock_now = 1000;
    race_ptr = nullptr;
    race_insert = 0;
    kctx = (struct sk_buff){.head = packet, .data = packet, .network_header = 14};
    packet[12] = (uint8_t)(proto >> 8);
    packet[13] = (uint8_t)proto;
    return (struct __sk_buff){
        .len = len, .protocol = htons(proto), .gso_segs = gso_segs, .gso_size = gso_size, .ifindex = 1};
}

static void put16(uint32_t off, uint32_t v) {
    packet[off] = (uint8_t)(v >> 8);
    packet[off + 1] = (uint8_t)v;
}

static void put32(uint32_t off, uint32_t v) {
    put16(off, v >> 16);
    put16(off + 2, v & 0xffff);
}

/* IPv6 header at 14 with payload length 0, and a Hop-by-Hop header with a Jumbo Payload option. */
static void ipv6_jumbo(uint8_t next, uint32_t jumbo_len) {
    packet[14] = 0x60;
    packet[20] = 0; // next header: hop-by-hop
    packet[54] = next;
    packet[55] = 0; // 8 bytes
    packet[56] = 0xc2;
    packet[57] = 4;
    put32(58, jumbo_len);
}

/* A TCP header without options at off, ACK set. */
static void tcp(uint32_t off) {
    put16(off, 40000);
    put16(off + 2, 443);
    packet[off + 12] = 5 << 4;
    packet[off + 13] = 0x10;
}

/*
 * Linux puts a Jumbo Payload header on IPv6 BIG TCP super-packets and removes it before
 * segmentation: the segments on the wire are 8 bytes shorter each.
 */
static void test_ipv6_big_tcp_jumbo_header(void) {
    const uint32_t payload = 100000;
    const uint32_t len = 14 + 40 + 8 + 20 + payload;

    for (int derived = 0; derived < 2; derived++) {
        struct __sk_buff skb = reset(ETH_P_IPV6, len, derived ? 0 : 100, 1000);

        ipv6_jumbo(IPPROTO_TCP, 8 + 20 + payload);
        tcp(62);
        CHECK_EQ(tcxflow_egress(&skb), TCX_NEXT);
        CHECK_EQ(n_slots, 1);
        CHECK_EQ(counters.c[STAT_TRUNC], 0);
        CHECK_EQ(slot[0].val.packets, 100);
        CHECK_EQ(slot[0].val.bytes, payload + (100 * (40 + 20))); // no segment has the 8 bytes
        CHECK_EQ(ntohs(slot[0].key.dport), 443);
    }
}

/* BIG TCP without that header (newer kernels), and IPv4: the length comes from the packet. */
static void test_big_tcp_without_length(void) {
    const uint32_t payload = 100000;
    struct __sk_buff skb = reset(ETH_P_IPV6, 14 + 40 + 20 + payload, 0, 1000);

    packet[14] = 0x60;
    packet[20] = IPPROTO_TCP;
    tcp(54);
    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
    CHECK_EQ(n_slots, 1);
    CHECK_EQ(slot[0].val.packets, 100);
    CHECK_EQ(slot[0].val.bytes, payload + (100 * 60));

    skb = reset(ETH_P_IP, 14 + 20 + 20 + payload, 0, 1000);
    packet[14] = 0x45;
    packet[23] = IPPROTO_TCP; // total length 0
    tcp(34);
    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
    CHECK_EQ(n_slots, 1);
    CHECK_EQ(slot[0].val.packets, 100);
    CHECK_EQ(slot[0].val.bytes, payload + (100 * 40));
}

/* A jumbogram without GSO (RFC 2675) is one packet on the wire, Hop-by-Hop header included. */
static void test_ipv6_jumbogram(void) {
    const uint32_t payload = 70000;
    struct __sk_buff skb = reset(ETH_P_IPV6, 14 + 40 + 8 + 8 + payload, 0, 0);

    ipv6_jumbo(IPPROTO_UDP, 8 + 8 + payload);
    put16(62, 5353);
    put16(64, 53); // UDP length 0: a jumbogram
    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
    CHECK_EQ(n_slots, 1);
    CHECK_EQ(counters.c[STAT_TRUNC], 0);
    CHECK_EQ(slot[0].val.packets, 1);
    CHECK_EQ(slot[0].val.bytes, 40 + 8 + 8 + payload);
    CHECK_EQ(ntohs(slot[0].key.dport), 53);
}

/* Jumbo lengths up to 65535, or beyond the packet: malformed. */
static void test_ipv6_jumbo_invalid(void) {
    static const uint32_t lens[] = {65535, 8 + 8 + 70000 + 1};

    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        struct __sk_buff skb = reset(ETH_P_IPV6, 14 + 40 + 8 + 8 + 70000, 0, 0);

        ipv6_jumbo(IPPROTO_UDP, lens[i]);
        CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
        CHECK_EQ(n_slots, 0);
        CHECK_EQ(counters.c[STAT_TRUNC], 1);
    }
}

/* An IPv4 UDP packet at 14, payload 8. */
static struct __sk_buff udp4(void) {
    const struct __sk_buff skb = reset(ETH_P_IP, 14 + 20 + 8, 0, 0);

    packet[14] = 0x45;
    put16(16, 28);
    packet[23] = IPPROTO_UDP;
    put16(38, 8);
    return skb;
}

/*
 * Another CPU stores a timestamp between the program's read and its compare-and-swap: the
 * program tries again, and the latest time (last_ns) or the earliest (first_ns) wins.
 */
static void test_timestamp_races(void) {
    struct __sk_buff skb = udp4();

    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT); // the flow, at 1000
    clock_now = 2000;
    race_ptr = &slot[0].val.last_ns;
    race_val = 1500; // stored by the other CPU after this program read 1000
    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
    CHECK_EQ(slot[0].val.last_ns, 2000);
    clock_now = 2200;
    race_ptr = &slot[0].val.last_ns;
    race_val = 2500; // a later time than this packet's: it stays
    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
    CHECK_EQ(slot[0].val.last_ns, 2500);
    CHECK_EQ(slot[0].val.packets, 3);

    skb = udp4(); // both CPUs insert the flow; the other one wins with a later clock reading
    clock_now = 2500;
    race_insert = 1;
    race_first = 3000;
    race_ptr = &slot[0].val.first_ns;
    race_val = 2800; // and a third CPU lowers it, but not to this packet's time
    CHECK_EQ(tcxflow_ingress(&skb), TCX_NEXT);
    CHECK_EQ(n_slots, 1);
    CHECK_EQ(slot[0].val.first_ns, 2500);
    CHECK_EQ(slot[0].val.packets, 1);
}

int main(void) {
    RUN_TEST(test_ipv6_big_tcp_jumbo_header);
    RUN_TEST(test_big_tcp_without_length);
    RUN_TEST(test_ipv6_jumbogram);
    RUN_TEST(test_ipv6_jumbo_invalid);
    RUN_TEST(test_timestamp_races);
    return test_summary();
}
