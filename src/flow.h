// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file flow.h
 * @brief Flow key, flow counters and statistics shared by the BPF program and userspace
 *
 * Included by both sides, so it uses only kernel UAPI types.
 */

#ifndef TCXFLOW_FLOW_H
#define TCXFLOW_FLOW_H

#include <linux/types.h>

#define FLOW_PROTO_ICMP 1    ///< IPPROTO_ICMP
#define FLOW_PROTO_TCP 6     ///< IPPROTO_TCP
#define FLOW_PROTO_ICMPV6 58 ///< IPPROTO_ICMPV6

/** Direction of a flow record relative to the metered interface. */
enum flow_dir {
    FLOW_DIR_IN = 0,  /**< tcx ingress: packet received on the interface */
    FLOW_DIR_OUT = 1, /**< tcx egress: packet sent out of the interface */
};

/**
 * Flow key: 56 bytes, no implicit padding (it is hashed and compared as raw bytes). IPv4
 * addresses use the first 4 bytes of src/dst.
 */
struct flow_key {
    __u32 in_if;      /**< ingressInterface; 0 for packets sent by this host */
    __u32 out_if;     /**< egressInterface; 0 on ingress (routing not done yet) */
    __u8 src[16];     /**< source address */
    __u8 dst[16];     /**< destination address */
    __be16 sport;     /**< source port (network order); 0 unless TCP, UDP, UDP-Lite, SCTP or DCCP */
    __be16 dport;     /**< destination port; ICMP and ICMPv6: type << 8 | code (network order) */
    __u8 proto;       /**< IP protocol */
    __u8 tos;         /**< IPv4 TOS or IPv6 traffic class without the ECN bits: the DSCP */
    __u8 dir;         /**< enum flow_dir */
    __u8 ipver;       /**< 4 or 6 */
    __u16 vlan;       /**< outer VLAN ID seen in the packet, 0 = untagged */
    __u16 vlan_inner; /**< inner VLAN ID (QinQ), 0 = none */
    __u32 pad;        /**< always 0 */
};

/** Counters of one flow within one measurement interval. */
struct flow_val {
    __u64 first_ns;  /**< first packet, CLOCK_MONOTONIC (coarse) */
    __u64 last_ns;   /**< last packet, CLOCK_MONOTONIC (coarse) */
    __u64 packets;   /**< on-wire packets: GRO/TSO segments are counted individually */
    __u64 bytes;     /**< layer 3 bytes */
    __u32 tcp_flags; /**< OR of all TCP flags seen */
    __u8 ecn;        /**< ECN bits of the first packet (the key holds only the DSCP) */
    __u8 pad[3];     /**< keeps the structure free of implicit padding */
};

/**
 * Indexes into struct flow_stats. Only the exceptions are counted here: the totals follow from
 * the drained flows, and counting them per packet would cost every packet a map access.
 */
enum flow_stat {
    STAT_NONIP,      /**< packets ignored: neither IPv4 nor IPv6 */
    STAT_TRUNC,      /**< packets ignored: malformed or cut short (lengths that do not fit) */
    STAT_FULL_PKTS,  /**< packets NOT accounted: flow table full */
    STAT_FULL_BYTES, /**< bytes NOT accounted: flow table full */
    STAT_MAX,
};

/** Per-CPU counters kept by the BPF program. */
struct flow_stats {
    __u64 c[STAT_MAX]; /**< indexed by enum flow_stat */
};

#endif // TCXFLOW_FLOW_H
