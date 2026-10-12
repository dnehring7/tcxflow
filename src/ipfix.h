// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file ipfix.h
 * @brief IPFIX (RFC 7011) message encoder
 *
 * Collects flow records into messages of at most max_len bytes and hands
 * finished messages to a send callback. Two data templates are used, one for IPv4
 * and one for IPv6. Templates are sent with the first message and then again every
 * IPFIX_TPL_REFRESH_NS and every IPFIX_TPL_REFRESH_MSGS messages, so a restarted
 * collector learns them quickly; at once after ipfix_resend_templates().
 */

#ifndef TCXFLOW_IPFIX_H
#define TCXFLOW_IPFIX_H

#include <stddef.h>
#include <stdint.h>

#include "flow.h"

#define IPFIX_VERSION 10          ///< version number in the message header
#define IPFIX_MSG_MAX 1400        ///< largest message: fits a 1500 byte MTU with IPv6, UDP and some tunnel headers
#define IPFIX_MSG_MIN 284         ///< smallest message limit: the header, both templates and an IPv6 record
#define IPFIX_HDR_LEN 16          ///< message header length
#define IPFIX_SET_TEMPLATE 2      ///< set id of a template set
#define IPFIX_TPL_V4 256          ///< template id of IPv4 records
#define IPFIX_TPL_V6 257          ///< template id of IPv6 records
#define IPFIX_REC_V4 68           ///< IPv4 data record length
#define IPFIX_REC_V6 92           ///< IPv6 data record length
#define IPFIX_TPL_REFRESH_MSGS 20 ///< repeat the templates after this many messages
#define IPFIX_TPL_REFRESH_NS (60ULL * 1000000000ULL) ///< repeat the templates after this long (60 s)

/** IPFIX flowEndReason (RFC 7012). */
enum ipfix_end_reason {
    IPFIX_END_IDLE = 1,     /**< idle timeout */
    IPFIX_END_ACTIVE = 2,   /**< active timeout */
    IPFIX_END_DETECTED = 3, /**< end of flow detected (TCP FIN/RST) */
    IPFIX_END_FORCED = 4,   /**< forced end (shutdown) */
    IPFIX_END_LACK = 5,     /**< lack of resources: the flow cache is full */
};

/** One flow record to export. */
struct ipfix_record {
    const struct flow_key *key; /**< addresses, ports, protocol, interfaces, direction */
    uint64_t start_ms;          /**< flowStartMilliseconds (Unix epoch) */
    uint64_t end_ms;            /**< flowEndMilliseconds (Unix epoch) */
    uint64_t packets;           /**< packetDeltaCount */
    uint64_t bytes;             /**< octetDeltaCount */
    uint8_t tos;                /**< ipClassOfService: the flow's DSCP, the ECN bits of its first packet */
    uint16_t tcp_flags;         /**< tcpControlBits */
    uint16_t vlan;              /**< outer VLAN ID on the metered interface, 0 = none */
    uint16_t vlan_inner;        /**< inner VLAN ID (QinQ), 0 = none */
    uint8_t end_reason;         /**< enum ipfix_end_reason */
};

/** Called with every finished message. */
typedef void (*ipfix_send_fn)(void *ctx, const uint8_t *msg, size_t len);

/** Encoder state. */
struct ipfix_exporter {
    uint8_t msg[IPFIX_MSG_MAX]; /**< message being built */
    size_t len;                 /**< bytes used in msg, 0 = no message started */
    size_t max_len;             /**< message size limit, see ipfix_set_max_len() */
    size_t set_off;             /**< offset of the open data set */
    uint16_t set_id;            /**< template id of the open data set, 0 = none */
    uint32_t records;           /**< data records in the current message */
    uint32_t seq;               /**< sequence number: data records sent before this message */
    uint32_t domain;            /**< observation domain id */
    unsigned msgs_since_tpl;    /**< messages sent since the last template set */
    uint64_t tpl_sent_ns;       /**< CLOCK_MONOTONIC time of the last template set */
    ipfix_send_fn send;         /**< receives finished messages */
    void *ctx;                  /**< passed to send */
    uint64_t n_messages;        /**< messages sent in total */
    uint64_t n_records;         /**< data records sent in total */
};

/**
 * Initialise an exporter; messages are limited to IPFIX_MSG_MAX bytes until
 * ipfix_set_max_len() is called.
 *
 * @param x       exporter
 * @param domain  observation domain id written into every message header
 * @param send    receives every finished message
 * @param ctx     passed to @p send
 */
void ipfix_init(struct ipfix_exporter *x, uint32_t domain, ipfix_send_fn send, void *ctx);

/**
 * Limit messages to @p max_len bytes, clamped to IPFIX_MSG_MIN..IPFIX_MSG_MAX; 0 means
 * IPFIX_MSG_MAX. Takes effect with the next message.
 *
 * @param x        exporter
 * @param max_len  message size limit in bytes
 */
void ipfix_set_max_len(struct ipfix_exporter *x, size_t max_len);

/**
 * Send the templates with the next message, instead of with the next refresh: for a collector that
 * restarted and no longer knows them.
 *
 * @param x  exporter
 */
void ipfix_resend_templates(struct ipfix_exporter *x);

/**
 * Add one record, sending the current message first if the record does not fit.
 *
 * @param x        exporter
 * @param rec      flow record
 * @param now_ns   CLOCK_MONOTONIC time, decides when templates are repeated
 * @param now_sec  Unix time for the message header
 */
void ipfix_add(struct ipfix_exporter *x, const struct ipfix_record *rec, uint64_t now_ns, uint32_t now_sec);

/**
 * Send the current message, if any.
 *
 * @param x        exporter
 * @param now_sec  Unix time for the message header
 */
void ipfix_flush(struct ipfix_exporter *x, uint32_t now_sec);

#endif // TCXFLOW_IPFIX_H
