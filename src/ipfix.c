// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file ipfix.c
 * @brief IPFIX (RFC 7011) message encoder
 */

#include "ipfix.h"

#include <linux/types.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "flow.h"
#include "util.h"

/** Information element: IANA id and encoded length. */
struct ipfix_ie {
    uint16_t id;  /**< IANA information element id */
    uint16_t len; /**< encoded length in bytes */
};

/**
 * Data template: addresses first, then the fields common to IPv4 and IPv6. Only fixed-length
 * fields: every record of a template has the same size, so encoding needs no length fields and
 * the space left in a message is simple arithmetic. Ports and icmpTypeCode are both present
 * because collectors look for ICMP type and code in icmpTypeCode, not in a port field.
 */
#define TEMPLATE(src_id, dst_id, alen, icmp_id)                                                                        \
    {                                                                                                                  \
        {src_id, alen}, /* sourceIPv4Address / sourceIPv6Address */                                                    \
        {dst_id, alen}, /* destinationIPv4Address / destinationIPv6Address */                                          \
        {7, 2},         /* sourceTransportPort */                                                                      \
        {11, 2},        /* destinationTransportPort */                                                                 \
        {icmp_id, 2},   /* icmpTypeCodeIPv4 / icmpTypeCodeIPv6 */                                                      \
        {4, 1},         /* protocolIdentifier */                                                                       \
        {5, 1},         /* ipClassOfService */                                                                         \
        {6, 2},         /* tcpControlBits */                                                                           \
        {10, 4},        /* ingressInterface */                                                                         \
        {14, 4},        /* egressInterface */                                                                          \
        {58, 2},        /* vlanId */                                                                                   \
        {59, 2},        /* postVlanId */                                                                               \
        {245, 2},       /* dot1qCustomerVlanId */                                                                      \
        {255, 2},       /* postDot1qCustomerVlanId */                                                                  \
        {61, 1},        /* flowDirection */                                                                            \
        {2, 8},         /* packetDeltaCount */                                                                         \
        {1, 8},         /* octetDeltaCount */                                                                          \
        {152, 8},       /* flowStartMilliseconds */                                                                    \
        {153, 8},       /* flowEndMilliseconds */                                                                      \
        {136, 1},       /* flowEndReason */                                                                            \
    }

static const struct ipfix_ie tpl_v4[] = TEMPLATE(8, 12, 4, 32);
static const struct ipfix_ie tpl_v6[] = TEMPLATE(27, 28, 16, 139);

static constexpr size_t N_IE = sizeof(tpl_v4) / sizeof(tpl_v4[0]); ///< information elements per template
static constexpr size_t TPL_LEN = 4 + (N_IE * 4);                  ///< one template record
static constexpr size_t TPL_SET_LEN = 4 + (2 * TPL_LEN);           ///< the template set with both templates

// The smallest message limit holds one IPv6 record, and a template on its own.
static_assert(IPFIX_HDR_LEN + 4 + IPFIX_REC_V6 == IPFIX_MSG_MIN, "IPFIX_MSG_MIN");
static_assert(IPFIX_HDR_LEN + 4 + TPL_LEN <= IPFIX_MSG_MIN, "template message");

/*
 * Byte-wise big-endian stores: the message buffer has no alignment, and the network byte order
 * is explicit at every call instead of hidden in htonl() conversions.
 */
static uint8_t *put8(uint8_t *p, uint8_t v) {
    *p = v;
    return p + 1;
}

static uint8_t *put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
    return p + 2;
}

static uint8_t *put32(uint8_t *p, uint32_t v) { return put16(put16(p, (uint16_t)(v >> 16)), (uint16_t)v); }

static uint8_t *put64(uint8_t *p, uint64_t v) { return put32(put32(p, (uint32_t)(v >> 32)), (uint32_t)v); }

static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint8_t *put_bytes(uint8_t *p, const void *src, size_t len) {
    memcpy(p, src, len);
    return p + len;
}

static uint8_t *put_template(uint8_t *p, uint16_t id, const struct ipfix_ie *tpl) {
    p = put16(put16(p, id), (uint16_t)N_IE);
    for (size_t i = 0; i < N_IE; i++)
        p = put16(put16(p, tpl[i].id), tpl[i].len);
    return p;
}

static uint8_t *put_header(uint8_t *p, size_t len, uint32_t now_sec, uint32_t seq, uint32_t domain) {
    return put32(put32(put32(put16(put16(p, IPFIX_VERSION), (uint16_t)len), now_sec), seq), domain);
}

static bool templates_due(const struct ipfix_exporter *x, uint64_t now_ns) {
    return x->msgs_since_tpl >= IPFIX_TPL_REFRESH_MSGS || now_ns - x->tpl_sent_ns >= x->tpl_refresh_ns;
}

size_t ipfix_template_message(const struct ipfix_exporter *x, unsigned index, uint32_t now_sec, uint8_t *buf,
                              size_t len) {
    const bool both = IPFIX_HDR_LEN + TPL_SET_LEN <= x->max_len;
    const size_t msg_len = IPFIX_HDR_LEN + 4 + ((both ? 2 : 1) * TPL_LEN);
    uint8_t *p = buf;

    if (index >= (both ? 1U : 2U) || msg_len > len)
        return 0;
    // The sequence number counts data records only: a template message has that of the next one.
    p = put_header(p, msg_len, now_sec, x->seq, x->domain);
    p = put16(put16(p, IPFIX_SET_TEMPLATE), (uint16_t)(msg_len - IPFIX_HDR_LEN));
    if (both || index == 0)
        p = put_template(p, IPFIX_TPL_V4, tpl_v4);
    if (both || index == 1)
        (void)put_template(p, IPFIX_TPL_V6, tpl_v6);
    return msg_len;
}

static void begin_message(struct ipfix_exporter *x) {
    x->len = IPFIX_HDR_LEN;
    x->set_id = 0;
    x->records = 0;
}

/*
 * Begin a message; include the template set when a refresh is due. The templates travel in
 * the same message as the data, so a collector that just (re)started decodes it at once. Under
 * a small path MTU they leave no room for a record: then they go in messages of their own first.
 */
static void start_message(struct ipfix_exporter *x, uint64_t now_ns, uint32_t now_sec) {
    x->started_ns = now_ns;
    begin_message(x);
    if (!templates_due(x, now_ns))
        return;
    if (IPFIX_HDR_LEN + TPL_SET_LEN + 4 + IPFIX_REC_V6 <= x->max_len) {
        uint8_t *p = put16(put16(x->msg + x->len, IPFIX_SET_TEMPLATE), (uint16_t)TPL_SET_LEN);

        (void)put_template(put_template(p, IPFIX_TPL_V4, tpl_v4), IPFIX_TPL_V6, tpl_v6);
        x->len += TPL_SET_LEN;
    } else {
        uint8_t buf[IPFIX_HDR_LEN + TPL_SET_LEN];
        size_t n = 0;

        for (unsigned i = 0; (n = ipfix_template_message(x, i, now_sec, buf, sizeof(buf))) != 0; i++) {
            x->send(x->ctx, buf, n);
            x->n_messages++;
        }
    }
    x->msgs_since_tpl = 0;
    x->tpl_sent_ns = now_ns;
}

static void close_set(struct ipfix_exporter *x) {
    if (x->set_id)
        (void)put16(x->msg + x->set_off + 2, (uint16_t)(x->len - x->set_off));
    x->set_id = 0;
}

static void open_set(struct ipfix_exporter *x, uint16_t id) {
    close_set(x);
    x->set_off = x->len;
    (void)put16(x->msg + x->len, id);
    x->len += 4;
    x->set_id = id;
}

static bool fits(const struct ipfix_exporter *x, size_t rlen, uint16_t id) {
    return x->len + rlen + (x->set_id != id ? 4 : 0) <= x->max_len;
}

void ipfix_init(struct ipfix_exporter *x, uint32_t domain, uint64_t refresh_ns, uint64_t wait_ns, ipfix_send_fn send,
                void *ctx) {
    memset(x, 0, sizeof(*x));
    x->domain = domain;
    x->tpl_refresh_ns = refresh_ns;
    x->wait_ns = wait_ns;
    x->max_len = IPFIX_MSG_MAX;
    x->send = send;
    x->ctx = ctx;
    x->msgs_since_tpl = IPFIX_TPL_REFRESH_MSGS; // first message carries the templates
}

void ipfix_set_max_len(struct ipfix_exporter *x, size_t max_len) {
    if (!max_len) // RFC 7011: 512-byte packets when the path MTU is unknown
        max_len = IPFIX_MSG_UNKNOWN;
    if (max_len > IPFIX_MSG_MAX)
        max_len = IPFIX_MSG_MAX;
    x->max_len = max_len < IPFIX_MSG_MIN ? IPFIX_MSG_MIN : max_len;
}

void ipfix_tick(struct ipfix_exporter *x, uint64_t now_ns, uint32_t now_sec) {
    // By age, so skipped ticks count; half a tick early, so jitter on the tick grid costs no tick.
    if (x->len && now_ns - x->started_ns + (NSEC_PER_SEC / 2) > x->wait_ns)
        ipfix_flush(x, now_sec);
    if (templates_due(x, now_ns)) {
        ipfix_flush(x, now_sec); // the data waiting goes first
        start_message(x, now_ns, now_sec);
    }
    // Templates, also those ipfix_add() started a message with, never wait for batched data.
    if (x->len > IPFIX_HDR_LEN && get16(x->msg + IPFIX_HDR_LEN) == IPFIX_SET_TEMPLATE)
        ipfix_flush(x, now_sec);
}

static void send_message(struct ipfix_exporter *x, uint32_t now_sec) {
    close_set(x);
    (void)put_header(x->msg, x->len, now_sec, x->seq, x->domain);
    x->send(x->ctx, x->msg, x->len);
    // Counted even when sending failed: the sequence number counts data records (RFC 7011), so a
    // collector sees the gap and knows that records were lost.
    x->seq += x->records;
    x->n_messages++;
    x->n_records += x->records;
    x->msgs_since_tpl++;
    x->len = 0;
}

/* The path MTU shrank while the message was buffered: repack its fixed-length records in order. */
static void split_message(struct ipfix_exporter *x, uint32_t now_sec) {
    uint8_t msg[IPFIX_MSG_MAX];
    const size_t len = x->len;

    memcpy(msg, x->msg, len);
    begin_message(x);
    for (size_t off = IPFIX_HDR_LEN, end = 0; off < len; off = end) {
        const uint16_t id = get16(msg + off);
        size_t rlen = id == IPFIX_TPL_V4 ? IPFIX_REC_V4 : IPFIX_REC_V6;

        if (id == IPFIX_SET_TEMPLATE)
            rlen = TPL_LEN;
        end = off + get16(msg + off + 2);
        for (size_t pos = off + 4; pos < end; pos += rlen) {
            if (!fits(x, rlen, id)) {
                send_message(x, now_sec);
                begin_message(x);
            }
            if (x->set_id != id)
                open_set(x, id);
            memcpy(x->msg + x->len, msg + pos, rlen);
            x->len += rlen;
            x->records += id != IPFIX_SET_TEMPLATE;
        }
    }
    send_message(x, now_sec);
}

void ipfix_flush(struct ipfix_exporter *x, uint32_t now_sec) {
    if (!x->len)
        return;
    if (x->len == IPFIX_HDR_LEN) { // the templates went on their own and no record followed
        x->len = 0;
        return;
    }
    close_set(x); // complete the set lengths split_message() reads
    if (x->len > x->max_len)
        split_message(x, now_sec);
    else
        send_message(x, now_sec);
}

void ipfix_add(struct ipfix_exporter *x, const struct ipfix_record *rec, uint64_t now_ns, uint32_t now_sec) {
    const struct flow_key *k = rec->key;
    const bool v6 = k->ipver == 6;
    const bool icmp = k->proto == FLOW_PROTO_ICMP || k->proto == FLOW_PROTO_ICMPV6;
    const bool out = k->dir == FLOW_DIR_OUT;
    const size_t alen = v6 ? 16 : 4;
    const size_t rlen = v6 ? IPFIX_REC_V6 : IPFIX_REC_V4;
    const uint16_t id = v6 ? IPFIX_TPL_V6 : IPFIX_TPL_V4;
    const __be16 none = 0;
    uint8_t *p = nullptr;

    if (!x->len)
        start_message(x, now_ns, now_sec);
    if (!fits(x, rlen, id)) {
        ipfix_flush(x, now_sec);
        start_message(x, now_ns, now_sec);
    }
    if (x->set_id != id)
        open_set(x, id);

    p = put_bytes(x->msg + x->len, k->src, alen);
    p = put_bytes(p, k->dst, alen);
    p = put_bytes(p, icmp ? &none : &k->sport, 2); // ports are already in network order
    p = put_bytes(p, icmp ? &none : &k->dport, 2);
    p = put_bytes(p, icmp ? &k->dport : &none, 2); // ICMP type and code
    p = put8(put8(p, k->proto), rec->tos);
    p = put16(p, k->proto == FLOW_PROTO_TCP ? rec->tcp_flags : 0);
    p = put32(put32(p, k->in_if), k->out_if);
    // The VLAN of the metered interface in this direction: like ingressInterface/egressInterface,
    // the elements of the other direction stay 0.
    p = put16(put16(p, out ? 0 : rec->vlan), out ? rec->vlan : 0);
    p = put16(put16(p, out ? 0 : rec->vlan_inner), out ? rec->vlan_inner : 0);
    p = put8(p, k->dir);
    p = put64(put64(p, rec->packets), rec->bytes);
    p = put64(put64(p, rec->start_ms), rec->end_ms);
    (void)put8(p, rec->end_reason);

    x->len += rlen;
    x->records++;
    if (!fits(x, IPFIX_REC_V4, IPFIX_TPL_V4))
        ipfix_flush(x, now_sec); // full: waiting gains nothing
}
