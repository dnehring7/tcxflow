// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file collector.h
 * @brief IPFIX collector addresses: parsing and UDP sockets
 */

#ifndef TCXFLOW_COLLECTOR_H
#define TCXFLOW_COLLECTOR_H

#include <stddef.h>
#include <stdint.h>

#define COLLECTOR_DEFAULT_PORT "4739" ///< IANA port for IPFIX, used when an address has none

/** A collector: its socket and the state of the message stream to it. */
struct collector {
    const char *name;       /**< address as configured, for log messages */
    int fd;                 /**< connected UDP socket from collector_open(), -1 = none */
    uint64_t sent;          /**< messages sent */
    uint64_t errors;        /**< messages that could not be sent */
    uint64_t failing;       /**< messages not sent since the last one that was */
    uint64_t wait_until_ns; /**< wait for room in a full send buffer until then (CLOCK_MONOTONIC), 0 = never */
    bool refused;           /**< the last message was refused: the collector is down or restarting */
    bool templates_due;     /**< send the templates before the next message */
};

/**
 * Writes the index-th message with just the templates into @p buf (ipfix_template_message()).
 *
 * @return message length, 0 after the last message
 */
typedef size_t (*collector_templates_fn)(void *ctx, unsigned index, uint8_t *buf, size_t len);

/**
 * Split "host:port", "[ipv6]:port", "host" or "[ipv6]" into host and port.
 * A missing port becomes COLLECTOR_DEFAULT_PORT.
 *
 * @param spec     collector address
 * @param host     receives the host name or address, without brackets
 * @param hostlen  size of @p host
 * @param port     receives the port
 * @param portlen  size of @p port
 * @return 0 on success, -1 if @p spec is malformed or a part does not fit
 */
[[nodiscard]] int collector_split(const char *spec, char *host, size_t hostlen, char *port, size_t portlen);

/**
 * Resolve @p spec and open a connected, non-blocking UDP socket to it. Every address the
 * name resolves to is tried in turn.
 *
 * @param spec    collector address, see collector_split()
 * @param err     receives the error message
 * @param errlen  size of @p err
 * @return socket descriptor, or -1 with a message in @p err
 */
[[nodiscard]] int collector_open(const char *spec, char *err, size_t errlen);

/**
 * Largest IPFIX message that fits the path MTU of a socket from collector_open() without
 * fragmentation (the route MTU, lowered by what path MTU discovery has learned).
 *
 * @param fd  collector socket
 * @return message size in bytes, 0 if unknown
 */
[[nodiscard]] size_t collector_max_message(int fd);

/**
 * Send one message to a collector, with the templates first where it needs them.
 *
 * A connected UDP socket reports an ICMP error (collector down or restarting) on the next
 * send, which then fails with ECONNREFUSED without sending anything. That call consumed the
 * error: the templates, which a restarted collector no longer knows, go out, then the message
 * once more. A message that could not be sent may have carried the templates: they precede the
 * next one. Only this collector gets them, the others are not affected. The first failure and
 * the recovery are logged, not every message. A full send buffer is waited for until
 * c->wait_until_ns, not longer.
 *
 * @param c          collector
 * @param msg        message
 * @param len        message length
 * @param templates  writes the template messages
 * @param ctx        passed to @p templates
 * @return 0, or -1 (errno set) if the message was not sent
 */
[[nodiscard]] int collector_export(struct collector *c, const void *msg, size_t len, collector_templates_fn templates,
                                   void *ctx);

#endif // TCXFLOW_COLLECTOR_H
