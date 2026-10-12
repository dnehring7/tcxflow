// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file collector.h
 * @brief IPFIX collector addresses: parsing and UDP sockets
 */

#ifndef TCXFLOW_COLLECTOR_H
#define TCXFLOW_COLLECTOR_H

#include <stddef.h>

#define COLLECTOR_DEFAULT_PORT "4739" ///< IANA port for IPFIX, used when an address has none

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
int collector_split(const char *spec, char *host, size_t hostlen, char *port, size_t portlen);

/**
 * Resolve @p spec and open a connected, non-blocking UDP socket to it. Every address the
 * name resolves to is tried in turn.
 *
 * @param spec    collector address, see collector_split()
 * @param err     receives the error message
 * @param errlen  size of @p err
 * @return socket descriptor, or -1 with a message in @p err
 */
int collector_open(const char *spec, char *err, size_t errlen);

/**
 * Largest IPFIX message that fits the path MTU of a socket from collector_open() without
 * fragmentation (the route MTU, lowered by what path MTU discovery has learned).
 *
 * @param fd  collector socket
 * @return message size in bytes, 0 if unknown
 */
size_t collector_max_message(int fd);

/**
 * Send one message on a socket from collector_open().
 *
 * A connected UDP socket reports an ICMP error (collector down or restarting) on the next
 * send, which then fails with ECONNREFUSED without sending anything. That call has
 * consumed the error, so the message is sent once more: a collector that is back up gets it.
 *
 * @param fd   collector socket
 * @param msg  message
 * @param len  message length
 * @return 0 if sent; 1 if sent once more after the error (the collector was down or restarted:
 *         it has lost the templates); -1 (errno set) if the message was not sent
 */
int collector_send(int fd, const void *msg, size_t len);

#endif // TCXFLOW_COLLECTOR_H
