// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file collector.c
 * @brief IPFIX collector addresses: parsing and UDP sockets
 */

#include "collector.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"

static constexpr int SNDBUF_SIZE = 4 << 20;     ///< socket send buffer, absorbs export bursts
static constexpr int IPV4_UDP_HDRS = 28;        ///< IPv4 and UDP header bytes in front of an IPFIX message
static constexpr int IPV6_UDP_HDRS = 48;        ///< IPv6 and UDP header bytes in front of an IPFIX message
static constexpr size_t TEMPLATE_MSG_MAX = 512; ///< buffer for a template message (IPFIX: 188 bytes)

/* Copy n bytes of src into dst as a string; fails if empty or too long. */
static int copy_part(char *dst, size_t dstlen, const char *src, size_t n) {
    if (n == 0 || n >= dstlen)
        return -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

static bool valid_port(const char *port) {
    unsigned long val = 0;

    if (!*port || strlen(port) > 5)
        return false;
    for (const char *p = port; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        val = (val * 10) + (unsigned long)(*p - '0');
    }
    return val >= 1 && val <= 65535;
}

int collector_split(const char *spec, char *host, size_t hostlen, char *port, size_t portlen) {
    const char *colon = strrchr(spec, ':');
    const char *portstr = COLLECTOR_DEFAULT_PORT;

    if (spec[0] == '[') { // [ipv6] or [ipv6]:port
        const char *end = strchr(spec, ']');

        if (!end || copy_part(host, hostlen, spec + 1, (size_t)(end - spec - 1)))
            return -1;
        if (end[1] == ':')
            portstr = end + 2;
        else if (end[1] != '\0')
            return -1;
    } else if (colon && colon == strchr(spec, ':')) { // exactly one colon: host:port
        if (copy_part(host, hostlen, spec, (size_t)(colon - spec)))
            return -1;
        portstr = colon + 1;
    } else { // host name, IPv4 address or bare IPv6 address
        if (copy_part(host, hostlen, spec, strlen(spec)))
            return -1;
    }
    if (!valid_port(portstr) || copy_part(port, portlen, portstr, strlen(portstr)))
        return -1;
    return 0;
}

size_t collector_max_message(int fd) {
    struct sockaddr_storage sa = {};
    socklen_t salen = sizeof(sa);
    int mtu = 0;
    socklen_t mtulen = sizeof(mtu);

    if (getsockname(fd, (struct sockaddr *)&sa, &salen))
        return 0;
    if (sa.ss_family == AF_INET6) {
        if (getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, &mtulen) || mtu <= IPV6_UDP_HDRS)
            return 0;
        return (size_t)mtu - IPV6_UDP_HDRS;
    }
    if (getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &mtulen) || mtu <= IPV4_UDP_HDRS)
        return 0;
    return (size_t)mtu - IPV4_UDP_HDRS;
}

static int send_templates(const struct collector *c, collector_templates_fn templates, void *ctx) {
    uint8_t buf[TEMPLATE_MSG_MAX];
    size_t n = 0;

    for (unsigned i = 0; (n = templates(ctx, i, buf, sizeof(buf))) != 0; i++)
        if (send(c->fd, buf, n, MSG_DONTWAIT) < 0)
            return -1;
    return 0;
}

int collector_export(struct collector *c, const void *msg, size_t len, collector_templates_fn templates, void *ctx) {
    ssize_t n = 0;

    if (c->templates_due && !send_templates(c, templates, ctx))
        c->templates_due = false;
    n = send(c->fd, msg, len, MSG_DONTWAIT);
    if (n < 0 && errno == ECONNREFUSED) {
        if (!c->refused)
            log_msg("collector %s: port unreachable, the collector is down or restarting", c->name);
        c->refused = true;
        // While it is still down, the templates draw the next refusal, which this send then reports.
        (void)send_templates(c, templates, ctx);
        n = send(c->fd, msg, len, MSG_DONTWAIT);
    }
    if (n < 0) {
        const int err = errno;

        if (c->failing++ == 0 && !c->refused) // a refusal has been logged already
            log_msg("collector %s: %s (counting the messages not sent)", c->name, strerror(err));
        c->errors++;
        c->templates_due = true;
        errno = err;
        return -1;
    }
    // One message for the end of an outage: the first that went out without a refusal.
    if (c->failing)
        log_msg("collector %s: reachable again, %llu messages not sent", c->name, (unsigned long long)c->failing);
    else if (c->refused)
        log_msg("collector %s: reachable again", c->name);
    c->failing = 0;
    c->refused = false;
    c->sent++;
    return 0;
}

int collector_open(const char *spec, char *err, size_t errlen) {
    struct addrinfo hints = {.ai_socktype = SOCK_DGRAM, .ai_flags = AI_NUMERICSERV};
    struct addrinfo *ai = nullptr;
    char host[256];
    char port[8];
    int sndbuf = SNDBUF_SIZE;
    int fd = -1;
    int rc = 0;

    if (collector_split(spec, host, sizeof(host), port, sizeof(port))) {
        (void)snprintf(err, errlen, "collector %s: invalid address", spec);
        return -1;
    }
    rc = getaddrinfo(host, port, &hints, &ai);
    if (rc) {
        (void)snprintf(err, errlen, "collector %s: %s", spec, gai_strerror(rc));
        return -1;
    }
    // Non-blocking: a collector that does not keep up must never stall the one-second tick.
    // Connected: the route is looked up once, and errors are reported per collector. Every
    // address is tried: an IPv6 address first in the list may have no route on this host.
    for (const struct addrinfo *cur = ai; cur; cur = cur->ai_next) {
        fd = socket(cur->ai_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd >= 0 && !connect(fd, cur->ai_addr, cur->ai_addrlen))
            break;
        rc = errno;
        if (fd >= 0)
            (void)close(fd);
        fd = -1;
    }
    if (fd < 0) {
        (void)snprintf(err, errlen, "collector %s: %s", spec, strerror(rc));
        freeaddrinfo(ai);
        return -1;
    }
    // A large buffer absorbs the burst when many flows end in one tick. SO_SNDBUFFORCE ignores
    // net.core.wmem_max (needs CAP_NET_ADMIN); SO_SNDBUF is capped by it.
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)))
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    freeaddrinfo(ai);
    return fd;
}
