// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file test_unit.c
 * @brief Unit tests: configuration, collector addresses, IPFIX encoding, flow cache
 *
 * Needs no privileges and no BPF: `make test`.
 */

#include <arpa/inet.h>
#include <errno.h> // IWYU pragma: keep (ENOSPC)
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cache.h"
#include "collector.h"
#include "config.h"
#include "control.h"
#include "flow.h"
#include "ipfix.h"
#include "test.h"
#include "util.h"
#include "vlan.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                            */

static int parse_config(struct config *cfg, const char *text, char *err, size_t errlen) {
    char *copy = strdup(text);
    FILE *fp = copy ? fmemopen(copy, strlen(copy), "r") : NULL;
    int rc = -2;

    config_init(cfg);
    if (fp) {
        rc = config_read(cfg, fp, "test.conf", err, errlen);
        (void)fclose(fp);
    }
    free(copy);
    return rc;
}

static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint32_t get32(const uint8_t *p) { return ((uint32_t)get16(p) << 16) | get16(p + 2); }

static uint64_t get64(const uint8_t *p) { return ((uint64_t)get32(p) << 32) | get32(p + 4); }

static struct flow_key make_key(int ipver, uint8_t proto, uint16_t sport, uint16_t dport) {
    struct flow_key k;

    memset(&k, 0, sizeof(k));
    k.ipver = (uint8_t)ipver;
    k.proto = proto;
    k.sport = htons(sport);
    k.dport = htons(dport);
    if (ipver == 4) {
        (void)inet_pton(AF_INET, "192.0.2.1", k.src);
        (void)inet_pton(AF_INET, "198.51.100.2", k.dst);
    } else {
        (void)inet_pton(AF_INET6, "2001:db8::1", k.src);
        (void)inet_pton(AF_INET6, "2001:db8::2", k.dst);
    }
    k.in_if = 3;
    k.out_if = 4;
    k.dir = FLOW_DIR_OUT;
    k.tos = 0x28;
    return k;
}

/* IPFIX messages captured from the encoder */
#define MAX_MSGS 64
static uint8_t msgs[MAX_MSGS][IPFIX_MSG_MAX];
static size_t msg_len[MAX_MSGS];
static int n_msgs;

static void capture(void *ctx, const uint8_t *msg, size_t len) {
    (void)ctx;
    if (n_msgs < MAX_MSGS) {
        memcpy(msgs[n_msgs], msg, len);
        msg_len[n_msgs] = len;
    }
    n_msgs++;
}

/* Offset of the first set with @p set_id in message @p m, or 0. */
static size_t find_set(int m, uint16_t set_id) {
    for (size_t off = IPFIX_HDR_LEN; off + 4 <= msg_len[m]; off += get16(msgs[m] + off + 2)) {
        if (get16(msgs[m] + off) == set_id)
            return off;
        if (get16(msgs[m] + off + 2) < 4)
            break;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                      */

static void test_config_defaults(void) {
    struct config cfg;

    config_init(&cfg);
    CHECK_EQ(cfg.n_ifaces, 0);
    CHECK_EQ(cfg.n_collectors, 0);
    CHECK_EQ(cfg.inactive_timeout, 15);
    CHECK_EQ(cfg.active_timeout, 1800);
    CHECK_EQ(cfg.max_flows, 131072);
    CHECK_EQ(cfg.observation_domain, 1);
    CHECK_STR(cfg.netns, "");
    CHECK_STR(cfg.socket, CONFIG_DEFAULT_SOCKET);
}

static void test_config_file(void) {
    static const char text[] = "# tcxflow test configuration\n"
                               "\n"
                               "netns dataplane\n"
                               "interface\teth0          # both directions\n"
                               "  interface = eth1:in\n"
                               "interface eth2:out\n"
                               "interface=eth3:both\n"
                               "collector 192.0.2.10:2056\n"
                               "collector [2001:db8::10]:2058\n"
                               "inactive-timeout 30\n"
                               "active-timeout   120\n"
                               "max-flows 65536\n"
                               "observation-domain 4711\n"
                               "socket /run/test.sock\n";
    struct config cfg;
    char err[256] = "";

    CHECK_EQ(parse_config(&cfg, text, err, sizeof(err)), 0);
    CHECK_STR(err, "");
    CHECK_STR(cfg.netns, "dataplane");
    CHECK_EQ(cfg.n_ifaces, 4);
    CHECK_STR(cfg.ifaces[0].name, "eth0");
    CHECK(cfg.ifaces[0].dir[FLOW_DIR_IN] && cfg.ifaces[0].dir[FLOW_DIR_OUT]);
    CHECK_STR(cfg.ifaces[1].name, "eth1");
    CHECK(cfg.ifaces[1].dir[FLOW_DIR_IN] && !cfg.ifaces[1].dir[FLOW_DIR_OUT]);
    CHECK(!cfg.ifaces[2].dir[FLOW_DIR_IN] && cfg.ifaces[2].dir[FLOW_DIR_OUT]);
    CHECK(cfg.ifaces[3].dir[FLOW_DIR_IN] && cfg.ifaces[3].dir[FLOW_DIR_OUT]);
    CHECK_EQ(cfg.n_collectors, 2);
    CHECK_STR(cfg.collectors[0], "192.0.2.10:2056");
    CHECK_STR(cfg.collectors[1], "[2001:db8::10]:2058");
    CHECK_EQ(cfg.inactive_timeout, 30);
    CHECK_EQ(cfg.active_timeout, 120);
    CHECK_EQ(cfg.max_flows, 65536);
    CHECK_EQ(cfg.observation_domain, 4711);
    CHECK_STR(cfg.socket, "/run/test.sock");
    CHECK_EQ(config_validate(&cfg, err, sizeof(err)), 0);
}

static void test_config_errors(void) {
    static const struct {
        const char *text;
        const char *message;
    } cases[] = {
        {"interface eth0\nbogus 1\n", "test.conf:2: unknown option \"bogus\""},
        {"interface\n", "test.conf:1: interface needs a value"},
        {"interface eth0:sideways\n", "direction must be in, out or both"},
        {"interface eth0\ninterface eth0:in\n", "interface eth0 is given twice"},
        {"interface abcdefghijklmnopq\n", "invalid name"},
        {"interface :in\n", "invalid name"},
        {"collector host:\n", "invalid address"},
        {"collector [2001:db8::1\n", "invalid address"},
        {"inactive-timeout 0\n", "inactive-timeout must be a number from 1 to 86400"},
        {"inactive-timeout 15s\n", "must be a number"},
        {"active-timeout -5\n", "must be a number"},
        {"max-flows 100\n", "max-flows must be a number from 1024"},
        {"observation-domain 4294967296\n", "must be a number"},
        {"netns relative/path\n", "netns must be a name or an absolute path"},
        {"socket run/x.sock\n", "socket must be an absolute path"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct config cfg;
        char err[256] = "";

        CHECK_EQ(parse_config(&cfg, cases[i].text, err, sizeof(err)), (unsigned long long)-1);
        if (!strstr(err, cases[i].message)) {
            test_errors++;
            (void)fprintf(stderr, "    case %zu: error \"%s\" does not contain \"%s\"\n", i, err, cases[i].message);
        }
    }
}

static void test_config_long_line(void) {
    char text[1024];
    struct config cfg;
    char err[256] = "";

    memset(text, 'x', sizeof(text) - 2);
    text[sizeof(text) - 2] = '\n';
    text[sizeof(text) - 1] = '\0';
    CHECK_EQ(parse_config(&cfg, text, err, sizeof(err)), (unsigned long long)-1);
    CHECK_CONTAINS(err, "line too long");
}

static void test_config_limits(void) {
    struct config cfg;
    char err[256];
    char value[32];

    config_init(&cfg);
    for (int i = 0; i < CONFIG_MAX_IFACES; i++) {
        (void)snprintf(value, sizeof(value), "eth%d", i);
        CHECK_EQ(config_set(&cfg, "interface", value, err, sizeof(err)), 0);
    }
    CHECK_EQ(config_set(&cfg, "interface", "one-too-many", err, sizeof(err)), (unsigned long long)-1);
    CHECK_CONTAINS(err, "too many interfaces");
    for (int i = 0; i < CONFIG_MAX_COLLECTORS; i++) {
        (void)snprintf(value, sizeof(value), "192.0.2.%d:4739", i + 1);
        CHECK_EQ(config_set(&cfg, "collector", value, err, sizeof(err)), 0);
    }
    CHECK_EQ(config_set(&cfg, "collector", "192.0.2.99", err, sizeof(err)), (unsigned long long)-1);
    CHECK_CONTAINS(err, "too many collectors");
}

static void test_config_validate(void) {
    struct config cfg;
    char err[256];

    config_init(&cfg);
    CHECK_EQ(config_validate(&cfg, err, sizeof(err)), (unsigned long long)-1);
    CHECK_STR(err, "no interface configured");
    CHECK_EQ(config_set(&cfg, "interface", "eth0", err, sizeof(err)), 0);
    CHECK_EQ(config_validate(&cfg, err, sizeof(err)), (unsigned long long)-1);
    CHECK_STR(err, "no collector configured");
    CHECK_EQ(config_set(&cfg, "collector", "localhost", err, sizeof(err)), 0);
    CHECK_EQ(config_validate(&cfg, err, sizeof(err)), 0);
}

/* ------------------------------------------------------------------ */
/* Collector addresses                                                */

static void test_collector_split(void) {
    static const struct {
        const char *spec, *host, *port;
    } good[] = {
        {"192.0.2.1:2055", "192.0.2.1", "2055"},       {"collector.example.org", "collector.example.org", "4739"},
        {"[2001:db8::1]:9995", "2001:db8::1", "9995"}, {"[2001:db8::1]", "2001:db8::1", "4739"},
        {"2001:db8::1", "2001:db8::1", "4739"},        {"h:65535", "h", "65535"},
    };
    static const char *const bad[] = {"",      "host:",        "host:0", "host:65536", "host:12a",
                                      ":4739", "[2001:db8::1", "[]:1",   "[::1]x",     "[::1]:"};
    char host[64];
    char port[8];

    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        CHECK_EQ(collector_split(good[i].spec, host, sizeof(host), port, sizeof(port)), 0);
        CHECK_STR(host, good[i].host);
        CHECK_STR(port, good[i].port);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (collector_split(bad[i], host, sizeof(host), port, sizeof(port)) != -1) {
            test_errors++;
            (void)fprintf(stderr, "    \"%s\" was accepted\n", bad[i]);
        }
    }
    CHECK_EQ(collector_split("a-very-long-host-name:1", host, 8, port, sizeof(port)), (unsigned long long)-1);
}

/* UDP socket bound to 127.0.0.1:port (0 = any free port); the port is stored back. */
static int udp_listen(uint16_t *port) {
    struct sockaddr_in sa = {
        .sin_family = AF_INET, .sin_port = htons(*port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(sa);
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    if (fd < 0 || bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) || getsockname(fd, (struct sockaddr *)&sa, &len)) {
        if (fd >= 0)
            (void)close(fd);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return fd;
}

/* A collector that was down (ICMP port unreachable) and is back must get the next message. */
static void test_collector_send_after_refused(void) {
    uint16_t port = 0;
    char spec[32];
    char err[256];
    char buf[16] = {0};
    int rx = udp_listen(&port);
    int fd = -1;

    CHECK(rx >= 0);
    if (rx < 0)
        return;
    (void)close(rx); // nothing listens on the port now
    (void)snprintf(spec, sizeof(spec), "127.0.0.1:%u", port);
    fd = collector_open(spec, err, sizeof(err));
    CHECK(fd >= 0);
    if (fd < 0)
        return;
    CHECK_EQ(collector_send(fd, "one", 3), 0); // goes out, the kernel answers port unreachable
    (void)usleep(20000);                       // the ICMP error is now pending on fd
    rx = udp_listen(&port);                    // the collector is back
    CHECK(rx >= 0);
    if (rx >= 0) {
        struct pollfd pfd = {.fd = rx, .events = POLLIN};

        CHECK_EQ(collector_send(fd, "two", 3), 1); // sent on the second try: the collector restarted
        CHECK_EQ(poll(&pfd, 1, 1000), 1);
        CHECK_EQ(recv(rx, buf, sizeof(buf), MSG_DONTWAIT), 3);
        CHECK_STR(buf, "two");
        (void)close(rx);
    }
    (void)close(fd);
}

/* The path MTU of a connected collector socket is known. */
static void test_collector_max_message(void) {
    char err[256];
    const int fd = collector_open("127.0.0.1:9", err, sizeof(err));

    CHECK(fd >= 0);
    if (fd < 0)
        return;
    CHECK(collector_max_message(fd) > IPFIX_MSG_MAX); // loopback: about 64 KiB
    (void)close(fd);
}

/* One owner per control socket; a stale socket is replaced, anything else is left alone. */
static void test_control_lock(void) {
    char dir[] = "/tmp/tcxflow-test.XXXXXX";
    char sock[64];
    char file[64];
    int lock1 = -1;
    int lock2 = -1;
    int fd1 = -1;
    int fd2 = -1;
    FILE *fp = NULL;

    CHECK(mkdtemp(dir) != NULL);
    (void)snprintf(sock, sizeof(sock), "%s/sock", dir);
    (void)snprintf(file, sizeof(file), "%s/file", dir);
    fd1 = control_listen(sock, &lock1);
    CHECK(fd1 >= 0);
    fd2 = control_listen(sock, &lock2);
    CHECK_EQ(fd2, -1);
    CHECK_EQ(errno, EADDRINUSE);
    (void)close(fd1); // the socket file stays behind, as after a crash
    (void)close(lock1);
    fd2 = control_listen(sock, &lock2);
    CHECK(fd2 >= 0);
    fp = fopen(file, "we");
    CHECK(fp != NULL);
    if (fp)
        (void)fclose(fp);
    CHECK_EQ(control_listen(file, &lock1), -1);
    CHECK_EQ(errno, EEXIST);
    CHECK_EQ(access(file, F_OK), 0); // not deleted
    if (fd2 >= 0) {
        (void)close(fd2);
        (void)close(lock2);
    }
    (void)unlink(sock);
    (void)unlink(file);
    (void)snprintf(file, sizeof(file), "%s/sock.lock", dir);
    (void)unlink(file);
    (void)snprintf(file, sizeof(file), "%s/file.lock", dir);
    (void)unlink(file);
    CHECK_EQ(rmdir(dir), 0);
}

/* /proc/net/vlan/config: VLAN ID and lower interface by name; header lines are skipped. */
static void test_vlan_parse(void) {
    static const char listing[] = "VLAN Dev name\t | VLAN ID\n"
                                  "Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n"
                                  "eth0.100       | 100  | eth0\n"
                                  "eth0.400       | 400  | eth0\n"
                                  "eth0.400.500   | 500  | eth0.400\n";
    static const struct {
        const char *name;
        uint16_t vid;
        const char *lower;
    } cases[] = {{"eth0.100", 100, "eth0"}, {"eth0.400.500", 500, "eth0.400"}, {"eth0", 0, ""}, {"eth0.1", 0, ""}};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *copy = strdup(listing);
        FILE *fp = copy ? fmemopen(copy, strlen(copy), "r") : NULL;
        char lower[16] = "";

        CHECK(fp != NULL);
        if (fp) {
            CHECK_EQ(vlan_parse(fp, cases[i].name, lower, sizeof(lower)), cases[i].vid);
            CHECK_STR(lower, cases[i].lower);
            (void)fclose(fp);
        }
        free(copy);
    }
}

/* ------------------------------------------------------------------ */
/* IPFIX encoder                                                      */

static void test_ipfix_message_layout(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, FLOW_PROTO_TCP, 40000, 443);
    const struct ipfix_record rec = {.key = &key,
                                     .start_ms = 1760000000123ULL,
                                     .end_ms = 1760000004567ULL,
                                     .packets = 12,
                                     .bytes = 3456,
                                     .tos = 0x2a,
                                     .tcp_flags = 0xe1b,
                                     .vlan = 100,
                                     .vlan_inner = 200,
                                     .end_reason = IPFIX_END_IDLE};
    const uint8_t *m = NULL;
    const uint8_t *d = NULL;
    size_t tpl = 0;
    size_t data = 0;

    n_msgs = 0;
    ipfix_init(&x, 42, capture, NULL);
    ipfix_add(&x, &rec, 1000, 1760000005);
    CHECK_EQ(n_msgs, 0); // nothing is sent before the flush
    ipfix_flush(&x, 1760000005);
    CHECK_EQ(n_msgs, 1);
    m = msgs[0];

    // Message header
    CHECK_EQ(get16(m), 10);
    CHECK_EQ(get16(m + 2), msg_len[0]);
    CHECK_EQ(get32(m + 4), 1760000005);
    CHECK_EQ(get32(m + 8), 0); // sequence number
    CHECK_EQ(get32(m + 12), 42);

    // Template set: IPv4 and IPv6 templates with 20 fields each
    tpl = find_set(0, IPFIX_SET_TEMPLATE);
    CHECK_EQ(tpl, IPFIX_HDR_LEN);
    CHECK_EQ(get16(m + tpl + 2), 4 + (2 * (4 + (20 * 4))));
    CHECK_EQ(get16(m + tpl + 4), IPFIX_TPL_V4);
    CHECK_EQ(get16(m + tpl + 6), 20);
    CHECK_EQ(get16(m + tpl + 8), 8); // sourceIPv4Address
    CHECK_EQ(get16(m + tpl + 10), 4);
    CHECK_EQ(get16(m + tpl + 8 + (10 * 4)), 58);  // vlanId
    CHECK_EQ(get16(m + tpl + 8 + (13 * 4)), 255); // postDot1qCustomerVlanId
    CHECK_EQ(get16(m + tpl + 4 + 84), IPFIX_TPL_V6);
    CHECK_EQ(get16(m + tpl + 4 + 84 + 4), 27); // sourceIPv6Address
    CHECK_EQ(get16(m + tpl + 4 + 84 + 6), 16);

    // Data set with one record, fields in template order
    data = find_set(0, IPFIX_TPL_V4);
    CHECK(data != 0);
    CHECK_EQ(get16(m + data + 2), 4 + IPFIX_REC_V4);
    CHECK_EQ(data + 4 + IPFIX_REC_V4, msg_len[0]);
    d = m + data + 4;
    CHECK(memcmp(d, key.src, 4) == 0);
    CHECK(memcmp(d + 4, key.dst, 4) == 0);
    CHECK_EQ(get16(d + 8), 40000);
    CHECK_EQ(get16(d + 10), 443);
    CHECK_EQ(get16(d + 12), 0); // icmpTypeCode
    CHECK_EQ(d[14], FLOW_PROTO_TCP);
    CHECK_EQ(d[15], 0x2a);          // ipClassOfService: DSCP and ECN
    CHECK_EQ(get16(d + 16), 0xe1b); // tcpControlBits, including the reserved bits
    CHECK_EQ(get32(d + 18), 3);
    CHECK_EQ(get32(d + 22), 4);
    CHECK_EQ(get16(d + 26), 0);   // vlanId: an egress record ...
    CHECK_EQ(get16(d + 28), 100); // ... has its VLAN in postVlanId
    CHECK_EQ(get16(d + 30), 0);
    CHECK_EQ(get16(d + 32), 200); // postDot1qCustomerVlanId
    CHECK_EQ(d[34], FLOW_DIR_OUT);
    CHECK_EQ(get64(d + 35), 12);
    CHECK_EQ(get64(d + 43), 3456);
    CHECK_EQ(get64(d + 51), 1760000000123ULL);
    CHECK_EQ(get64(d + 59), 1760000004567ULL);
    CHECK_EQ(d[67], IPFIX_END_IDLE);
    CHECK_EQ(x.n_records, 1);
    CHECK_EQ(x.n_messages, 1);
}

/* An ingress record carries its VLANs in vlanId and dot1qCustomerVlanId. */
static void test_ipfix_vlan_ingress(void) {
    struct ipfix_exporter x;
    struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1, .vlan = 300, .vlan_inner = 7};
    const uint8_t *d = NULL;
    size_t data = 0;

    key.dir = FLOW_DIR_IN;
    n_msgs = 0;
    ipfix_init(&x, 1, capture, NULL);
    ipfix_add(&x, &rec, 0, 0);
    ipfix_flush(&x, 0);
    data = find_set(0, IPFIX_TPL_V4);
    CHECK(data != 0);
    d = msgs[0] + data + 4;
    CHECK_EQ(get16(d + 26), 300);
    CHECK_EQ(get16(d + 28), 0);
    CHECK_EQ(get16(d + 30), 7);
    CHECK_EQ(get16(d + 32), 0);
    CHECK_EQ(d[34], FLOW_DIR_IN);
}

static void test_ipfix_icmp_and_ipv6(void) {
    struct ipfix_exporter x;
    const struct flow_key icmp = make_key(4, FLOW_PROTO_ICMP, 0, 0x0800); // echo request
    const struct flow_key v6 = make_key(6, FLOW_PROTO_ICMPV6, 0, 0x8100); // ICMPv6 echo request
    struct ipfix_record rec = {.key = &icmp, .packets = 1, .bytes = 84, .tcp_flags = 0x02};
    const uint8_t *d = NULL;
    size_t off = 0;

    n_msgs = 0;
    ipfix_init(&x, 0, capture, NULL);
    ipfix_add(&x, &rec, 0, 1);
    rec.key = &v6;
    ipfix_add(&x, &rec, 0, 1);
    rec.key = &icmp;
    ipfix_add(&x, &rec, 0, 1);
    ipfix_flush(&x, 1);
    CHECK_EQ(n_msgs, 1);

    // Sets: template, IPv4 data, IPv6 data, IPv4 data again
    off = IPFIX_HDR_LEN + get16(msgs[0] + IPFIX_HDR_LEN + 2);
    CHECK_EQ(get16(msgs[0] + off), IPFIX_TPL_V4);
    CHECK_EQ(get16(msgs[0] + off + 2), 4 + IPFIX_REC_V4);
    d = msgs[0] + off + 4;
    CHECK_EQ(get16(d + 8), 0);       // sourceTransportPort
    CHECK_EQ(get16(d + 10), 0);      // destinationTransportPort
    CHECK_EQ(get16(d + 12), 0x0800); // icmpTypeCodeIPv4
    CHECK_EQ(get16(d + 16), 0);      // tcpControlBits only for TCP
    off += 4 + IPFIX_REC_V4;
    CHECK_EQ(get16(msgs[0] + off), IPFIX_TPL_V6);
    CHECK_EQ(get16(msgs[0] + off + 2), 4 + IPFIX_REC_V6);
    d = msgs[0] + off + 4;
    CHECK(memcmp(d, v6.src, 16) == 0);
    CHECK_EQ(get16(d + 36), 0x8100); // icmpTypeCodeIPv6
    off += 4 + IPFIX_REC_V6;
    CHECK_EQ(get16(msgs[0] + off), IPFIX_TPL_V4);
    CHECK_EQ(off + 4 + IPFIX_REC_V4, msg_len[0]);
}

/* The message limit follows the path MTU, within IPFIX_MSG_MIN..IPFIX_MSG_MAX. */
static void test_ipfix_max_len(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1, .bytes = 100};

    ipfix_init(&x, 1, capture, NULL);
    n_msgs = 0;
    ipfix_set_max_len(&x, 300);
    for (int i = 0; i < 30; i++)
        ipfix_add(&x, &rec, 0, 0);
    ipfix_flush(&x, 0);
    CHECK(n_msgs >= 3);
    for (int i = 0; i < n_msgs && i < MAX_MSGS; i++)
        CHECK(msg_len[i] <= 300);
    ipfix_set_max_len(&x, 100);
    CHECK_EQ(x.max_len, IPFIX_MSG_MIN);
    ipfix_set_max_len(&x, 0);
    CHECK_EQ(x.max_len, IPFIX_MSG_MAX);
    ipfix_set_max_len(&x, 9000);
    CHECK_EQ(x.max_len, IPFIX_MSG_MAX);
}

static void test_ipfix_split_and_sequence(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1, .bytes = 100};
    uint32_t records = 0;

    n_msgs = 0;
    ipfix_init(&x, 0, capture, NULL);
    for (int i = 0; i < 50; i++)
        ipfix_add(&x, &rec, 0, 1);
    ipfix_flush(&x, 1);
    CHECK(n_msgs >= 3);
    CHECK_EQ(x.n_records, 50);
    for (int i = 0; i < n_msgs && i < MAX_MSGS; i++) {
        const size_t data = find_set(i, IPFIX_TPL_V4);

        CHECK(msg_len[i] <= IPFIX_MSG_MAX);
        CHECK_EQ(get32(msgs[i] + 8), records); // sequence = records sent before
        CHECK_EQ(find_set(i, IPFIX_SET_TEMPLATE) != 0, i == 0);
        records += (uint32_t)((get16(msgs[i] + data + 2) - 4) / IPFIX_REC_V4);
    }
    CHECK_EQ(records, 50);
}

static void test_ipfix_template_refresh(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1, .bytes = 100};

    n_msgs = 0;
    ipfix_init(&x, 0, capture, NULL);
    for (unsigned i = 0; i < IPFIX_TPL_REFRESH_MSGS + 1; i++) { // one record per message
        ipfix_add(&x, &rec, i * NSEC_PER_SEC, 1);
        ipfix_flush(&x, 1);
    }
    CHECK(find_set(0, IPFIX_SET_TEMPLATE) != 0);
    CHECK(find_set(1, IPFIX_SET_TEMPLATE) == 0);
    CHECK(find_set(IPFIX_TPL_REFRESH_MSGS, IPFIX_SET_TEMPLATE) != 0); // after 20 messages

    ipfix_add(&x, &rec, 30 * NSEC_PER_SEC, 1);
    ipfix_flush(&x, 1);
    CHECK(find_set(n_msgs - 1, IPFIX_SET_TEMPLATE) == 0);
    ipfix_add(&x, &rec, 100 * NSEC_PER_SEC, 1); // more than 60 s after the last templates
    ipfix_flush(&x, 1);
    CHECK(find_set(n_msgs - 1, IPFIX_SET_TEMPLATE) != 0);

    ipfix_add(&x, &rec, 101 * NSEC_PER_SEC, 1);
    ipfix_flush(&x, 1);
    CHECK(find_set(n_msgs - 1, IPFIX_SET_TEMPLATE) == 0);
    ipfix_resend_templates(&x); // a collector restarted
    ipfix_add(&x, &rec, 102 * NSEC_PER_SEC, 1);
    ipfix_flush(&x, 1);
    CHECK(find_set(n_msgs - 1, IPFIX_SET_TEMPLATE) != 0);
}

/* ------------------------------------------------------------------ */
/* Flow cache                                                         */

#define MAX_EXPORTED 8
static struct {
    struct flow_entry entry;
    uint8_t reason;
} exported[MAX_EXPORTED];
static int n_exported;

static void collect(void *ctx, const struct flow_entry *entry, uint8_t reason) {
    (void)ctx;
    if (n_exported < MAX_EXPORTED) {
        exported[n_exported].entry = *entry;
        exported[n_exported].reason = reason;
    }
    n_exported++;
}

static void count_only(void *ctx, const struct flow_entry *entry, uint8_t reason) {
    (void)entry;
    (void)reason;
    (*(uint32_t *)ctx)++;
}

static const struct expire_policy policy = {
    .inactive_ns = 15 * NSEC_PER_SEC,
    .active_ns = 60 * NSEC_PER_SEC,
    .fin_ns = 2 * NSEC_PER_SEC,
};

static void test_cache_merge(void) {
    struct flow_cache c;
    const struct flow_key key = make_key(4, FLOW_PROTO_TCP, 1000, 80);
    const struct flow_val first = {
        .first_ns = 100, .last_ns = 200, .packets = 3, .bytes = 300, .tcp_flags = 0x02, .ecn = 0};
    const struct flow_val second = {
        .first_ns = 1000, .last_ns = 1500, .packets = 2, .bytes = 80, .tcp_flags = 0x810, .ecn = 2};

    CHECK_EQ(cache_init(&c, 16, UINT32_MAX), 0);
    CHECK_EQ(cache_add(&c, &key, &first), 0);
    CHECK_EQ(cache_add(&c, &key, &second), 0);
    CHECK_EQ(c.count, 1);
    n_exported = 0;
    CHECK_EQ(cache_expire(&c, 2000, &policy, true, collect, NULL), 1);
    CHECK_EQ(exported[0].entry.first_ns, 100);
    CHECK_EQ(exported[0].entry.last_ns, 1500);
    CHECK_EQ(exported[0].entry.packets, 5);
    CHECK_EQ(exported[0].entry.bytes, 380);
    CHECK_EQ(exported[0].entry.tcp_flags, 0x812);
    CHECK_EQ(exported[0].entry.ecn, 0); // the first packet's, not the later ECT(0)
    CHECK_EQ(exported[0].reason, IPFIX_END_FORCED);
    CHECK_EQ(c.count, 0);
    cache_destroy(&c);
}

static void test_cache_expire_reasons(void) {
    struct flow_cache c;
    const uint64_t now = 1000 * NSEC_PER_SEC;
    const struct flow_key idle = make_key(4, 17, 1, 1);
    const struct flow_key active = make_key(4, 17, 2, 2);
    const struct flow_key fin = make_key(4, FLOW_PROTO_TCP, 3, 3);
    const struct flow_key fresh = make_key(4, FLOW_PROTO_TCP, 4, 4);
    const struct flow_val v_idle = {.first_ns = now - (20 * NSEC_PER_SEC), .last_ns = now - (16 * NSEC_PER_SEC)};
    const struct flow_val v_active = {.first_ns = now - (61 * NSEC_PER_SEC), .last_ns = now};
    const struct flow_val v_fin = {
        .first_ns = now - (5 * NSEC_PER_SEC), .last_ns = now - (3 * NSEC_PER_SEC), .tcp_flags = 0x11};
    const struct flow_val v_fresh = {.first_ns = now - NSEC_PER_SEC, .last_ns = now, .tcp_flags = 0x11};
    uint8_t reasons[5] = {0};

    CHECK_EQ(cache_init(&c, 16, UINT32_MAX), 0);
    CHECK_EQ(cache_add(&c, &idle, &v_idle), 0);
    CHECK_EQ(cache_add(&c, &active, &v_active), 0);
    CHECK_EQ(cache_add(&c, &fin, &v_fin), 0);
    CHECK_EQ(cache_add(&c, &fresh, &v_fresh), 0);

    n_exported = 0;
    CHECK_EQ(cache_expire(&c, now, &policy, false, collect, NULL), 3);
    for (int i = 0; i < n_exported && i < MAX_EXPORTED; i++)
        reasons[ntohs(exported[i].entry.key.sport)] = exported[i].reason;
    CHECK_EQ(reasons[1], IPFIX_END_IDLE);
    CHECK_EQ(reasons[2], IPFIX_END_ACTIVE);
    CHECK_EQ(reasons[3], IPFIX_END_DETECTED);
    CHECK_EQ(reasons[4], 0);
    CHECK_EQ(c.count, 1); // the fresh flow stays

    n_exported = 0;
    CHECK_EQ(cache_expire(&c, now, &policy, true, collect, NULL), 1);
    CHECK_EQ(ntohs(exported[0].entry.key.sport), 4);
    CHECK_EQ(exported[0].reason, IPFIX_END_FORCED);
    cache_destroy(&c);
}

static void test_cache_growth_and_reuse(void) {
    struct flow_cache c;
    const struct flow_val val = {.first_ns = 1, .last_ns = 1, .packets = 1, .bytes = 64};
    const uint32_t n = 200000;
    uint32_t count = 0;
    uint32_t used = 0;

    CHECK_EQ(cache_init(&c, 16, UINT32_MAX), 0);
    for (uint32_t i = 0; i < n; i++) {
        struct flow_key key = make_key(4, 17, (uint16_t)(i & 0xffff), (uint16_t)(i >> 16));

        CHECK_EQ(cache_add(&c, &key, &val), 0);
    }
    CHECK_EQ(c.count, n);
    CHECK(c.n_buckets >= n); // buckets doubled along the way
    used = c.used;
    CHECK_EQ(cache_expire(&c, 2, &policy, true, count_only, &count), n);
    CHECK_EQ(count, n);
    CHECK_EQ(c.count, 0);
    for (uint32_t i = 0; i < 1000; i++) { // free entries are reused
        struct flow_key key = make_key(4, 6, (uint16_t)i, 1);

        CHECK_EQ(cache_add(&c, &key, &val), 0);
    }
    CHECK_EQ(c.used, used);
    cache_destroy(&c);
}

static void test_cache_limit(void) {
    struct flow_cache c;
    const struct flow_val val = {.first_ns = 1, .last_ns = 1, .packets = 1, .bytes = 64};
    const struct flow_key k1 = make_key(4, 17, 1, 1);
    const struct flow_key k2 = make_key(4, 17, 2, 2);
    const struct flow_key k3 = make_key(4, 17, 3, 3);

    CHECK_EQ(cache_init(&c, 16, 2), 0);
    CHECK_EQ(cache_add(&c, &k1, &val), 0);
    CHECK_EQ(cache_add(&c, &k2, &val), 0);
    CHECK_EQ(cache_add(&c, &k3, &val), -ENOSPC); // a new flow does not fit
    CHECK_EQ(cache_add(&c, &k1, &val), 0);       // a cached one still adds up
    CHECK_EQ(c.count, 2);
    CHECK_EQ(c.entries[0].packets + c.entries[1].packets, 3); // k1 and k2, in the order added
    cache_destroy(&c);
}

/* Walk a list both ways: links must be symmetric and the length must match. */
static uint32_t list_length(const struct flow_cache *c, const struct cache_list *list, bool age) {
    uint32_t n = 0;
    uint32_t prev = CACHE_NIL;

    for (uint32_t i = list->head; i != CACHE_NIL && n <= c->count;
         i = age ? c->entries[i].age.next : c->entries[i].idle.next) {
        const struct cache_link *l = age ? &c->entries[i].age : &c->entries[i].idle;

        CHECK_EQ(l->prev, prev);
        prev = i;
        n++;
    }
    CHECK_EQ(list->tail, prev);
    return n;
}

/* The flow model of the randomized test: what a brute-force cache would hold. */
#define MODEL_KEYS 512
static struct {
    uint64_t first_ns;
    uint64_t last_ns;
    uint64_t packets;
    uint32_t tcp_flags;
    bool cached;
} model[MODEL_KEYS];
static bool model_exported[MODEL_KEYS];

static void model_collect(void *ctx, const struct flow_entry *entry, uint8_t reason) {
    const uint16_t k = ntohs(entry->key.sport);

    (void)ctx;
    (void)reason;
    if (k < MODEL_KEYS) {
        CHECK(model[k].cached);
        CHECK_EQ(entry->packets, model[k].packets);
        model_exported[k] = true;
    }
}

/*
 * O(1) expiry must decide exactly like looking at every flow: random updates, FIN/RST and
 * expiry over 300 ticks, compared with a brute-force model after every tick.
 */
static void test_cache_matches_brute_force(void) {
    struct flow_cache c;
    uint64_t rnd = 0x2545f4914f6cdd1dULL;

    memset(model, 0, sizeof(model));
    CHECK_EQ(cache_init(&c, 16, UINT32_MAX), 0);
    for (uint64_t tick = 1; tick <= 300; tick++) {
        const uint64_t now = tick * NSEC_PER_SEC;

        for (int u = 0; u < 40; u++) { // one interval: every update carries this tick's time
            uint16_t k = 0;
            struct flow_val v = {.first_ns = now, .last_ns = now, .packets = 1, .bytes = 100};
            struct flow_key key;

            rnd ^= rnd << 13;
            rnd ^= rnd >> 7;
            rnd ^= rnd << 17;
            k = (uint16_t)(rnd % MODEL_KEYS);
            v.tcp_flags = 0x10U; // ACK; now and then FIN or RST
            if ((rnd >> 20) % 50 == 0)
                v.tcp_flags = 0x01U;
            else if ((rnd >> 30) % 80 == 0)
                v.tcp_flags = 0x04U;
            key = make_key(4, FLOW_PROTO_TCP, k, 80);
            CHECK_EQ(cache_add(&c, &key, &v), 0);
            if (!model[k].cached)
                model[k] = (__typeof__(model[0])){.cached = true, .first_ns = now};
            model[k].last_ns = now;
            model[k].tcp_flags |= v.tcp_flags;
            model[k].packets++;
        }
        memset(model_exported, 0, sizeof(model_exported));
        (void)cache_expire(&c, now, &policy, false, model_collect, NULL);
        for (int k = 0; k < MODEL_KEYS; k++) {
            const bool ended =
                model[k].cached &&
                (now - model[k].last_ns >= policy.inactive_ns || now - model[k].first_ns >= policy.active_ns ||
                 ((model[k].tcp_flags & 0x05U) && now - model[k].last_ns >= policy.fin_ns));

            CHECK_EQ(model_exported[k], ended);
            if (ended)
                model[k].cached = false;
        }
        CHECK_EQ(list_length(&c, &c.idle, false) + list_length(&c, &c.fin, false), c.count);
        CHECK_EQ(list_length(&c, &c.age, true), c.count);
        if (test_errors)
            break; // one detailed failure is enough
    }
    cache_destroy(&c);
}

/*
 * Flows of one drained interval enter the lists in drain order, not timestamp order. A flow
 * whose timeout has passed can wait behind a younger one of the same interval, but never longer
 * than that interval: by then the younger one has expired as well.
 */
static void test_cache_expiry_delay_bounded(void) {
    struct flow_cache c;
    const struct flow_key young = make_key(4, 17, 1, 9);
    const struct flow_key old = make_key(4, 17, 2, 9);
    const struct flow_val v_young = {.first_ns = 900000000, .last_ns = 900000000, .packets = 1};
    const struct flow_val v_old = {.first_ns = 100000000, .last_ns = 100000000, .packets = 1};
    const struct expire_policy p = {.inactive_ns = 10 * NSEC_PER_SEC, .active_ns = 500000000, .fin_ns = NSEC_PER_SEC};
    uint32_t count = 0;

    CHECK_EQ(cache_init(&c, 16, 16), 0);
    CHECK_EQ(cache_add(&c, &young, &v_young), 0); // same interval, drained first
    CHECK_EQ(cache_add(&c, &old, &v_old), 0);
    (void)cache_expire(&c, 1000000000, &p, false, count_only, &count); // old is due, may wait
    CHECK(count <= 1);
    (void)cache_expire(&c, 1400000000, &p, false, count_only, &count); // young is due: both gone
    CHECK_EQ(count, 2);
    CHECK_EQ(c.count, 0);
    cache_destroy(&c);
}

int main(void) {
    RUN_TEST(test_config_defaults);
    RUN_TEST(test_config_file);
    RUN_TEST(test_config_errors);
    RUN_TEST(test_config_long_line);
    RUN_TEST(test_config_limits);
    RUN_TEST(test_config_validate);
    RUN_TEST(test_collector_split);
    RUN_TEST(test_collector_send_after_refused);
    RUN_TEST(test_collector_max_message);
    RUN_TEST(test_control_lock);
    RUN_TEST(test_vlan_parse);
    RUN_TEST(test_ipfix_message_layout);
    RUN_TEST(test_ipfix_icmp_and_ipv6);
    RUN_TEST(test_ipfix_vlan_ingress);
    RUN_TEST(test_ipfix_split_and_sequence);
    RUN_TEST(test_ipfix_template_refresh);
    RUN_TEST(test_ipfix_max_len);
    RUN_TEST(test_cache_merge);
    RUN_TEST(test_cache_expire_reasons);
    RUN_TEST(test_cache_growth_and_reuse);
    RUN_TEST(test_cache_limit);
    RUN_TEST(test_cache_matches_brute_force);
    RUN_TEST(test_cache_expiry_delay_bounded);
    return test_summary();
}
