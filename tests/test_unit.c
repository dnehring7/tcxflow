// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file test_unit.c
 * @brief Unit tests: configuration, collectors, control socket, interfaces, IPFIX encoding, flow cache
 *
 * Needs no privileges and no BPF: `make test`.
 */

#include <arpa/inet.h>
#include <errno.h> // IWYU pragma: keep (ENOSPC)
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cache.h"
#include "collector.h"
#include "config.h"
#include "control.h"
#include "flow.h"
#include "iface.h"
#include "ipfix.h"
#include "test.h"
#include "util.h"
#include "vlan.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                            */

static int parse_config(struct config *cfg, const char *text, char *err, size_t errlen) {
    char *copy = strdup(text);
    FILE *fp = copy ? fmemopen(copy, strlen(copy), "r") : nullptr;
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
static constexpr int MAX_MSGS = 64;
static constexpr uint64_t TPL_REFRESH_NS = 60 * NSEC_PER_SEC; // template-refresh default
static uint8_t msgs[MAX_MSGS][IPFIX_MSG_MAX];
static size_t msg_len[MAX_MSGS];
static int n_msgs;

static void capture([[maybe_unused]] void *ctx, const uint8_t *msg, size_t len) {
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
    CHECK_EQ(cfg.export_interval, 10);
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
                               "export-interval 1\n"
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
    CHECK_EQ(cfg.export_interval, 1);
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
        {"export-interval 61\n", "export-interval must be a number from 0 to 60"},
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

/* The command line offers config_options: each must be implemented, and nothing else accepted. */
static void test_config_options(void) {
    struct config cfg;
    char err[256];

    for (int i = 0; i < CONFIG_N_OPTIONS; i++) {
        err[0] = '\0';
        config_init(&cfg);
        (void)config_set(&cfg, config_options[i], "1", err, sizeof(err));
        if (strstr(err, "unknown") || strstr(err, "not implemented")) {
            test_errors++;
            (void)fprintf(stderr, "    option %s: %s\n", config_options[i], err);
        }
    }
    CHECK_EQ(config_set(&cfg, "config", "x", err, sizeof(err)), (unsigned long long)-1);
    CHECK_STR(err, "unknown option \"config\"");
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

/* collector_templates_fn: one template message, "T", for the tests. */
static size_t test_templates([[maybe_unused]] void *ctx, unsigned index, uint8_t *buf, size_t len) {
    if (index > 0 || len < 1)
        return 0;
    buf[0] = 'T';
    return 1;
}

/* The next datagram on rx, "" if none arrives within a second. */
static void recv_str(int rx, char *buf, size_t len) {
    struct pollfd pfd = {.fd = rx, .events = POLLIN};
    ssize_t n = 0;

    buf[0] = '\0';
    if (poll(&pfd, 1, 1000) != 1)
        return;
    n = recv(rx, buf, len - 1, MSG_DONTWAIT);
    if (n > 0)
        buf[n] = '\0';
}

/* A collector that refused a message was down: it gets the templates, then the message again. */
static void test_collector_export_after_refused(void) {
    struct collector c = {.name = "test", .fd = -1};
    uint16_t port = 0;
    char spec[32];
    char err[256];
    char buf[16];
    int rx = udp_listen(&port);

    CHECK(rx >= 0);
    if (rx < 0)
        return;
    (void)close(rx); // nothing listens on the port now
    (void)snprintf(spec, sizeof(spec), "127.0.0.1:%u", port);
    c.fd = collector_open(spec, err, sizeof(err));
    CHECK(c.fd >= 0);
    if (c.fd < 0)
        return;
    CHECK_EQ(collector_export(&c, "one", 3, test_templates, nullptr), 0); // the kernel answers port unreachable
    (void)usleep(20000);                                                  // the error is now pending on fd
    rx = udp_listen(&port);                                               // the collector is back
    CHECK(rx >= 0);
    if (rx >= 0) {
        CHECK_EQ(collector_export(&c, "two", 3, test_templates, nullptr), 0);
        CHECK(!c.refused); // sent after the refusal: reachable again
        recv_str(rx, buf, sizeof(buf));
        CHECK_STR(buf, "T"); // the templates first
        recv_str(rx, buf, sizeof(buf));
        CHECK_STR(buf, "two");
        CHECK_EQ(collector_export(&c, "three", 5, test_templates, nullptr), 0);
        recv_str(rx, buf, sizeof(buf));
        CHECK_STR(buf, "three"); // no templates any more
        (void)close(rx);
    }
    CHECK_EQ(c.sent, 3);
    CHECK_EQ(c.errors, 0);
    (void)close(c.fd);
}

/*
 * A message that could not be sent may have carried the templates: they precede the next one,
 * to this collector only. Another one that keeps refusing does not change what a healthy one gets.
 */
static void test_collector_templates_after_failure(void) {
    struct collector bad = {.name = "bad", .fd = -1};
    struct collector good = {.name = "good", .fd = -1};
    struct collector gone = {.name = "gone", .fd = -1};
    uint16_t port = 0;
    uint16_t dead = 0;
    char spec[32];
    char err[256];
    char buf[16];
    const int rx = udp_listen(&port);
    int tmp = udp_listen(&dead);

    CHECK(rx >= 0 && tmp >= 0);
    if (rx < 0 || tmp < 0)
        return;
    (void)close(tmp);
    (void)snprintf(spec, sizeof(spec), "127.0.0.1:%u", port);
    good.fd = collector_open(spec, err, sizeof(err));
    (void)snprintf(spec, sizeof(spec), "127.0.0.1:%u", dead);
    gone.fd = collector_open(spec, err, sizeof(err));
    CHECK(good.fd >= 0 && gone.fd >= 0);
    CHECK_EQ(collector_export(&bad, "x", 1, test_templates, nullptr), -1); // fd -1: not sent
    CHECK_EQ(errno, EBADF);
    CHECK(bad.templates_due);
    CHECK_EQ(bad.errors, 1);
    bad.fd = good.fd; // working again
    CHECK_EQ(collector_export(&bad, "y", 1, test_templates, nullptr), 0);
    CHECK(!bad.templates_due);
    recv_str(rx, buf, sizeof(buf));
    CHECK_STR(buf, "T");
    recv_str(rx, buf, sizeof(buf));
    CHECK_STR(buf, "y");
    for (int i = 0; i < 5; i++) { // gone refuses every message, good gets just the messages
        (void)collector_export(&gone, "m", 1, test_templates, nullptr);
        (void)usleep(5000);
        CHECK_EQ(collector_export(&good, "m", 1, test_templates, nullptr), 0);
        recv_str(rx, buf, sizeof(buf));
        CHECK_STR(buf, "m");
    }
    CHECK(gone.refused);
    (void)close(gone.fd);
    (void)close(good.fd);
    (void)close(rx);
}

/* A full send buffer is waited for until the deadline. Unix datagrams: UDP loopback never fills. */
static void test_collector_waits_for_full_buffer(void) {
    struct collector c = {.name = "slow", .fd = -1};
    int sv[2] = {-1, -1};
    uint64_t start = 0;
    pid_t pid = -1;
    int status = 0;

    CHECK_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv), 0);
    if (sv[0] < 0)
        return;
    c.fd = sv[0];
    while (send(sv[0], "fill", 4, MSG_DONTWAIT) == 4)
        ;
    CHECK_EQ(errno, EAGAIN);
    CHECK_EQ(collector_export(&c, "now", 3, test_templates, nullptr), -1); // no deadline: no waiting
    CHECK_EQ(errno, EAGAIN);
    pid = fork();
    if (pid == 0) { // the collector catches up after 50 ms
        struct pollfd pfd = {.fd = sv[1], .events = POLLIN};
        char buf[16];

        (void)usleep(50000);
        while (poll(&pfd, 1, 500) == 1)
            (void)recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT);
        _exit(0);
    }
    start = clock_ns(CLOCK_MONOTONIC);
    c.wait_until_ns = start + (2 * NSEC_PER_SEC);
    CHECK_EQ(collector_export(&c, "later", 5, test_templates, nullptr), 0);
    CHECK(clock_ns(CLOCK_MONOTONIC) - start >= 40 * NSEC_PER_MSEC); // it waited for room
    CHECK(!c.templates_due);                                        // and sent the templates
    CHECK_EQ(c.sent, 1);
    CHECK_EQ(c.errors, 1);
    (void)waitpid(pid, &status, 0);
    (void)close(sv[0]);
    (void)close(sv[1]);
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
    FILE *fp = nullptr;

    CHECK(mkdtemp(dir) != nullptr);
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
    CHECK(fp != nullptr);
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

/* A Unix socket listening at path, as another program would have it: no lock file. */
static int unix_listen(const char *path) {
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    (void)snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (fd < 0 || bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) || listen(fd, 1)) {
        if (fd >= 0)
            (void)close(fd);
        return -1;
    }
    return fd;
}

/*
 * The socket of another program at the configured path is in use, not stale: tcxflow must not
 * take it over. And whatever answers there without a reply is no tcxflow.
 */
static void test_control_foreign_socket(void) {
    char dir[] = "/tmp/tcxflow-test.XXXXXX";
    char sock[64];
    char lock[72];
    int lock_fd = -1;
    int other = -1;
    int peer = -1;
    FILE *out = tmpfile();

    CHECK(mkdtemp(dir) != nullptr);
    CHECK(out != nullptr);
    (void)snprintf(sock, sizeof(sock), "%s/sock", dir);
    (void)snprintf(lock, sizeof(lock), "%s.lock", sock);
    other = unix_listen(sock);
    CHECK(other >= 0);
    if (other < 0) {
        if (out)
            (void)fclose(out);
        return;
    }
    CHECK_EQ(control_listen(sock, &lock_fd), -1);
    CHECK_EQ(errno, EADDRINUSE);
    peer = accept(other, nullptr, nullptr); // the connection tcxflow probed with
    if (peer >= 0)
        (void)close(peer);
    // The other program's socket still works: it accepts the request and closes without a reply.
    if (fork() == 0) {
        _exit(control_request(sock, "stats", out) == -1 && errno == ENODATA ? 0 : 1);
    }
    peer = accept(other, nullptr, nullptr);
    CHECK(peer >= 0);
    if (peer >= 0) {
        char cmd[16];

        CHECK(read(peer, cmd, sizeof(cmd)) > 0); // reads the request, replies nothing
        (void)close(peer);
    }
    {
        int status = 0;

        (void)wait(&status);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0); // empty reply: ENODATA
    }
    (void)close(other);
    if (out)
        (void)fclose(out);
    (void)unlink(sock);
    (void)unlink(lock);
    CHECK_EQ(rmdir(dir), 0);
}

/* A client connected to sa, or -1. */
static int unix_connect(const struct sockaddr_un *sa) {
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd >= 0 && connect(fd, (const struct sockaddr *)sa, sizeof(*sa))) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* The command arrives; a silent client costs the daemon 200 ms at most; a reply never blocks. */
static void test_control_accept(void) {
    char dir[] = "/tmp/tcxflow-test.XXXXXX";
    char sock[64];
    char lock[72];
    char cmd[64];
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    uint64_t start = 0;
    int lock_fd = -1;
    int lfd = -1;
    int cl = -1;
    int fd = -1;

    CHECK(mkdtemp(dir) != nullptr);
    (void)snprintf(sock, sizeof(sock), "%s/sock", dir);
    (void)snprintf(lock, sizeof(lock), "%s.lock", sock);
    (void)snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", sock);
    lfd = control_listen(sock, &lock_fd);
    CHECK(lfd >= 0);
    if (lfd < 0)
        return;
    cl = unix_connect(&sa);
    CHECK(cl >= 0 && write(cl, "stats\n", 6) == 6);
    fd = control_accept(lfd, cmd, sizeof(cmd));
    CHECK(fd >= 0);
    CHECK_STR(cmd, "stats");
    if (fd >= 0) { // the client does not read: the reply is cut off
        char buf[4096] = {};

        CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK);
        while (write(fd, buf, sizeof(buf)) > 0)
            ;
        CHECK_EQ(errno, EAGAIN);
        (void)close(fd);
    }
    if (cl >= 0)
        (void)close(cl);
    cl = unix_connect(&sa);
    CHECK(cl >= 0);
    start = clock_ns(CLOCK_MONOTONIC);
    fd = control_accept(lfd, cmd, sizeof(cmd));
    CHECK(fd >= 0);
    CHECK_STR(cmd, "");
    CHECK(clock_ns(CLOCK_MONOTONIC) - start < NSEC_PER_SEC);
    if (fd >= 0)
        (void)close(fd);
    if (cl >= 0)
        (void)close(cl);
    (void)close(lfd);
    (void)close(lock_fd);
    (void)unlink(sock);
    (void)unlink(lock);
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
        FILE *fp = copy ? fmemopen(copy, strlen(copy), "r") : nullptr;
        char lower[16] = "";

        CHECK(fp != nullptr);
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
    const uint8_t *m = nullptr;
    const uint8_t *d = nullptr;
    size_t tpl = 0;
    size_t data = 0;

    n_msgs = 0;
    ipfix_init(&x, 42, TPL_REFRESH_NS, 0, capture, nullptr);
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
    const uint8_t *d = nullptr;
    size_t data = 0;

    key.dir = FLOW_DIR_IN;
    n_msgs = 0;
    ipfix_init(&x, 1, TPL_REFRESH_NS, 0, capture, nullptr);
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
    const uint8_t *d = nullptr;
    size_t off = 0;

    n_msgs = 0;
    ipfix_init(&x, 0, TPL_REFRESH_NS, 0, capture, nullptr);
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

    ipfix_init(&x, 1, TPL_REFRESH_NS, 0, capture, nullptr);
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
    ipfix_set_max_len(&x, 0); // unknown path MTU: 512-byte packets
    CHECK_EQ(x.max_len, IPFIX_MSG_UNKNOWN);
    ipfix_set_max_len(&x, 9000);
    CHECK_EQ(x.max_len, IPFIX_MSG_MAX);
}

static void test_ipfix_split_and_sequence(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1, .bytes = 100};
    uint32_t records = 0;

    n_msgs = 0;
    ipfix_init(&x, 0, TPL_REFRESH_NS, 0, capture, nullptr);
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
    ipfix_init(&x, 0, TPL_REFRESH_NS, 0, capture, nullptr);
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
}

/*
 * The templates keep their own deadline, shorter than export-interval here: on their own while no
 * flow ends, after the data waiting, and with the data they started a message with.
 */
static void test_ipfix_refresh_idle(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1, .bytes = 100};

    n_msgs = 0;
    ipfix_init(&x, 7, 30 * NSEC_PER_SEC, 60 * NSEC_PER_SEC, capture, nullptr); // template-refresh 30
    ipfix_add(&x, &rec, 10 * NSEC_PER_SEC, 1);
    ipfix_flush(&x, 1);
    CHECK_EQ(n_msgs, 1);
    ipfix_tick(&x, 39 * NSEC_PER_SEC, 2); // not due yet
    CHECK_EQ(n_msgs, 1);
    ipfix_tick(&x, 40 * NSEC_PER_SEC, 3);
    CHECK_EQ(n_msgs, 2);
    CHECK_EQ(get16(msgs[1] + 2), IPFIX_HDR_LEN + 4 + (2 * (4 + (20 * 4)))); // templates only
    CHECK_EQ(get32(msgs[1] + 8), 1);      // the sequence number counts the one data record
    ipfix_tick(&x, 41 * NSEC_PER_SEC, 4); // just sent
    CHECK_EQ(n_msgs, 2);
    ipfix_add(&x, &rec, 50 * NSEC_PER_SEC, 5);
    ipfix_tick(&x, 60 * NSEC_PER_SEC, 6); // the data waits for export-interval ...
    CHECK_EQ(n_msgs, 2);
    ipfix_tick(&x, 70 * NSEC_PER_SEC, 7); // ... the templates do not: the data goes first
    CHECK_EQ(n_msgs, 4);
    CHECK(find_set(2, IPFIX_TPL_V4) != 0 && find_set(2, IPFIX_SET_TEMPLATE) == 0);
    CHECK(find_set(3, IPFIX_SET_TEMPLATE) != 0 && find_set(3, IPFIX_TPL_V4) == 0);
    CHECK_EQ(get32(msgs[3] + 8), 2);
    ipfix_add(&x, &rec, 101 * NSEC_PER_SEC, 8); // due again: one message with templates and data
    ipfix_tick(&x, 101 * NSEC_PER_SEC, 8);
    CHECK_EQ(n_msgs, 5);
    CHECK(find_set(4, IPFIX_SET_TEMPLATE) != 0 && find_set(4, IPFIX_TPL_V4) != 0);
    CHECK_EQ(get32(msgs[4] + 8), 2);
    CHECK_EQ(x.n_records, 3);
}

/* A partly filled message is sent once it is export-interval old, also when ticks were skipped. */
static void test_ipfix_tick_wait(void) {
    struct ipfix_exporter x;
    const struct flow_key key = make_key(4, 17, 1, 2);
    const struct ipfix_record rec = {.key = &key, .packets = 1};

    n_msgs = 0;
    ipfix_init(&x, 1, 86400 * NSEC_PER_SEC, 10 * NSEC_PER_SEC, capture, nullptr);
    ipfix_tick(&x, 0, 0); // the initial templates
    CHECK_EQ(n_msgs, 1);
    ipfix_add(&x, &rec, 1'200'000'000, 1); // in a tick that ran 200 ms late
    for (uint64_t t = 1; t <= 10; t++)
        ipfix_tick(&x, t * NSEC_PER_SEC, (uint32_t)t);
    CHECK_EQ(n_msgs, 1);
    ipfix_tick(&x, 11 * NSEC_PER_SEC, 11); // the 10th tick after it
    CHECK_EQ(n_msgs, 2);
    ipfix_add(&x, &rec, 12 * NSEC_PER_SEC, 12);
    ipfix_tick(&x, 100 * NSEC_PER_SEC, 100); // ticks 13 to 99 skipped: the next one sends it
    CHECK_EQ(n_msgs, 3);
    CHECK_EQ(x.n_records, 2);
}

/*
 * A path MTU too small for the templates and a record: the templates go in messages of their
 * own, one per template below 188 bytes, and every message fits.
 */
static void test_ipfix_small_pmtu(void) {
    struct ipfix_exporter x;
    const struct flow_key k4 = make_key(4, 17, 1, 2);
    const struct flow_key k6 = make_key(6, 17, 1, 2);
    const struct ipfix_record r4 = {.key = &k4, .packets = 1};
    const struct ipfix_record r6 = {.key = &k6, .packets = 1};
    const size_t limits[] = {228, IPFIX_MSG_MIN};

    for (size_t l = 0; l < sizeof(limits) / sizeof(limits[0]); l++) {
        const int tpl_msgs = limits[l] >= IPFIX_HDR_LEN + 4 + (2 * (4 + (20 * 4))) ? 1 : 2;

        n_msgs = 0;
        ipfix_init(&x, 1, TPL_REFRESH_NS, 0, capture, nullptr);
        ipfix_set_max_len(&x, limits[l]);
        ipfix_add(&x, &r4, 0, 0);
        ipfix_add(&x, &r6, 0, 0);
        ipfix_flush(&x, 0);
        CHECK(n_msgs >= tpl_msgs + 1);
        for (int i = 0; i < n_msgs && i < MAX_MSGS; i++) {
            CHECK(msg_len[i] <= limits[l]);
            CHECK_EQ(get16(msgs[i] + 2), msg_len[i]);
            CHECK_EQ(find_set(i, IPFIX_SET_TEMPLATE) != 0, i < tpl_msgs); // templates first
        }
        CHECK_EQ(get16(msgs[0] + IPFIX_HDR_LEN + 4), IPFIX_TPL_V4);
        if (tpl_msgs == 2)
            CHECK_EQ(get16(msgs[1] + IPFIX_HDR_LEN + 4), IPFIX_TPL_V6);
        CHECK_EQ(get32(msgs[0] + 8), 0); // before any data record
        CHECK_EQ(x.n_records, 2);
    }
}

/* What a collector gets before the next message when it needs the templates. */
static void test_ipfix_template_message(void) {
    struct ipfix_exporter x;
    uint8_t buf[512];

    ipfix_init(&x, 9, TPL_REFRESH_NS, 0, capture, nullptr);
    CHECK_EQ(ipfix_template_message(&x, 0, 5, buf, sizeof(buf)), IPFIX_HDR_LEN + 4 + (2 * 84));
    CHECK_EQ(get32(buf + 4), 5);  // export time
    CHECK_EQ(get32(buf + 12), 9); // observation domain
    CHECK_EQ(ipfix_template_message(&x, 1, 5, buf, sizeof(buf)), 0);
    CHECK_EQ(ipfix_template_message(&x, 0, 5, buf, 100), 0); // does not fit the buffer
    ipfix_set_max_len(&x, IPFIX_MSG_MIN);
    CHECK_EQ(ipfix_template_message(&x, 0, 5, buf, sizeof(buf)), IPFIX_HDR_LEN + 4 + 84);
    CHECK_EQ(get16(buf + IPFIX_HDR_LEN + 4), IPFIX_TPL_V4);
    CHECK_EQ(ipfix_template_message(&x, 1, 5, buf, sizeof(buf)), IPFIX_HDR_LEN + 4 + 84);
    CHECK_EQ(get16(buf + IPFIX_HDR_LEN + 4), IPFIX_TPL_V6);
    CHECK_EQ(ipfix_template_message(&x, 2, 5, buf, sizeof(buf)), 0);
}

/* ------------------------------------------------------------------ */
/* Flow cache                                                         */

static constexpr int MAX_EXPORTED = 8;
static struct {
    struct flow_entry entry;
    uint8_t reason;
} exported[MAX_EXPORTED];
static int n_exported;

static void collect([[maybe_unused]] void *ctx, const struct flow_entry *entry, uint8_t reason) {
    if (n_exported < MAX_EXPORTED) {
        exported[n_exported].entry = *entry;
        exported[n_exported].reason = reason;
    }
    n_exported++;
}

static void count_only(void *ctx, [[maybe_unused]] const struct flow_entry *entry, [[maybe_unused]] uint8_t reason) {
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

    CHECK_EQ(cache_init(&c, 16, UINT32_MAX, &policy, collect, nullptr), 0);
    CHECK_EQ(cache_add(&c, &key, &first), 0);
    CHECK_EQ(cache_add(&c, &key, &second), 0);
    CHECK_EQ(c.count, 1);
    n_exported = 0;
    CHECK_EQ(cache_expire(&c, 2000, true), 1);
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
    uint8_t reasons[5] = {};

    CHECK_EQ(cache_init(&c, 16, UINT32_MAX, &policy, collect, nullptr), 0);
    CHECK_EQ(cache_add(&c, &idle, &v_idle), 0);
    CHECK_EQ(cache_add(&c, &active, &v_active), 0);
    CHECK_EQ(cache_add(&c, &fin, &v_fin), 0);
    CHECK_EQ(cache_add(&c, &fresh, &v_fresh), 0);

    n_exported = 0;
    CHECK_EQ(cache_expire(&c, now, false), 3);
    for (int i = 0; i < n_exported && i < MAX_EXPORTED; i++)
        reasons[ntohs(exported[i].entry.key.sport)] = exported[i].reason;
    CHECK_EQ(reasons[1], IPFIX_END_IDLE);
    CHECK_EQ(reasons[2], IPFIX_END_ACTIVE);
    CHECK_EQ(reasons[3], IPFIX_END_DETECTED);
    CHECK_EQ(reasons[4], 0);
    CHECK_EQ(c.count, 1); // the fresh flow stays

    n_exported = 0;
    CHECK_EQ(cache_expire(&c, now, true), 1);
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

    CHECK_EQ(cache_init(&c, 16, UINT32_MAX, &policy, count_only, &count), 0);
    for (uint32_t i = 0; i < n; i++) {
        struct flow_key key = make_key(4, 17, (uint16_t)(i & 0xffff), (uint16_t)(i >> 16));

        CHECK_EQ(cache_add(&c, &key, &val), 0);
    }
    CHECK_EQ(c.count, n);
    CHECK(c.n_buckets >= n); // buckets doubled along the way
    used = c.used;
    CHECK_EQ(cache_expire(&c, 2, true), n);
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

    CHECK_EQ(cache_init(&c, 16, 2, &policy, collect, nullptr), 0);
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
static constexpr int MODEL_KEYS = 512;
static struct {
    uint64_t first_ns;
    uint64_t last_ns;
    uint64_t packets;
    uint32_t tcp_flags;
    bool cached;
} model[MODEL_KEYS];
static bool model_exported[MODEL_KEYS];

static void model_collect([[maybe_unused]] void *ctx, const struct flow_entry *entry, [[maybe_unused]] uint8_t reason) {
    const uint16_t k = ntohs(entry->key.sport);

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
/* The same rules as the cache: whether model flow k has ended at now. */
static bool model_ended(int k, uint64_t now) {
    return model[k].cached &&
           (now - model[k].last_ns >= policy.inactive_ns || now - model[k].first_ns >= policy.active_ns ||
            ((model[k].tcp_flags & 0x05U) && now - model[k].last_ns >= policy.fin_ns));
}

static void test_cache_matches_brute_force(void) {
    struct flow_cache c;
    uint64_t rnd = 0x2545f4914f6cdd1dULL;

    memset(model, 0, sizeof(model));
    CHECK_EQ(cache_init(&c, 16, UINT32_MAX, &policy, model_collect, nullptr), 0);
    for (uint64_t tick = 1; tick <= 300; tick++) {
        const uint64_t now = tick * NSEC_PER_SEC;

        for (int u = 0; u < 40; u++) { // one interval: every update carries this tick's time
            uint16_t k = 0;
            bool split = false;
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
            split = model_ended(k, now); // the record ended before this packet: a new one starts
            model_exported[k] = false;
            CHECK_EQ(cache_add(&c, &key, &v), 0);
            CHECK_EQ(model_exported[k], split);
            if (split)
                model[k].cached = false;
            if (!model[k].cached)
                model[k] = (__typeof__(model[0])){.cached = true, .first_ns = now};
            model[k].last_ns = now;
            model[k].tcp_flags |= v.tcp_flags;
            model[k].packets++;
        }
        memset(model_exported, 0, sizeof(model_exported));
        (void)cache_expire(&c, now, false);
        for (int k = 0; k < MODEL_KEYS; k++) {
            const bool ended = model_ended(k, now);

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

    CHECK_EQ(cache_init(&c, 16, 16, &p, count_only, &count), 0);
    CHECK_EQ(cache_add(&c, &young, &v_young), 0); // same interval, drained first
    CHECK_EQ(cache_add(&c, &old, &v_old), 0);
    (void)cache_expire(&c, 1000000000, false); // old is due, may wait
    CHECK(count <= 1);
    (void)cache_expire(&c, 1400000000, false); // young is due: both gone
    CHECK_EQ(count, 2);
    CHECK_EQ(c.count, 0);
    cache_destroy(&c);
}

/* Packets after a gap longer than the inactive timeout start a new record, expiry run or not. */
static void test_cache_idle_gap(void) {
    struct flow_cache c;
    const struct flow_key k = make_key(4, 17, 1, 2);
    const struct flow_val a = {.first_ns = 100000000, .last_ns = 100000000, .packets = 1};
    const struct flow_val b = {.first_ns = 15900000000ULL, .last_ns = 15900000000ULL, .packets = 1};
    const struct flow_val c2 = {.first_ns = 16100000000ULL, .last_ns = 16100000000ULL, .packets = 1};

    CHECK_EQ(cache_init(&c, 16, 16, &policy, collect, nullptr), 0);
    n_exported = 0;
    CHECK_EQ(cache_add(&c, &k, &a), 0);
    (void)cache_expire(&c, 15 * NSEC_PER_SEC, false); // 14.9 s: not yet
    CHECK_EQ(n_exported, 0);
    CHECK_EQ(cache_add(&c, &k, &b), 0); // 15.8 s after the last packet
    CHECK_EQ(n_exported, 1);
    CHECK_EQ(exported[0].reason, IPFIX_END_IDLE);
    CHECK_EQ(exported[0].entry.last_ns, a.last_ns);
    CHECK_EQ(cache_add(&c, &k, &c2), 0); // 0.2 s later: the same new record
    (void)cache_expire(&c, 17 * NSEC_PER_SEC, true);
    CHECK_EQ(n_exported, 2);
    CHECK_EQ(exported[1].entry.first_ns, b.first_ns);
    CHECK_EQ(exported[1].entry.packets, 2);
    cache_destroy(&c);
}

/* A new connection on the same ports, more than 2 s after FIN: a new record. */
static void test_cache_port_reuse(void) {
    struct flow_cache c;
    const struct flow_key k = make_key(4, FLOW_PROTO_TCP, 1000, 80);
    const struct flow_val fin = {.first_ns = NSEC_PER_SEC, .last_ns = NSEC_PER_SEC, .packets = 3, .tcp_flags = 0x11};
    const struct flow_val syn = {.first_ns = 3500000000ULL, .last_ns = 3500000000ULL, .packets = 1, .tcp_flags = 0x02};

    CHECK_EQ(cache_init(&c, 16, 16, &policy, collect, nullptr), 0);
    n_exported = 0;
    CHECK_EQ(cache_add(&c, &k, &fin), 0);
    CHECK_EQ(cache_add(&c, &k, &syn), 0);
    CHECK_EQ(n_exported, 1);
    CHECK_EQ(exported[0].reason, IPFIX_END_DETECTED);
    CHECK_EQ(exported[0].entry.packets, 3);
    (void)cache_expire(&c, 4 * NSEC_PER_SEC, true);
    CHECK_EQ(n_exported, 2);
    CHECK_EQ(exported[1].entry.tcp_flags, 0x02); // the new connection only
    cache_destroy(&c);
}

/* stop() drains both maps; the newer interval may come first: the record still starts at the older. */
static void test_cache_older_interval_later(void) {
    struct flow_cache c;
    const struct flow_key k = make_key(4, 17, 1, 2);
    const struct flow_val newer = {.first_ns = 2 * NSEC_PER_SEC, .last_ns = 3 * NSEC_PER_SEC, .packets = 1, .ecn = 1};
    const struct flow_val older = {.first_ns = NSEC_PER_SEC, .last_ns = 1500000000ULL, .packets = 2, .ecn = 2};

    CHECK_EQ(cache_init(&c, 16, 16, &policy, collect, nullptr), 0);
    n_exported = 0;
    CHECK_EQ(cache_add(&c, &k, &newer), 0);
    CHECK_EQ(cache_add(&c, &k, &older), 0);
    (void)cache_expire(&c, 4 * NSEC_PER_SEC, true);
    CHECK_EQ(n_exported, 1);
    CHECK_EQ(exported[0].entry.first_ns, older.first_ns);
    CHECK_EQ(exported[0].entry.last_ns, newer.last_ns);
    CHECK_EQ(exported[0].entry.ecn, 2); // the first packet's
    CHECK_EQ(exported[0].entry.packets, 3);
    cache_destroy(&c);
}

/*
 * A map that collected for 10 s (tcxflow stalled) comes in hash order: its batch is sorted, so a
 * flow that ended does not wait behind a younger one.
 */
static void test_cache_delayed_interval(void) {
    struct flow_cache c;
    const struct flow_key young = make_key(4, 17, 1, 2);
    const struct flow_key old = make_key(4, 17, 3, 4);
    const struct flow_key mid = make_key(4, FLOW_PROTO_TCP, 5, 6);
    const struct flow_val a = {.first_ns = 9900000000ULL, .last_ns = 9900000000ULL};
    const struct flow_val b = {.first_ns = 100000000, .last_ns = 100000000};
    const struct flow_val m = {.first_ns = 5 * NSEC_PER_SEC, .last_ns = 5 * NSEC_PER_SEC, .tcp_flags = 0x01};
    const struct expire_policy p = {
        .inactive_ns = 2 * NSEC_PER_SEC, .active_ns = 100 * NSEC_PER_SEC, .fin_ns = NSEC_PER_SEC};
    uint32_t count = 0;

    CHECK_EQ(cache_init(&c, 16, 16, &p, count_only, &count), 0);
    cache_batch_begin(&c);
    CHECK_EQ(cache_add(&c, &young, &a), 0);
    CHECK_EQ(cache_add(&c, &mid, &m), 0);
    CHECK_EQ(cache_add(&c, &old, &b), 0);
    cache_batch_end(&c);
    (void)cache_expire(&c, 10 * NSEC_PER_SEC, false);
    CHECK_EQ(count, 2); // old (idle 9.9 s) and mid (FIN, 5 s), not young
    CHECK_EQ(c.count, 1);
    CHECK_EQ(list_length(&c, &c.idle, false), 1);
    CHECK_EQ(list_length(&c, &c.age, true), 1);
    cache_destroy(&c);
}

/* The memory the cache holds, used or not. */
static void test_cache_memory(void) {
    struct flow_cache c;
    const struct flow_val val = {.first_ns = 1, .last_ns = 1, .packets = 1};
    const struct flow_key k = make_key(4, 17, 1, 1);

    CHECK_EQ(cache_init(&c, 16, 100000, &policy, collect, nullptr), 0);
    CHECK_EQ(cache_memory(&c), 16 * sizeof(uint32_t));
    CHECK_EQ(cache_add(&c, &k, &val), 0);
    CHECK(cache_memory(&c) >= (16 * sizeof(uint32_t)) + sizeof(struct flow_entry));
    cache_destroy(&c);
}

/* A cache whose initialisation failed is empty and usable: stop() still drains into it. */
static void test_cache_init_failed(void) {
    struct flow_cache c;
    const struct flow_val val = {.first_ns = 1, .last_ns = 1, .packets = 1};
    const struct flow_key k = make_key(4, 17, 1, 1);

    for (int i = 0; i < 2; i++) {
        CHECK_EQ(cache_init(&c, i ? UINT32_MAX : 0, 100000, &policy, collect, nullptr), (unsigned long long)-EINVAL);
        CHECK_EQ(cache_add(&c, &k, &val), (unsigned long long)-ENOMEM);
        CHECK_EQ(cache_expire(&c, 1, true), 0);
        CHECK_EQ(cache_memory(&c), 0);
        cache_destroy(&c);
    }
}

/* ------------------------------------------------------------------ */
/* Interfaces                                                         */

/* Colliding slots are probed past, an ifindex is unique, the table is bounded. */
static void test_iface_table(void) {
    static struct iface_table t;
    const struct iface_config cfg = {.name = "eth0", .dir = {true, false}};
    struct flow_key k = {.dir = FLOW_DIR_IN, .in_if = 1};
    struct iface_state *a = nullptr;
    struct iface_state *b = nullptr;

    CHECK_EQ(iface_add(&t, &cfg, 1, &a), 0);
    CHECK_EQ(iface_add(&t, &cfg, 1 + IFACE_MAP_SIZE, &b), 0); // the same slot
    CHECK(iface_of_flow(&t, &k) == a);
    k.in_if = 1 + IFACE_MAP_SIZE;
    CHECK(iface_of_flow(&t, &k) == b);
    k = (struct flow_key){.dir = FLOW_DIR_OUT, .in_if = 1, .out_if = 2};
    CHECK(iface_of_flow(&t, &k) == nullptr); // egress: the outgoing interface counts
    CHECK_EQ(iface_add(&t, &cfg, 1, &b), (unsigned long long)-EEXIST);
    CHECK(b == a);
    for (unsigned i = 2; t.n < CONFIG_MAX_IFACES; i++)
        CHECK_EQ(iface_add(&t, &cfg, 1000 + i, &b), 0);
    CHECK_EQ(iface_add(&t, &cfg, 5000, &b), (unsigned long long)-ENOSPC);
    CHECK_STR(iface_dir_name(&cfg), "in");
}

/* VLAN interface IDs first, then the tags in the packet; two levels at most. */
static void test_iface_vlans(void) {
    struct iface_state s = {.vlan = 100};
    const struct flow_key k = {.vlan = 200, .vlan_inner = 300};
    uint16_t outer = 0;
    uint16_t inner = 0;
    char buf[16];

    iface_vlans(nullptr, &k, &outer, &inner); // not a metered interface: the tags only
    CHECK(outer == 200 && inner == 300);
    iface_vlans(&s, &k, &outer, &inner);
    CHECK(outer == 100 && inner == 200);
    iface_format_vlan(&s, buf, sizeof(buf));
    CHECK_STR(buf, "100");
    s.vlan_inner = 101; // QinQ interface
    iface_vlans(&s, &k, &outer, &inner);
    CHECK(outer == 100 && inner == 101);
    iface_format_vlan(&s, buf, sizeof(buf));
    CHECK_STR(buf, "100.101");
    s = (struct iface_state){};
    iface_vlans(&s, &(struct flow_key){}, &outer, &inner);
    CHECK(outer == 0 && inner == 0);
    iface_format_vlan(&s, buf, sizeof(buf));
    CHECK_STR(buf, "-");
}

int main(void) {
    RUN_TEST(test_config_defaults);
    RUN_TEST(test_config_file);
    RUN_TEST(test_config_errors);
    RUN_TEST(test_config_options);
    RUN_TEST(test_config_long_line);
    RUN_TEST(test_config_limits);
    RUN_TEST(test_config_validate);
    RUN_TEST(test_collector_split);
    RUN_TEST(test_collector_export_after_refused);
    RUN_TEST(test_collector_templates_after_failure);
    RUN_TEST(test_collector_waits_for_full_buffer);
    RUN_TEST(test_collector_max_message);
    RUN_TEST(test_control_lock);
    RUN_TEST(test_control_foreign_socket);
    RUN_TEST(test_control_accept);
    RUN_TEST(test_vlan_parse);
    RUN_TEST(test_iface_table);
    RUN_TEST(test_iface_vlans);
    RUN_TEST(test_ipfix_message_layout);
    RUN_TEST(test_ipfix_icmp_and_ipv6);
    RUN_TEST(test_ipfix_vlan_ingress);
    RUN_TEST(test_ipfix_split_and_sequence);
    RUN_TEST(test_ipfix_template_refresh);
    RUN_TEST(test_ipfix_refresh_idle);
    RUN_TEST(test_ipfix_tick_wait);
    RUN_TEST(test_ipfix_small_pmtu);
    RUN_TEST(test_ipfix_template_message);
    RUN_TEST(test_ipfix_max_len);
    RUN_TEST(test_cache_merge);
    RUN_TEST(test_cache_expire_reasons);
    RUN_TEST(test_cache_growth_and_reuse);
    RUN_TEST(test_cache_limit);
    RUN_TEST(test_cache_matches_brute_force);
    RUN_TEST(test_cache_expiry_delay_bounded);
    RUN_TEST(test_cache_idle_gap);
    RUN_TEST(test_cache_port_reuse);
    RUN_TEST(test_cache_older_interval_later);
    RUN_TEST(test_cache_delayed_interval);
    RUN_TEST(test_cache_memory);
    RUN_TEST(test_cache_init_failed);
    return test_summary();
}
