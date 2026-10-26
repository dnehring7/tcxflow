// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file daemon.c
 * @brief The exporter main loop
 *
 * Once per second: swap the BPF flow maps, drain the idle one into the flow cache,
 * export flows that have ended as IPFIX. In between, answer control requests.
 *
 * The process is single-threaded on purpose: the BPF side never waits for userspace, so
 * nothing here is time-critical, and one thread needs no locking around the cache.
 */

#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "cache.h"
#include "collector.h"
#include "config.h"
#include "control.h"
#include "flow.h"
#include "iface.h"
#include "ipfix.h"
#include "meter.h"
#include "util.h"
#include "vlan.h"

static constexpr uint64_t FIN_LINGER_NS = 2 * NSEC_PER_SEC; ///< closed TCP flows: export after 2 s without packets
static constexpr uint32_t CACHE_BUCKETS = 65536;            ///< initial hash buckets of the flow cache
static constexpr uint32_t CACHE_LIMIT_FACTOR = 8;           ///< the flow cache holds at most this many times max-flows
static constexpr int DRAIN_RETRIES = 10; ///< failed map switches or drains in a row before tcxflow exits
static constexpr uint64_t EXPORT_WAIT_NS = 200 * NSEC_PER_MSEC;    ///< tick: longest wait for full send buffers
static constexpr uint64_t FINAL_EXPORT_WAIT_NS = 5 * NSEC_PER_SEC; ///< the same at shutdown

/** Everything the exporter needs; one instance per process. */
struct daemon {
    const struct config *cfg;                     /**< configuration */
    struct meter meter;                           /**< BPF side */
    struct flow_cache cache;                      /**< flows not yet exported */
    struct ipfix_exporter ipfix;                  /**< IPFIX encoder */
    struct iface_table ifaces;                    /**< metered interfaces */
    struct collector coll[CONFIG_MAX_COLLECTORS]; /**< one per configured collector */
    int ctl_fd;                                   /**< listening control socket */
    int lock_fd;                                  /**< lock that guards the control socket */
    int undrained;                                /**< flow map left over from a failed drain, -1 = none */
    uint64_t drain_errors;                        /**< failed map switches or drains */
    int64_t mono2real;                            /**< CLOCK_REALTIME - CLOCK_MONOTONIC in nanoseconds */
    uint64_t now_ns;                              /**< CLOCK_MONOTONIC at the start of the tick */
    uint32_t now_sec;                             /**< Unix time at the start of the tick */
    uint64_t started_ns;                          /**< start time, CLOCK_MONOTONIC */
    uint64_t packets;                             /**< packets accounted, from drained flows */
    uint64_t bytes;                               /**< bytes accounted, from drained flows */
    uint64_t lost_seen;                           /**< lost packets (STAT_FULL_PKTS) already logged */
    uint64_t uncached;                            /**< flow intervals exported at once: cache full */
    uint64_t tick_ns;                             /**< duration of the last tick */
    uint64_t tick_max_ns;                         /**< longest tick so far */
    char netns_path[sizeof("/run/netns/") + CONFIG_STRING_MAX]; /**< namespace file, "" = none */
    dev_t netns_dev;                                            /**< device of the namespace entered */
    ino_t netns_ino;                                            /**< inode of the namespace entered */
    bool target_gone;  /**< an interface or the namespace disappeared: exit status 1 */
    bool meter_failed; /**< the flow maps could not be drained DRAIN_RETRIES times: exit status 1 */
};

static volatile sig_atomic_t stop_requested;

static void on_signal([[maybe_unused]] int sig) { stop_requested = 1; }

/*
 * One clock reading per tick, not per flow: all records of a tick share it, and the BPF side's
 * monotonic timestamps are converted with one offset, re-read every tick. A clock step corrects
 * the clock (NTP after boot), so the newest offset also dates the packets before it best.
 */
static void set_now(struct daemon *d) {
    d->now_ns = clock_ns(CLOCK_MONOTONIC);
    d->mono2real = (int64_t)clock_ns(CLOCK_REALTIME) - (int64_t)d->now_ns;
    d->now_sec = (uint32_t)((uint64_t)((int64_t)d->now_ns + d->mono2real) / NSEC_PER_SEC);
}

static uint64_t epoch_ms(const struct daemon *d, uint64_t mono_ns) {
    return (uint64_t)((int64_t)mono_ns + d->mono2real) / 1000000ULL;
}

/* collector_templates_fn */
static size_t template_message(void *ctx, unsigned index, uint8_t *buf, size_t len) {
    const struct daemon *d = ctx;

    return ipfix_template_message(&d->ipfix, index, d->now_sec, buf, len);
}

/* ipfix_send_fn: every message goes to every collector, so collectors are redundant copies. */
static void send_message(void *ctx, const uint8_t *msg, size_t len) {
    struct daemon *d = ctx;

    for (int i = 0; i < d->cfg->n_collectors; i++)
        (void)collector_export(&d->coll[i], msg, len, template_message, d);
}

/* cache_export_fn */
static void export_flow(void *ctx, const struct flow_entry *e, uint8_t reason) {
    struct daemon *d = ctx;
    struct ipfix_record rec = {
        .key = &e->key,
        .start_ms = epoch_ms(d, e->first_ns),
        .end_ms = epoch_ms(d, e->last_ns),
        .packets = e->packets,
        .bytes = e->bytes,
        .tos = (uint8_t)(e->key.tos | e->ecn),
        .tcp_flags = e->tcp_flags,
        .end_reason = reason,
    };

    iface_vlans(iface_of_flow(&d->ifaces, &e->key), &e->key, &rec.vlan, &rec.vlan_inner);
    ipfix_add(&d->ipfix, &rec, d->now_ns, d->now_sec);
}

/* meter_flow_fn: one drained flow goes into the cache and the counters. */
static void collect_flow(void *ctx, const struct flow_key *key, const struct flow_val *val) {
    struct daemon *d = ctx;
    struct iface_state *s = iface_of_flow(&d->ifaces, key);
    const int err = cache_add(&d->cache, key, val);

    // Cache full (or out of memory): exporting this interval at once loses no count, where
    // dropping it would.
    if (err) {
        const struct flow_entry e = {.key = *key,
                                     .first_ns = val->first_ns,
                                     .last_ns = val->last_ns,
                                     .packets = val->packets,
                                     .bytes = val->bytes,
                                     .tcp_flags = (uint16_t)val->tcp_flags,
                                     .ecn = val->ecn};

        export_flow(d, &e, IPFIX_END_LACK);
        if (d->uncached++ == 0)
            log_msg("WARNING: flow cache full (%u flows%s): new flows are exported every second", d->cache.count,
                    err == -ENOMEM ? ", out of memory" : "");
    }
    d->packets += val->packets;
    d->bytes += val->bytes;
    if (s) {
        s->packets[key->dir & 1U] += val->packets;
        s->bytes[key->dir & 1U] += val->bytes;
    }
}

/* Logs only the increase, so a long overload is one warning per second, not one per packet. */
static void warn_if_lost(struct daemon *d) {
    uint64_t st[STAT_MAX];

    if (meter_stats(&d->meter, st))
        return;
    if (st[STAT_FULL_PKTS] > d->lost_seen)
        log_msg("WARNING: flow table full, %llu packets not accounted - raise max-flows (now %u)",
                (unsigned long long)(st[STAT_FULL_PKTS] - d->lost_seen), d->cfg->max_flows);
    d->lost_seen = st[STAT_FULL_PKTS];
}

/*
 * Deleting an interface detaches its links, also if a namesake with its index comes back, and a link
 * can be detached on its own (bpftool link detach): the links tell, no name lookup is needed.
 */
static bool links_attached(const struct iface_state *s) {
    for (int dir = FLOW_DIR_IN; dir <= FLOW_DIR_OUT; dir++)
        if (s->link[dir] && meter_link_ifindex(s->link[dir]) != s->ifindex)
            return false;
    return true;
}

/*
 * A deleted (or deleted and recreated) interface or namespace is no longer metered: stop, systemd
 * restarts us. An entered namespace stays alive as long as tcxflow is in it, so its interfaces never
 * vanish when it is deleted; the namespace file tells.
 */
static void check_target(struct daemon *d) {
    struct stat st;

    if (d->netns_path[0] && !d->target_gone &&
        (stat(d->netns_path, &st) || st.st_dev != d->netns_dev || st.st_ino != d->netns_ino)) {
        log_msg("network namespace %s is gone, exiting", d->netns_path);
        d->target_gone = true;
        stop_requested = 1;
    }
    if (d->target_gone) // its interfaces went with the namespace: no message for each of them
        return;
    for (int i = 0; i < d->ifaces.n; i++) {
        struct iface_state *s = &d->ifaces.ifs[i];

        if (!s->gone && !links_attached(s)) {
            log_msg("interface %s is gone or detached, exiting", s->cfg->name);
            s->gone = true;
            d->target_gone = true;
            stop_requested = 1;
        }
    }
}

/* One absolute deadline: a slow collector delays the tick by wait_ns at most, however much it sends. */
static void set_export_deadline(struct daemon *d, uint64_t wait_ns) {
    for (int i = 0; i < d->cfg->n_collectors; i++)
        d->coll[i].wait_until_ns = d->now_ns + wait_ns;
}

/* The largest message that fits the path MTU of every collector: all get the same messages. */
static size_t export_max_len(const struct daemon *d) {
    size_t max = 0;

    for (int i = 0; i < d->cfg->n_collectors; i++) {
        const size_t m = collector_max_message(d->coll[i].fd);

        if (m && (!max || m < max))
            max = m;
    }
    return max;
}

/* Logs the first failure of a series only, so a lasting problem is not logged every second. */
static void drain_failed(struct daemon *d, const char *what, int err) {
    if (d->drain_errors++ == 0)
        log_msg("%s flow map failed: %s (retrying every second)", what, strerror(-err));
    // Meanwhile the active map fills up and new flows go uncounted: a restart with fresh maps
    // recovers from a lasting failure, waiting does not.
    if (d->drain_errors == DRAIN_RETRIES) {
        log_msg("flow maps not drained %d times in a row, exiting", DRAIN_RETRIES);
        d->meter_failed = true;
        stop_requested = 1;
    }
}

static void tick(struct daemon *d) {
    set_now(d);
    set_export_deadline(d, EXPORT_WAIT_NS);
    // Re-read every tick: path MTU discovery or a route change can lower it at any time.
    ipfix_set_max_len(&d->ipfix, export_max_len(d));
    // A map that could not be drained completely must not become active again: old and new
    // intervals would mix in it, and it could fill up. Drain it again before switching.
    if (d->undrained < 0) {
        const int idle = meter_swap(&d->meter);

        if (idle < 0)
            drain_failed(d, "switching", idle);
        else
            d->undrained = idle;
    }
    if (d->undrained >= 0) {
        int n = 0;

        cache_batch_begin(&d->cache);
        n = meter_drain(&d->meter, d->undrained, collect_flow, d);
        cache_batch_end(&d->cache);
        if (n < 0) {
            drain_failed(d, "draining", n);
        } else {
            if (d->drain_errors)
                log_msg("flow maps drained again after %llu failures", (unsigned long long)d->drain_errors);
            d->drain_errors = 0;
            d->undrained = -1;
        }
    }
    (void)cache_expire(&d->cache, d->now_ns, false);
    ipfix_tick(&d->ipfix, d->now_ns, d->now_sec);
    warn_if_lost(d);
    check_target(d);
    d->tick_ns = clock_ns(CLOCK_MONOTONIC) - d->now_ns;
    if (d->tick_ns > d->tick_max_ns)
        d->tick_max_ns = d->tick_ns;
}

static void format_duration(uint64_t sec, char *buf, size_t len) {
    if (sec >= 86400)
        (void)snprintf(buf, len, "%llud %lluh %llum", (unsigned long long)(sec / 86400),
                       (unsigned long long)(sec % 86400 / 3600), (unsigned long long)(sec % 3600 / 60));
    else
        (void)snprintf(buf, len, "%lluh %llum %llus", (unsigned long long)(sec / 3600),
                       (unsigned long long)(sec % 3600 / 60), (unsigned long long)(sec % 60));
}

static uint64_t timeval_us(struct timeval tv) { return ((uint64_t)tv.tv_sec * 1000000U) + (uint64_t)tv.tv_usec; }

static void reply_stats(const struct daemon *d, int fd) {
    const uint64_t up_ns = clock_ns(CLOCK_MONOTONIC) - d->started_ns;
    uint64_t st[STAT_MAX];
    uint64_t cpu_us = 0;
    struct rusage ru = {};
    char uptime[32];
    int gone = 0;

    (void)meter_stats(&d->meter, st);
    if (!getrusage(RUSAGE_SELF, &ru))
        cpu_us = timeval_us(ru.ru_utime) + timeval_us(ru.ru_stime);
    format_duration(up_ns / NSEC_PER_SEC, uptime, sizeof(uptime));
    for (int i = 0; i < d->ifaces.n; i++)
        gone += d->ifaces.ifs[i].gone;
    (void)dprintf(fd, "%-18s %s\n", "version", TCXFLOW_VERSION);
    (void)dprintf(fd, "%-18s %s\n", "uptime", uptime);
    // Userspace CPU and memory, to watch the exporter's own cost over months of runtime.
    (void)dprintf(fd, "%-18s %llu.%03llu s (%.3f%% of one CPU), max RSS %ld KiB\n", "cpu",
                  (unsigned long long)(cpu_us / 1000000U), (unsigned long long)(cpu_us % 1000000U / 1000U),
                  up_ns ? (double)cpu_us * 1e5 / (double)up_ns : 0.0, ru.ru_maxrss);
    (void)dprintf(fd, "%-18s last %llu us, max %llu us\n", "tick", (unsigned long long)(d->tick_ns / 1000U),
                  (unsigned long long)(d->tick_max_ns / 1000U));
    (void)dprintf(fd, "%-18s %s\n", "netns", d->cfg->netns[0] ? d->cfg->netns : "-");
    (void)dprintf(fd, "%-18s %d attached, %d gone\n", "interfaces", d->ifaces.n - gone, gone);
    (void)dprintf(fd, "%-18s %llu\n", "packets", (unsigned long long)d->packets);
    (void)dprintf(fd, "%-18s %llu\n", "bytes", (unsigned long long)d->bytes);
    (void)dprintf(fd, "%-18s %llu non-IP, %llu malformed\n", "ignored", (unsigned long long)st[STAT_NONIP],
                  (unsigned long long)st[STAT_TRUNC]);
    (void)dprintf(fd, "%-18s %llu packets, %llu bytes (flow table full, max_flows %u)\n", "lost",
                  (unsigned long long)st[STAT_FULL_PKTS], (unsigned long long)st[STAT_FULL_BYTES], d->cfg->max_flows);
    (void)dprintf(fd, "%-18s %u (at most %u)\n", "flows cached", d->cache.count, d->cache.limit);
    // Allocated, not used: the cache keeps the memory of its largest size, up to its limit.
    (void)dprintf(fd, "%-18s %zu KiB allocated\n", "cache memory", cache_memory(&d->cache) / 1024);
    (void)dprintf(fd, "%-18s %llu (cache full: exported at once)\n", "flows uncached", (unsigned long long)d->uncached);
    (void)dprintf(fd, "%-18s %llu\n", "flows exported", (unsigned long long)d->ipfix.n_records);
    (void)dprintf(fd, "%-18s %llu\n", "ipfix messages", (unsigned long long)d->ipfix.n_messages);
    for (int i = 0; i < d->cfg->n_collectors; i++)
        (void)dprintf(fd, "%-18s %s: %llu sent, %llu errors\n", "collector", d->cfg->collectors[i],
                      (unsigned long long)d->coll[i].sent, (unsigned long long)d->coll[i].errors);
}

static void reply_interfaces(const struct daemon *d, int fd) {
    (void)dprintf(fd, "%-15s %7s %-9s %-9s %-8s %14s %16s %14s %16s\n", "INTERFACE", "IFINDEX", "VLAN", "DIRECTION",
                  "STATUS", "IN PACKETS", "IN BYTES", "OUT PACKETS", "OUT BYTES");
    for (int i = 0; i < d->ifaces.n; i++) {
        const struct iface_state *s = &d->ifaces.ifs[i];
        char vlan[16];

        iface_format_vlan(s, vlan, sizeof(vlan));
        (void)dprintf(fd, "%-15s %7u %-9s %-9s %-8s %14llu %16llu %14llu %16llu\n", s->cfg->name, s->ifindex, vlan,
                      iface_dir_name(s->cfg), s->gone ? "gone" : "attached",
                      (unsigned long long)s->packets[FLOW_DIR_IN], (unsigned long long)s->bytes[FLOW_DIR_IN],
                      (unsigned long long)s->packets[FLOW_DIR_OUT], (unsigned long long)s->bytes[FLOW_DIR_OUT]);
    }
}

static void handle_control(struct daemon *d) {
    char cmd[64];
    const int fd = control_accept(d->ctl_fd, cmd, sizeof(cmd));

    if (fd < 0)
        return;
    if (!strcmp(cmd, "stats"))
        reply_stats(d, fd);
    else if (!strcmp(cmd, "interfaces"))
        reply_interfaces(d, fd);
    else
        (void)dprintf(fd, "unknown command \"%s\"\n", cmd);
    (void)close(fd);
}

/* Enter the configured namespace; remember which one, so check_target() notices when it is rebuilt. */
static int enter_netns(struct daemon *d) {
    const char *ns = d->cfg->netns;
    struct stat st;
    int fd = -1;

    (void)snprintf(d->netns_path, sizeof(d->netns_path), "%s%s", ns[0] == '/' ? "" : "/run/netns/", ns);
    fd = open(d->netns_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || setns(fd, CLONE_NEWNET)) {
        log_msg("network namespace %s: %s", d->netns_path, strerror(errno));
        if (fd >= 0)
            (void)close(fd);
        return -1;
    }
    d->netns_dev = st.st_dev;
    d->netns_ino = st.st_ino;
    (void)close(fd);
    return 0;
}

static int attach_interfaces(struct daemon *d) {
    for (int i = 0; i < d->cfg->n_ifaces; i++) {
        const struct iface_config *cfg = &d->cfg->ifaces[i];
        const unsigned ifindex = if_nametoindex(cfg->name);
        struct iface_state *s = nullptr;
        char vlan[16];

        if (!ifindex) {
            log_msg("interface %s: %s", cfg->name, strerror(errno));
            return -1;
        }
        // An altname resolves to the same interface: its traffic would be booked to one of them.
        if (iface_add(&d->ifaces, cfg, ifindex, &s)) {
            log_msg("interface %s is the same as %s (ifindex %u)", cfg->name, s->cfg->name, ifindex);
            return -1;
        }
        vlan_of_interface(s->cfg->name, &s->vlan, &s->vlan_inner); // in the metered namespace
        for (int dir = FLOW_DIR_IN; dir <= FLOW_DIR_OUT; dir++) {
            if (!s->cfg->dir[dir])
                continue;
            // A tcx link, not a classic tc filter: it detaches by itself when tcxflow dies, even
            // by SIGKILL, so a crash never leaves a stale program behind.
            s->link[dir] = meter_attach(&d->meter, (int)s->ifindex, (enum flow_dir)dir);
            if (!s->link[dir]) {
                log_msg("interface %s: cannot attach tcx %s: %s", s->cfg->name, dir ? "egress" : "ingress",
                        strerror(errno));
                return -1;
            }
        }
        iface_format_vlan(s, vlan, sizeof(vlan));
        log_msg("metering %s (ifindex %u, %s%s%s)", s->cfg->name, s->ifindex, iface_dir_name(s->cfg),
                s->vlan ? ", VLAN " : "", s->vlan ? vlan : "");
    }
    return 0;
}

static void detach_interfaces(struct daemon *d) {
    for (int i = 0; i < d->ifaces.n; i++) {
        for (int dir = 0; dir < 2; dir++) {
            (void)bpf_link__destroy(d->ifaces.ifs[i].link[dir]);
            d->ifaces.ifs[i].link[dir] = nullptr;
        }
    }
}

/* Everything that precedes the main loop. */
static int start(struct daemon *d) {
    const struct expire_policy policy = {
        .inactive_ns = d->cfg->inactive_timeout * NSEC_PER_SEC,
        .active_ns = d->cfg->active_timeout * NSEC_PER_SEC,
        .fin_ns = FIN_LINGER_NS,
    };
    char err[256];
    int rc = 0;

    // Sockets first, in the namespace tcxflow was started in: export and control stay on the
    // management side even when the metered interfaces live in another namespace.
    for (int i = 0; i < d->cfg->n_collectors; i++) {
        d->coll[i].name = d->cfg->collectors[i];
        d->coll[i].fd = collector_open(d->cfg->collectors[i], err, sizeof(err));
        if (d->coll[i].fd < 0) {
            log_msg("%s", err);
            return -1;
        }
    }
    d->ctl_fd = control_listen(d->cfg->socket, &d->lock_fd);
    if (d->ctl_fd < 0) {
        log_msg("control socket %s: %s%s", d->cfg->socket, strerror(errno),
                errno == EADDRINUSE ? " (tcxflow is already running, or another program uses it)" : "");
        return -1;
    }
    rc = meter_open(&d->meter, d->cfg->max_flows);
    if (rc) {
        log_msg("cannot load the BPF program: %s (needs root and Linux >= 6.6)", strerror(-rc));
        return -1;
    }
    // Small configurations start small; the bucket array doubles as the cache grows.
    rc = cache_init(&d->cache, d->cfg->max_flows < CACHE_BUCKETS ? d->cfg->max_flows : CACHE_BUCKETS,
                    d->cfg->cache_flows ? d->cfg->cache_flows : d->cfg->max_flows * CACHE_LIMIT_FACTOR, &policy,
                    export_flow, d);
    if (rc) {
        log_msg("flow cache: %s", strerror(-rc));
        return -1;
    }
    if (d->cfg->netns[0] && enter_netns(d))
        return -1;
    return attach_interfaces(d);
}

/* Export everything and release all resources. Returns -1 if flows were lost on the way. */
static int stop(struct daemon *d) {
    int rc = 0;

    if (d->meter.skel) {
        uint64_t errors[CONFIG_MAX_COLLECTORS] = {};
        bool drained = true;
        uint32_t older = 0;
        int swapped = 0;

        detach_interfaces(d);
        swapped = meter_swap(&d->meter); // returns when no program run is left
        if (swapped < 0)
            drained = false;
        // The map written last holds the newest interval, the other one an undrained, older one if
        // any: that one first, so the cache gets them in time order. After a switch it is active.
        older = swapped < 0 ? d->meter.active ^ 1U : d->meter.active;
        set_now(d);
        // The whole cache goes out at once; systemd allows 90 s to stop.
        set_export_deadline(d, FINAL_EXPORT_WAIT_NS);
        ipfix_set_max_len(&d->ipfix, export_max_len(d)); // a signal can come before the first tick
        for (int i = 0; i < d->cfg->n_collectors; i++)
            errors[i] = d->coll[i].errors;
        for (uint32_t k = 0; k < 2; k++) {
            cache_batch_begin(&d->cache);
            if (meter_drain(&d->meter, (int)(older ^ k), collect_flow, d) < 0)
                drained = false;
            cache_batch_end(&d->cache);
        }
        (void)cache_expire(&d->cache, d->now_ns, true);
        ipfix_flush(&d->ipfix, d->now_sec);
        // Nothing retries after this: a message not sent now is lost for good.
        for (int i = 0; i < d->cfg->n_collectors; i++) {
            if (d->coll[i].errors != errors[i]) {
                log_msg("collector %s: %llu messages of the final export not sent", d->cfg->collectors[i],
                        (unsigned long long)(d->coll[i].errors - errors[i]));
                rc = -1;
            }
        }
        log_msg("stopped: %llu flows exported in %llu messages%s", (unsigned long long)d->ipfix.n_records,
                (unsigned long long)d->ipfix.n_messages, drained ? "" : ", but the flow maps could not be drained");
        if (!drained)
            rc = -1;
        meter_close(&d->meter);
    }
    if (d->ctl_fd >= 0) {
        (void)unlink(d->cfg->socket); // while the lock is still held: never another instance's socket
        (void)close(d->ctl_fd);
    }
    if (d->lock_fd >= 0)
        (void)close(d->lock_fd);
    for (int i = 0; i < d->cfg->n_collectors; i++)
        if (d->coll[i].fd >= 0)
            (void)close(d->coll[i].fd);
    cache_destroy(&d->cache);
    return rc;
}

int daemon_run(const struct config *cfg) {
    static struct daemon d; // static: too large for the stack
    struct sigaction sa = {.sa_handler = on_signal};
    uint64_t next = 0;
    int rc = 0;

    memset(&d, 0, sizeof(d));
    d.cfg = cfg;
    d.ctl_fd = -1;
    d.lock_fd = -1;
    d.undrained = -1;
    for (int i = 0; i < CONFIG_MAX_COLLECTORS; i++)
        d.coll[i].fd = -1;
    ipfix_init(&d.ipfix, cfg->observation_domain, cfg->template_refresh * NSEC_PER_SEC,
               cfg->export_interval * NSEC_PER_SEC, send_message, &d);
    set_now(&d);
    d.started_ns = d.now_ns;

    // No SA_RESTART: a signal must interrupt poll() so the loop sees stop_requested at once.
    // SIGHUP stops too (and exports everything): there is no reload, and the unit restarts us.
    (void)sigaction(SIGINT, &sa, nullptr);
    (void)sigaction(SIGTERM, &sa, nullptr);
    (void)sigaction(SIGHUP, &sa, nullptr);
    (void)signal(SIGPIPE, SIG_IGN); // a control client that hangs up must not kill the daemon

    if (start(&d)) {
        (void)stop(&d);
        return 1;
    }
    log_msg("%s started: %d interface(s)%s%s, %d collector(s), inactive %us, active %us", TCXFLOW_VERSION,
            cfg->n_ifaces, cfg->netns[0] ? " in netns " : "", cfg->netns, cfg->n_collectors, cfg->inactive_timeout,
            cfg->active_timeout);

    // Ticks on a fixed one-second grid, so a slow tick does not shift all later ones; the poll
    // timeout is the only wakeup, which keeps an idle exporter at one wakeup per second.
    next = clock_ns(CLOCK_MONOTONIC) + NSEC_PER_SEC;
    while (!stop_requested) {
        const uint64_t now = clock_ns(CLOCK_MONOTONIC);
        struct pollfd pfd = {.fd = d.ctl_fd, .events = POLLIN};

        if (now >= next) {
            uint64_t after = 0;

            tick(&d);
            after = clock_ns(CLOCK_MONOTONIC);
            next += NSEC_PER_SEC;
            if (next <= after) // we fell behind (a very slow tick, or the process was stopped): skip, do not catch up
                next = after + NSEC_PER_SEC;
            continue;
        }
        if (poll(&pfd, 1, (int)((next - now + 999999) / 1000000)) > 0 && (pfd.revents & POLLIN))
            handle_control(&d);
    }

    rc = d.target_gone || d.meter_failed ? 1 : 0;
    if (stop(&d))
        rc = 1;
    return rc;
}
