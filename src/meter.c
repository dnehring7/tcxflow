// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file meter.c
 * @brief BPF side: load, attach, swap and drain
 */

#include "meter.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>

#include "flow.h"
#include "tcxflow.skel.h"

static constexpr __u32 DRAIN_BATCH = 4096; ///< flows read per bpf_map_lookup_and_delete_batch() call

static bool verbose_log;

[[gnu::format(printf, 2, 0)]] static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list ap) {
    if (level != LIBBPF_WARN && !verbose_log)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

void meter_set_verbose(bool verbose) {
    verbose_log = verbose;
    (void)libbpf_set_print(libbpf_log);
}

/*
 * Point active[0] at flows[idx]. The kernel runs synchronize_rcu() before an update of an
 * array of maps returns: no program still writes to the previous map afterwards.
 */
static int set_active(struct meter *m, uint32_t idx) {
    const __u32 zero = 0;
    const int err =
        bpf_map__update_elem(m->skel->maps.active, &zero, sizeof(zero), &m->flows_fd[idx], sizeof(int), BPF_ANY);

    if (err)
        return err;
    m->active = idx;
    return 0;
}

int meter_open(struct meter *m, uint32_t max_flows) {
    int err = 0;

    memset(m, 0, sizeof(*m));
    m->ncpus = libbpf_num_possible_cpus();
    if (m->ncpus <= 0)
        return m->ncpus ? m->ncpus : -EINVAL;
    // Allocated once: the statistics are read every second for months, without malloc churn.
    m->percpu = calloc((size_t)m->ncpus, sizeof(*m->percpu));
    if (!m->percpu)
        return -ENOMEM;
    m->skel = tcxflow_bpf__open();
    if (!m->skel) {
        err = -errno;
        meter_close(m);
        return err;
    }
    err = bpf_map__set_max_entries(m->skel->maps.flows0, max_flows);
    if (!err)
        err = bpf_map__set_max_entries(m->skel->maps.flows1, max_flows);
    if (!err)
        err = tcxflow_bpf__load(m->skel);
    if (err) {
        meter_close(m);
        return err;
    }
    m->prog[FLOW_DIR_IN] = m->skel->progs.tcxflow_ingress;
    m->prog[FLOW_DIR_OUT] = m->skel->progs.tcxflow_egress;
    m->flows_fd[0] = bpf_map__fd(m->skel->maps.flows0);
    m->flows_fd[1] = bpf_map__fd(m->skel->maps.flows1);
    err = set_active(m, 0);
    if (err) {
        meter_close(m);
        return err;
    }
    return 0;
}

/*
 * In front of the programs already on the hook: one that ends the chain (TCX_PASS, a drop or a
 * redirect, as Cilium's programs do) would hide the packets from the meter otherwise. tcxflow
 * returns TCX_NEXT, so the programs behind it still see every packet.
 */
struct bpf_link *meter_attach(const struct meter *m, int ifindex, enum flow_dir dir) {
    LIBBPF_OPTS(bpf_tcx_opts, opts, .flags = BPF_F_BEFORE);

    return bpf_program__attach_tcx(m->prog[dir], ifindex, &opts);
}

unsigned meter_link_ifindex(const struct bpf_link *link) {
    struct bpf_link_info info = {};
    __u32 len = sizeof(info);

    if (bpf_link_get_info_by_fd(bpf_link__fd(link), &info, &len))
        return 0;
    return info.tcx.ifindex;
}

int meter_swap(struct meter *m) {
    const uint32_t old = m->active;
    const int err = set_active(m, old ^ 1U);

    return err ? err : (int)old;
}

int meter_drain(const struct meter *m, int idx, meter_flow_fn fn, void *ctx) {
    static struct flow_key keys[DRAIN_BATCH];
    static struct flow_val vals[DRAIN_BATCH];
    __u32 batch = 0;
    __u32 *in = nullptr;
    int total = 0;
    int err = 0;

    do {
        __u32 n = DRAIN_BATCH;

        err = bpf_map_lookup_and_delete_batch(m->flows_fd[idx], in, &batch, keys, vals, &n, nullptr);
        // The kernel reports a count only on success and at the end of the map (-ENOENT). After
        // any other error, n still holds the buffer size and the buffers the flows of the
        // previous call: passing them on would count those flows twice.
        if (err && err != -ENOENT)
            return err;
        for (__u32 i = 0; i < n; i++)
            fn(ctx, &keys[i], &vals[i]);
        total += (int)n;
        in = &batch;
    } while (!err);
    return total; // -ENOENT: the map is empty now
}

int meter_stats(const struct meter *m, uint64_t out[STAT_MAX]) {
    const __u32 zero = 0;
    // Sizes checked by libbpf: a per-CPU value has to be read for every possible CPU at once.
    const int err = bpf_map__lookup_elem(m->skel->maps.stats, &zero, sizeof(zero), m->percpu,
                                         (size_t)m->ncpus * sizeof(*m->percpu), 0);

    memset(out, 0, STAT_MAX * sizeof(*out));
    for (int cpu = 0; !err && cpu < m->ncpus; cpu++)
        for (int i = 0; i < STAT_MAX; i++)
            out[i] += m->percpu[cpu].c[i];
    return err;
}

void meter_close(struct meter *m) {
    tcxflow_bpf__destroy(m->skel);
    free(m->percpu);
    memset(m, 0, sizeof(*m));
}
