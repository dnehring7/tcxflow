// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file meter.h
 * @brief BPF side: load the embedded program, attach it with tcx, swap and drain the flow maps
 */

#ifndef TCXFLOW_METER_H
#define TCXFLOW_METER_H

#include <stdint.h>

#include "flow.h"

struct bpf_link;
struct bpf_program;
struct tcxflow_bpf;

/** Loaded BPF object, with its programs and flow maps indexed for direct use. */
struct meter {
    struct tcxflow_bpf *skel;    /**< programs and maps (bpftool skeleton), nullptr = not loaded */
    struct bpf_program *prog[2]; /**< [FLOW_DIR_IN] ingress and [FLOW_DIR_OUT] egress program */
    int flows_fd[2];             /**< flows0 and flows1 */
    uint32_t active;             /**< index the BPF side currently writes to */
    int ncpus;                   /**< possible CPUs (per-CPU map size) */
    struct flow_stats *percpu;   /**< buffer for one read of the per-CPU statistics */
};

/** Called for every flow drained from a map. */
typedef void (*meter_flow_fn)(void *ctx, const struct flow_key *key, const struct flow_val *val);

/**
 * Show libbpf's informational and debug messages too (default: warnings only).
 *
 * @param verbose  true for all messages
 */
void meter_set_verbose(bool verbose);

/**
 * Load the embedded BPF object; flows0 is active.
 *
 * @param m          receives the loaded object
 * @param max_flows  entries of each flow map
 * @return 0 or -errno
 */
[[nodiscard]] int meter_open(struct meter *m, uint32_t max_flows);

/**
 * Attach the program for @p dir to an interface of the current network namespace, in front of
 * the tcx programs already attached there.
 *
 * @param m        object from meter_open()
 * @param ifindex  interface index
 * @param dir      FLOW_DIR_IN for tcx ingress, FLOW_DIR_OUT for tcx egress
 * @return link to destroy on shutdown, or nullptr with errno set
 */
[[nodiscard]] struct bpf_link *meter_attach(const struct meter *m, int ifindex, enum flow_dir dir);

/**
 * The interface a tcx link from meter_attach() is attached to. The kernel detaches the links of
 * an interface that is deleted, so a new interface with the same name and index has none.
 *
 * @param link  link from meter_attach()
 * @return interface index, or 0 if the link is detached
 */
[[nodiscard]] unsigned meter_link_ifindex(const struct bpf_link *link);

/**
 * Point the BPF side at the other flow map. Returns after every program run that may
 * still write to the previous map has finished (the kernel waits for an RCU grace period).
 *
 * @param m  object from meter_open()
 * @return index of the now idle map, to be passed to meter_drain(), or -errno
 */
[[nodiscard]] int meter_swap(struct meter *m);

/**
 * Move every flow out of an idle flow map.
 *
 * @param m    object from meter_open()
 * @param idx  map index from meter_swap()
 * @param fn   receives every flow
 * @param ctx  passed to @p fn
 * @return number of flows, or -errno
 */
[[nodiscard]] int meter_drain(const struct meter *m, int idx, meter_flow_fn fn, void *ctx);

/**
 * Sum the per-CPU statistics.
 *
 * @param m    object from meter_open()
 * @param out  receives the counters, indexed by enum flow_stat
 * @return 0 or -errno
 */
[[nodiscard]] int meter_stats(const struct meter *m, uint64_t out[STAT_MAX]);

/**
 * Unload everything. Attached links must be destroyed first. Works on a zeroed object.
 *
 * @param m  object from meter_open()
 */
void meter_close(struct meter *m);

#endif // TCXFLOW_METER_H
