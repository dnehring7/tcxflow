// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file cache.h
 * @brief Userspace flow cache: aggregates per-second BPF counters until a flow ends
 *
 * Every operation is O(1) per flow: a chained hash table finds a flow, and three lists kept
 * in time order let cache_expire() stop at the first flow that has not ended, instead of
 * looking at every cached flow once per second:
 *
 * - idle list: flows without TCP FIN/RST, least recently updated first (inactive timeout);
 * - fin list: flows with FIN or RST, least recently updated first (2 s linger);
 * - age list: all flows, oldest first (active timeout).
 *
 * The flows of one drained BPF map come in hash order, so the lists are in time order only up
 * to the time the map collected, normally one second. A map that collected longer (tcxflow
 * stalled) is sorted into place when its batch ends.
 *
 * Entries live in one array and refer to each other by index, so growing the array with
 * realloc() keeps every link valid. Removed entries go onto a free list and are reused.
 */

#ifndef TCXFLOW_CACHE_H
#define TCXFLOW_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include "flow.h"

/** Links of an entry in a doubly linked list of entries. */
struct cache_link {
    uint32_t prev; /**< previous entry, CACHE_NIL at the head */
    uint32_t next; /**< next entry, CACHE_NIL at the tail */
};

/** A cached flow. */
struct flow_entry {
    struct flow_key key;    /**< flow identity */
    uint64_t first_ns;      /**< first packet, CLOCK_MONOTONIC */
    uint64_t last_ns;       /**< last packet, CLOCK_MONOTONIC */
    uint64_t packets;       /**< packets since the flow record started */
    uint64_t bytes;         /**< bytes since the flow record started */
    uint16_t tcp_flags;     /**< OR of all TCP flags (12 bits) */
    uint8_t ecn;            /**< ECN bits of the first packet */
    uint8_t batch;          /**< batch of the last update (modulo 256) */
    uint32_t next;          /**< next entry in the bucket chain or free list */
    struct cache_link idle; /**< place in the idle or fin list */
    struct cache_link age;  /**< place in the age list */
};

/** Head and tail of a list of entries. */
struct cache_list {
    uint32_t head; /**< first entry, CACHE_NIL if empty */
    uint32_t tail; /**< last entry, CACHE_NIL if empty */
};

/** When cached flows end. All values in nanoseconds. */
struct expire_policy {
    uint64_t inactive_ns; /**< no packet for this long: flow ended (idle timeout) */
    uint64_t active_ns;   /**< flow record older than this: export it (active timeout) */
    uint64_t fin_ns;      /**< TCP FIN or RST seen and idle this long: flow ended */
};

/** Receives every flow the cache removes, with its IPFIX flowEndReason. */
typedef void (*cache_export_fn)(void *ctx, const struct flow_entry *entry, uint8_t reason);

/** The cache. Initialise with cache_init(), release with cache_destroy(). */
struct flow_cache {
    uint32_t *bucket;            /**< chain heads, CACHE_NIL = empty */
    uint32_t n_buckets;          /**< power of two */
    struct flow_entry *entries;  /**< entry storage */
    uint32_t capacity;           /**< allocated entries */
    uint32_t used;               /**< entries ever handed out */
    uint32_t free_list;          /**< first free entry, CACHE_NIL = none */
    uint32_t count;              /**< flows currently cached */
    uint32_t limit;              /**< flows cached at most */
    uint64_t seed;               /**< random hash seed */
    bool grow_failed;            /**< an allocation failed: no new one before the next cache_expire() */
    struct cache_list idle;      /**< flows without FIN/RST, by last update */
    struct cache_list fin;       /**< flows with FIN/RST, by last update */
    struct cache_list age;       /**< all flows, by creation */
    struct expire_policy policy; /**< when flows end */
    cache_export_fn export_fn;   /**< receives every flow that ended */
    void *ctx;                   /**< passed to export_fn */
    uint8_t batch;               /**< current batch, see cache_batch_begin() */
    uint64_t batch_min_ns;       /**< earliest first packet in the current batch */
    uint64_t batch_max_ns;       /**< latest last packet in the current batch */
};

constexpr uint32_t CACHE_NIL = UINT32_MAX;                ///< no entry: end of a bucket chain, a list or the free list
constexpr uint64_t CACHE_BATCH_SPREAD_NS = 1'250'000'000; ///< a batch spreading wider is sorted (normal: one second)

/**
 * Set up an empty cache that holds at most @p limit flows.
 *
 * @param c          cache to set up
 * @param n_buckets  initial hash buckets, rounded up to a power of two
 * @param limit      flows cached at most
 * @param policy     when flows end
 * @param export_fn  receives every flow that ended, from cache_add() or cache_expire()
 * @param ctx        passed to @p export_fn
 * @return 0, -ENOMEM, or -errno if no random hash seed is available
 */
[[nodiscard]] int cache_init(struct flow_cache *c, uint32_t n_buckets, uint32_t limit,
                             const struct expire_policy *policy, cache_export_fn export_fn, void *ctx);

/**
 * Free all memory.
 *
 * @param c  cache from cache_init()
 */
void cache_destroy(struct flow_cache *c);

/**
 * Add the counters of one measurement interval.
 *
 * A cached flow whose packets stopped for longer than its timeout before this interval began
 * ended there: it is exported, and the interval starts a new record. Intervals should come in
 * time order, one map after the other, which keeps the lists sorted.
 *
 * @param c    cache
 * @param key  flow identity
 * @param val  counters of the interval, added to the cached flow
 * @return 0, -ENOSPC if the flow is new and the cache holds @p limit flows, or -ENOMEM
 */
[[nodiscard]] int cache_add(struct flow_cache *c, const struct flow_key *key, const struct flow_val *val);

/**
 * Begin a batch: the intervals of one drained map.
 *
 * @param c  cache
 */
void cache_batch_begin(struct flow_cache *c);

/**
 * End a batch. If its intervals spread over more than CACHE_BATCH_SPREAD_NS (the map collected
 * longer than usual), the flows it updated are sorted into time order, so that no flow that
 * ended waits behind a younger one of the same batch.
 *
 * @param c  cache
 */
void cache_batch_end(struct flow_cache *c);

/**
 * Remove and export every flow that has ended at @p now_ns, or every flow if @p force.
 * Costs O(flows exported), not O(flows cached).
 *
 * @param c       cache
 * @param now_ns  current CLOCK_MONOTONIC time
 * @param force   export every flow (shutdown)
 * @return number of flows exported
 */
uint32_t cache_expire(struct flow_cache *c, uint64_t now_ns, bool force);

/**
 * Memory the cache has allocated: entries and buckets, used or not.
 *
 * @param c  cache
 * @return bytes
 */
[[nodiscard]] size_t cache_memory(const struct flow_cache *c);

#endif // TCXFLOW_CACHE_H
