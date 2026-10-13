// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file cache.c
 * @brief Userspace flow cache
 */

#include "cache.h"

#include <errno.h> // IWYU pragma: keep (ENOMEM, ENOSPC)
#include <stdbit.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "flow.h"
#include "ipfix.h"

static constexpr uint32_t FIRST_CAPACITY = 1024; ///< entries allocated on first use; doubled whenever full
static constexpr uint16_t TCP_FIN = 0x01;        ///< TCP FIN flag
static constexpr uint16_t TCP_RST = 0x04;        ///< TCP RST flag

// The key is hashed in 8-byte words: its size must stay a multiple of 8.
static_assert(sizeof(struct flow_key) % sizeof(uint64_t) == 0, "flow_key size");

/*
 * splitmix64-style mixing of the key words. Keys that differ in a single port or address
 * byte must land in different buckets, since flood traffic often varies just one field.
 * The random per-process seed keeps an attacker who controls the flow keys (spoofed
 * packets) from computing keys that all share one bucket and turn lookups into list scans.
 */
static uint32_t hash_key(const struct flow_cache *c, const struct flow_key *key) {
    uint64_t h = c->seed;
    uint64_t word = 0;

    for (size_t i = 0; i < sizeof(*key); i += sizeof(word)) {
        memcpy(&word, (const uint8_t *)key + i, sizeof(word));
        h = (h ^ word) * 0xbf58476d1ce4e5b9ULL;
        h ^= h >> 31;
    }
    return (uint32_t)(h ^ (h >> 32));
}

/* The link of entry i in a list; which of its two links depends on the list. */
static struct cache_link *link_of(struct flow_cache *c, const struct cache_list *list, uint32_t i) {
    return list == &c->age ? &c->entries[i].age : &c->entries[i].idle;
}

static void list_push_tail(struct flow_cache *c, struct cache_list *list, uint32_t i) {
    struct cache_link *l = link_of(c, list, i);

    l->prev = list->tail;
    l->next = CACHE_NIL;
    if (list->tail != CACHE_NIL)
        link_of(c, list, list->tail)->next = i;
    else
        list->head = i;
    list->tail = i;
}

static void list_remove(struct flow_cache *c, struct cache_list *list, uint32_t i) {
    const struct cache_link *l = link_of(c, list, i);

    if (l->prev != CACHE_NIL)
        link_of(c, list, l->prev)->next = l->next;
    else
        list->head = l->next;
    if (l->next != CACHE_NIL)
        link_of(c, list, l->next)->prev = l->prev;
    else
        list->tail = l->prev;
}

/* A flow that saw FIN or RST ends after a short linger instead of the inactive timeout. */
static struct cache_list *idle_list_of(struct flow_cache *c, const struct flow_entry *e) {
    return (e->tcp_flags & (TCP_FIN | TCP_RST)) ? &c->fin : &c->idle;
}

int cache_init(struct flow_cache *c, uint32_t n_buckets, uint32_t limit, const struct expire_policy *policy,
               cache_export_fn export_fn, void *ctx) {
    memset(c, 0, sizeof(*c));
    c->policy = *policy;
    c->export_fn = export_fn;
    c->ctx = ctx;
    c->batch_min_ns = UINT64_MAX;
    // Empty before anything can fail: the caller still expires (and destroys) a cache whose
    // initialisation failed.
    c->free_list = CACHE_NIL;
    c->idle = c->fin = c->age = (struct cache_list){CACHE_NIL, CACHE_NIL};
    if (getentropy(&c->seed, sizeof(c->seed)))
        return -errno;
    c->limit = limit;
    c->n_buckets = stdc_bit_ceil(n_buckets);
    c->bucket = malloc(c->n_buckets * sizeof(*c->bucket));
    if (!c->bucket)
        return -ENOMEM;
    memset(c->bucket, 0xff, c->n_buckets * sizeof(*c->bucket));
    return 0;
}

void cache_destroy(struct flow_cache *c) {
    free(c->bucket);
    free(c->entries);
    memset(c, 0, sizeof(*c));
}

/*
 * Double the bucket array so chains stay short (load factor <= 1). A failed allocation is not
 * an error: lookups only get slower, so the cache keeps working under memory pressure.
 */
static void grow_buckets(struct flow_cache *c) {
    const uint32_t n = c->n_buckets * 2;
    uint32_t *nb = c->grow_failed ? nullptr : malloc(n * sizeof(*nb));

    if (!nb) {
        c->grow_failed = true;
        return;
    }
    memset(nb, 0xff, n * sizeof(*nb));
    for (uint32_t b = 0; b < c->n_buckets; b++) {
        uint32_t next = CACHE_NIL;

        for (uint32_t i = c->bucket[b]; i != CACHE_NIL; i = next) {
            const uint32_t h = hash_key(c, &c->entries[i].key) & (n - 1);

            next = c->entries[i].next;
            c->entries[i].next = nb[h];
            nb[h] = i;
        }
    }
    free(c->bucket);
    c->bucket = nb;
    c->n_buckets = n;
}

/*
 * Freed entries are reused first, so memory only grows up to the largest number of flows
 * ever cached at once, which cache_add() bounds by limit: no growth over months of runtime.
 */
static int alloc_entry(struct flow_cache *c, uint32_t *idx) {
    if (c->free_list != CACHE_NIL) {
        *idx = c->free_list;
        c->free_list = c->entries[*idx].next;
        return 0;
    }
    if (c->used == c->capacity) {
        uint32_t cap = c->capacity ? c->capacity * 2 : FIRST_CAPACITY;

        if (cap > c->limit) // more entries than the limit can never be in use at once
            cap = c->limit > c->used ? c->limit : c->used + 1;
        struct flow_entry *e = c->grow_failed ? nullptr : realloc(c->entries, (size_t)cap * sizeof(*e));

        if (!e) {
            c->grow_failed = true;
            return -ENOMEM;
        }
        c->entries = e;
        c->capacity = cap;
    }
    *idx = c->used++;
    return 0;
}

static uint8_t end_reason(const struct flow_entry *e, uint64_t now_ns, const struct expire_policy *p) {
    // Clamped: a flow can carry a timestamp a tick newer than now_ns, which must not wrap.
    const uint64_t idle = now_ns > e->last_ns ? now_ns - e->last_ns : 0;
    const uint64_t age = now_ns > e->first_ns ? now_ns - e->first_ns : 0;

    if (idle >= p->inactive_ns)
        return IPFIX_END_IDLE;
    if (age >= p->active_ns)
        return IPFIX_END_ACTIVE;
    if ((e->tcp_flags & (TCP_FIN | TCP_RST)) && idle >= p->fin_ns)
        return IPFIX_END_DETECTED;
    return 0;
}

/* Export entry i and give it back: out of its bucket chain, both lists, onto the free list. */
static void evict(struct flow_cache *c, uint32_t i, uint8_t reason) {
    struct flow_entry *e = &c->entries[i];
    uint32_t *link = &c->bucket[hash_key(c, &e->key) & (c->n_buckets - 1)];

    c->export_fn(c->ctx, e, reason);
    while (*link != i) // chains are short: load factor <= 1
        link = &c->entries[*link].next;
    *link = e->next;
    list_remove(c, idle_list_of(c, e), i);
    list_remove(c, &c->age, i);
    e->next = c->free_list;
    c->free_list = i;
    c->count--;
}

int cache_add(struct flow_cache *c, const struct flow_key *key, const struct flow_val *val) {
    const uint32_t b = hash_key(c, key) & (c->n_buckets - 1);
    struct flow_entry *e = nullptr;
    uint32_t i = 0;

    if (val->first_ns < c->batch_min_ns)
        c->batch_min_ns = val->first_ns;
    if (val->last_ns > c->batch_max_ns)
        c->batch_max_ns = val->last_ns;
    for (i = c->bucket[b]; i != CACHE_NIL; i = c->entries[i].next) {
        uint8_t reason = 0;

        e = &c->entries[i];
        if (memcmp(&e->key, key, sizeof(*key)) != 0)
            continue;
        // The flow ended before this interval began (a gap longer than the timeout, or a new
        // connection on the same ports after FIN): the record ends there, even though no expiry
        // run came in between to notice.
        reason = end_reason(e, val->first_ns, &c->policy);
        if (reason) {
            evict(c, i, reason);
            break;
        }
        // Moving the flow to the tail of its idle list keeps that list sorted by last update.
        list_remove(c, idle_list_of(c, e), i);
        // Intervals can come out of order (stop() drains both maps): the record starts with the
        // earliest one, and so do the ECN bits of its first packet.
        if (val->first_ns < e->first_ns) {
            e->first_ns = val->first_ns;
            e->ecn = val->ecn;
        }
        if (val->last_ns > e->last_ns)
            e->last_ns = val->last_ns;
        e->packets += val->packets;
        e->bytes += val->bytes;
        e->tcp_flags = (uint16_t)(e->tcp_flags | val->tcp_flags);
        e->batch = c->batch;
        list_push_tail(c, idle_list_of(c, e), i);
        return 0;
    }
    // A bound, so that a flood of spoofed sources cannot make the daemon grow without limit.
    if (c->count >= c->limit)
        return -ENOSPC;
    if (alloc_entry(c, &i))
        return -ENOMEM;
    e = &c->entries[i];
    e->key = *key;
    e->first_ns = val->first_ns;
    e->last_ns = val->last_ns;
    e->packets = val->packets;
    e->bytes = val->bytes;
    e->tcp_flags = (uint16_t)val->tcp_flags;
    e->ecn = val->ecn;
    e->batch = c->batch;
    e->next = c->bucket[b];
    c->bucket[b] = i;
    list_push_tail(c, idle_list_of(c, e), i);
    list_push_tail(c, &c->age, i);
    if (++c->count > c->n_buckets)
        grow_buckets(c);
    return 0;
}

/*
 * Export from the head of a time-ordered list until the first flow that has not ended: every
 * flow behind it was updated (or created) later and cannot have ended either.
 */
static uint32_t expire_list(struct flow_cache *c, struct cache_list *list, uint64_t now_ns) {
    uint32_t exported = 0;

    while (list->head != CACHE_NIL) {
        const uint32_t i = list->head;
        const uint8_t reason = end_reason(&c->entries[i], now_ns, &c->policy);

        if (!reason)
            break;
        evict(c, i, reason);
        exported++;
    }
    return exported;
}

uint32_t cache_expire(struct flow_cache *c, uint64_t now_ns, bool force) {
    uint32_t exported = 0;

    // Under memory pressure, growing is tried again once per expiry run (once per second), not for
    // every new flow.
    c->grow_failed = false;
    if (force) {
        while (c->age.head != CACHE_NIL) {
            evict(c, c->age.head, IPFIX_END_FORCED);
            exported++;
        }
        return exported;
    }
    exported += expire_list(c, &c->idle, now_ns);
    exported += expire_list(c, &c->fin, now_ns);
    exported += expire_list(c, &c->age, now_ns);
    return exported;
}

void cache_batch_begin(struct flow_cache *c) {
    c->batch++;
    c->batch_min_ns = UINT64_MAX;
    c->batch_max_ns = 0;
}

/** Sort key of qsort_r(): which timestamp orders the list. */
struct sort_ctx {
    const struct flow_entry *entries; /**< the cache's entries */
    bool by_first;                    /**< first_ns (age list), else last_ns */
};

static int by_time(const void *a, const void *b, void *arg) {
    const struct sort_ctx *s = arg;
    const struct flow_entry *x = &s->entries[*(const uint32_t *)a];
    const struct flow_entry *y = &s->entries[*(const uint32_t *)b];
    const uint64_t tx = s->by_first ? x->first_ns : x->last_ns;
    const uint64_t ty = s->by_first ? y->first_ns : y->last_ns;

    return (tx > ty) - (tx < ty);
}

/*
 * Sort the tail of a list that the current batch pushed: everything in front of it is older
 * (earlier batches), so the whole list is in time order again. A batch number that recurs after
 * 256 batches can pull an older entry into the sort; it is sorted along, which does no harm.
 */
static void sort_batch(struct flow_cache *c, struct cache_list *list, bool by_first) {
    struct sort_ctx ctx = {.entries = c->entries, .by_first = by_first};
    uint32_t before = list->tail;
    uint32_t *idx = nullptr;
    uint32_t n = 0;

    while (before != CACHE_NIL && c->entries[before].batch == c->batch) {
        before = link_of(c, list, before)->prev;
        n++;
    }
    // Without memory to sort, ended flows can only wait a little longer behind younger ones.
    idx = n > 1 ? malloc(n * sizeof(*idx)) : nullptr;
    if (!idx)
        return;
    for (uint32_t i = list->tail, k = n; k > 0; i = link_of(c, list, i)->prev)
        idx[--k] = i;
    qsort_r(idx, n, sizeof(*idx), by_time, &ctx);
    for (uint32_t k = 0; k < n; k++) {
        struct cache_link *l = link_of(c, list, idx[k]);

        l->prev = k ? idx[k - 1] : before;
        l->next = k + 1 < n ? idx[k + 1] : CACHE_NIL;
    }
    if (before == CACHE_NIL)
        list->head = idx[0];
    else
        link_of(c, list, before)->next = idx[0];
    list->tail = idx[n - 1];
    free(idx);
}

void cache_batch_end(struct flow_cache *c) {
    if (c->batch_max_ns < c->batch_min_ns || c->batch_max_ns - c->batch_min_ns <= CACHE_BATCH_SPREAD_NS)
        return;
    sort_batch(c, &c->idle, false);
    sort_batch(c, &c->fin, false);
    sort_batch(c, &c->age, true);
}

size_t cache_memory(const struct flow_cache *c) {
    return ((size_t)c->capacity * sizeof(*c->entries)) + ((size_t)c->n_buckets * sizeof(*c->bucket));
}
