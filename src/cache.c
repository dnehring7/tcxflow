// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file cache.c
 * @brief Userspace flow cache
 */

#include "cache.h"

#include <errno.h> // IWYU pragma: keep (ENOMEM, ENOSPC)
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "flow.h"
#include "ipfix.h"

#define FIRST_CAPACITY 1024 ///< entries allocated on first use; doubled whenever full
#define TCP_FIN 0x01        ///< TCP FIN flag
#define TCP_RST 0x04        ///< TCP RST flag

// The key is hashed in 8-byte words: its size must stay a multiple of 8.
_Static_assert(sizeof(struct flow_key) % sizeof(uint64_t) == 0, "flow_key size");

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

int cache_init(struct flow_cache *c, uint32_t n_buckets, uint32_t limit) {
    memset(c, 0, sizeof(*c));
    // Empty before anything can fail: the caller still expires (and destroys) a cache whose
    // initialisation failed.
    c->free_list = CACHE_NIL;
    c->idle = c->fin = c->age = (struct cache_list){CACHE_NIL, CACHE_NIL};
    if (getentropy(&c->seed, sizeof(c->seed)))
        return -errno;
    c->limit = limit;
    c->n_buckets = 1;
    while (c->n_buckets < n_buckets)
        c->n_buckets <<= 1;
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
    uint32_t *nb = c->grow_failed ? NULL : malloc(n * sizeof(*nb));

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
        struct flow_entry *e = c->grow_failed ? NULL : realloc(c->entries, (size_t)cap * sizeof(*e));

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

int cache_add(struct flow_cache *c, const struct flow_key *key, const struct flow_val *val) {
    const uint32_t b = hash_key(c, key) & (c->n_buckets - 1);
    struct flow_entry *e = NULL;
    uint32_t i = 0;

    for (i = c->bucket[b]; i != CACHE_NIL; i = c->entries[i].next) {
        e = &c->entries[i];
        if (memcmp(&e->key, key, sizeof(*key)) != 0)
            continue;
        // Moving the flow to the tail of its idle list keeps that list sorted by last update.
        list_remove(c, idle_list_of(c, e), i);
        if (val->last_ns > e->last_ns)
            e->last_ns = val->last_ns;
        e->packets += val->packets;
        e->bytes += val->bytes;
        e->tcp_flags = (uint16_t)(e->tcp_flags | val->tcp_flags);
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
    e->next = c->bucket[b];
    c->bucket[b] = i;
    list_push_tail(c, idle_list_of(c, e), i);
    list_push_tail(c, &c->age, i);
    if (++c->count > c->n_buckets)
        grow_buckets(c);
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
static void evict(struct flow_cache *c, uint32_t i, uint8_t reason, cache_export_fn export_fn, void *ctx) {
    struct flow_entry *e = &c->entries[i];
    uint32_t *link = &c->bucket[hash_key(c, &e->key) & (c->n_buckets - 1)];

    export_fn(ctx, e, reason);
    while (*link != i) // chains are short: load factor <= 1
        link = &c->entries[*link].next;
    *link = e->next;
    list_remove(c, idle_list_of(c, e), i);
    list_remove(c, &c->age, i);
    e->next = c->free_list;
    c->free_list = i;
    c->count--;
}

/*
 * Export from the head of a time-ordered list until the first flow that has not ended: every
 * flow behind it was updated (or created) later and cannot have ended either.
 */
static uint32_t expire_list(struct flow_cache *c, struct cache_list *list, uint64_t now_ns,
                            const struct expire_policy *policy, cache_export_fn export_fn, void *ctx) {
    uint32_t exported = 0;

    while (list->head != CACHE_NIL) {
        const uint32_t i = list->head;
        const uint8_t reason = end_reason(&c->entries[i], now_ns, policy);

        if (!reason)
            break;
        evict(c, i, reason, export_fn, ctx);
        exported++;
    }
    return exported;
}

uint32_t cache_expire(struct flow_cache *c, uint64_t now_ns, const struct expire_policy *policy, bool force,
                      cache_export_fn export_fn, void *ctx) {
    uint32_t exported = 0;

    // Under memory pressure, growing is tried again once per expiry run (once per second), not for
    // every new flow.
    c->grow_failed = false;
    if (force) {
        while (c->age.head != CACHE_NIL) {
            evict(c, c->age.head, IPFIX_END_FORCED, export_fn, ctx);
            exported++;
        }
        return exported;
    }
    exported += expire_list(c, &c->idle, now_ns, policy, export_fn, ctx);
    exported += expire_list(c, &c->fin, now_ns, policy, export_fn, ctx);
    exported += expire_list(c, &c->age, now_ns, policy, export_fn, ctx);
    return exported;
}
