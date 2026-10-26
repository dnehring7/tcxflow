// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file iface.c
 * @brief Metered interfaces: runtime state, lookup by ifindex, VLAN IDs of their records
 */

#include "iface.h"

#include <errno.h> // IWYU pragma: keep (EEXIST, ENOSPC)
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "flow.h"

// Masking needs a power of two; at most half full keeps the probe chains short.
static_assert((IFACE_MAP_SIZE & (IFACE_MAP_SIZE - 1)) == 0 && IFACE_MAP_SIZE >= 2 * CONFIG_MAX_IFACES,
              "IFACE_MAP_SIZE");

/* Called for every drained flow: a hash lookup instead of a scan over up to 64 interfaces. */
static struct iface_slot *slot_of(struct iface_table *t, unsigned ifindex) {
    unsigned h = ifindex & (IFACE_MAP_SIZE - 1);

    while (t->map[h].s && t->map[h].ifindex != ifindex)
        h = (h + 1) & (IFACE_MAP_SIZE - 1);
    return &t->map[h];
}

int iface_add(struct iface_table *t, const struct iface_config *cfg, unsigned ifindex, struct iface_state **s) {
    struct iface_slot *slot = slot_of(t, ifindex);

    if (slot->s) {
        *s = slot->s;
        return -EEXIST;
    }
    if (t->n == CONFIG_MAX_IFACES)
        return -ENOSPC;
    *s = &t->ifs[t->n++];
    **s = (struct iface_state){.cfg = cfg, .ifindex = ifindex};
    *slot = (struct iface_slot){.ifindex = ifindex, .s = *s};
    return 0;
}

struct iface_state *iface_of_flow(struct iface_table *t, const struct flow_key *k) {
    return slot_of(t, k->dir == FLOW_DIR_IN ? k->in_if : k->out_if)->s;
}

/* Packets on a VLAN interface carry no tag any more: its IDs are the outer ones. */
void iface_vlans(const struct iface_state *s, const struct flow_key *k, uint16_t *outer, uint16_t *inner) {
    uint16_t v[4];
    int n = 0;

    if (s && s->vlan)
        v[n++] = s->vlan;
    if (s && s->vlan_inner)
        v[n++] = s->vlan_inner;
    if (k->vlan)
        v[n++] = k->vlan;
    if (k->vlan_inner)
        v[n++] = k->vlan_inner;
    *outer = n > 0 ? v[0] : 0;
    *inner = n > 1 ? v[1] : 0;
}

const char *iface_dir_name(const struct iface_config *cfg) {
    static const char *const names[] = {"-", "in", "out", "in+out"};

    return names[(cfg->dir[FLOW_DIR_IN] ? 1U : 0U) | (cfg->dir[FLOW_DIR_OUT] ? 2U : 0U)];
}

void iface_format_vlan(const struct iface_state *s, char *buf, size_t len) {
    if (s->vlan_inner)
        (void)snprintf(buf, len, "%u.%u", s->vlan, s->vlan_inner);
    else if (s->vlan)
        (void)snprintf(buf, len, "%u", s->vlan);
    else
        (void)snprintf(buf, len, "-");
}
