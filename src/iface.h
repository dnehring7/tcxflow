// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file iface.h
 * @brief Metered interfaces: runtime state, lookup by ifindex, VLAN IDs of their records
 */

#ifndef TCXFLOW_IFACE_H
#define TCXFLOW_IFACE_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "flow.h"

struct bpf_link;

constexpr unsigned IFACE_MAP_SIZE = 128; ///< ifindex lookup slots

/** Runtime state of one configured interface. */
struct iface_state {
    const struct iface_config *cfg; /**< configuration of the interface */
    unsigned ifindex;               /**< ifindex inside the namespace at start */
    struct bpf_link *link[2];       /**< tcx links per enum flow_dir, nullptr = not metered */
    uint16_t vlan;                  /**< outer VLAN ID if it is a VLAN interface, else 0 */
    uint16_t vlan_inner;            /**< inner VLAN ID of a stacked (QinQ) VLAN interface */
    bool gone;                      /**< the interface disappeared */
    uint64_t packets[2];            /**< packets per enum flow_dir, from drained flows */
    uint64_t bytes[2];              /**< bytes per enum flow_dir, from drained flows */
};

/** One slot of the ifindex -> interface map (open addressing). */
struct iface_slot {
    unsigned ifindex;      /**< key */
    struct iface_state *s; /**< interface, nullptr = empty slot */
};

/** The metered interfaces; fixed size, zero-initialised it is empty. */
struct iface_table {
    struct iface_state ifs[CONFIG_MAX_IFACES]; /**< in configuration order */
    int n;                                     /**< entries used in ifs */
    struct iface_slot map[IFACE_MAP_SIZE];     /**< finds ifs[] by ifindex */
};

/**
 * Add an interface.
 *
 * @param t        table
 * @param cfg      its configuration, referenced by the entry
 * @param ifindex  its ifindex
 * @param s        receives the new entry; on -EEXIST the entry that has @p ifindex already
 * @return 0, -EEXIST if @p ifindex is in the table (an altname), -ENOSPC if the table is full
 */
[[nodiscard]] int iface_add(struct iface_table *t, const struct iface_config *cfg, unsigned ifindex,
                            struct iface_state **s);

/**
 * The metered interface a flow was seen on.
 *
 * @param t  table
 * @param k  flow key
 * @return its entry, nullptr if the interface is not in the table
 */
[[nodiscard]] struct iface_state *iface_of_flow(struct iface_table *t, const struct flow_key *k);

/**
 * VLAN IDs of a flow record: those of the metered VLAN interface first, then the tags left in
 * the packets, so metering eth0 or eth0.100 gives the same VLAN ID.
 *
 * @param s      interface the flow was seen on, or nullptr
 * @param k      flow key
 * @param outer  receives the outer VLAN ID, 0 = none
 * @param inner  receives the inner VLAN ID, 0 = none
 */
void iface_vlans(const struct iface_state *s, const struct flow_key *k, uint16_t *outer, uint16_t *inner);

/**
 * Configured directions as text.
 *
 * @param cfg  interface configuration
 * @return "in", "out", "in+out" or "-"
 */
[[nodiscard]] const char *iface_dir_name(const struct iface_config *cfg);

/**
 * VLAN IDs of a VLAN interface as text: "100", "100.200" (QinQ) or "-".
 *
 * @param s    interface
 * @param buf  receives the text
 * @param len  size of @p buf
 */
void iface_format_vlan(const struct iface_state *s, char *buf, size_t len);

#endif // TCXFLOW_IFACE_H
