// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file vlan.h
 * @brief VLAN IDs of VLAN interfaces (eth0.100, eth0.100.200)
 *
 * Packets on a VLAN interface carry no tag any more, so its VLAN IDs come from the interface
 * configuration instead: /proc/net/vlan/config of the current network namespace.
 */

#ifndef TCXFLOW_VLAN_H
#define TCXFLOW_VLAN_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * Find @p name in a /proc/net/vlan/config listing ("eth0.100 | 100 | eth0" lines).
 *
 * @param fp        the listing
 * @param name      interface name
 * @param lower     receives the interface the VLAN interface sits on
 * @param lowerlen  size of @p lower
 * @return VLAN ID, or 0 if @p name is not a VLAN interface
 */
[[nodiscard]] uint16_t vlan_parse(FILE *fp, const char *name, char *lower, size_t lowerlen);

/**
 * VLAN IDs of an interface in the current network namespace: for eth0.100 outer 100;
 * for a stacked eth0.100.200 outer 100 and inner 200; 0 for interfaces that are no VLAN.
 *
 * @param name   interface name
 * @param outer  receives the outer VLAN ID
 * @param inner  receives the inner VLAN ID (QinQ)
 */
void vlan_of_interface(const char *name, uint16_t *outer, uint16_t *inner);

#endif // TCXFLOW_VLAN_H
