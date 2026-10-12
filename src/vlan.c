// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file vlan.c
 * @brief VLAN IDs of VLAN interfaces
 */

#include "vlan.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VLAN_CONFIG "/proc/net/vlan/config" ///< per network namespace, exists while 8021q is loaded
#define VLAN_ID_MAX 4094                    ///< highest valid VLAN ID

/* Strip blanks on both ends, in place. */
static char *trim(char *s) {
    char *end = NULL;

    while (*s == ' ' || *s == '\t')
        s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

uint16_t vlan_parse(FILE *fp, const char *name, char *lower, size_t lowerlen) {
    char line[128];

    while (fgets(line, sizeof(line), fp)) {
        char *bar1 = strchr(line, '|');
        char *bar2 = bar1 ? strchr(bar1 + 1, '|') : NULL;
        char *end = NULL;
        unsigned long vid = 0;

        if (!bar2) // the two header lines
            continue;
        *bar1 = *bar2 = '\0';
        vid = strtoul(bar1 + 1, &end, 10);
        if (strcmp(trim(line), name) != 0 || vid == 0 || vid > VLAN_ID_MAX || *trim(end))
            continue;
        (void)snprintf(lower, lowerlen, "%s", trim(bar2 + 1));
        return (uint16_t)vid;
    }
    return 0;
}

/* Read from /proc, not with the SIOCGIFVLAN ioctl: that ioctl loads the 8021q module even on
 * hosts without any VLAN. */
static uint16_t lookup(const char *name, char *lower, size_t lowerlen) {
    FILE *fp = fopen(VLAN_CONFIG, "re");
    uint16_t vid = 0;

    if (!fp) // 8021q not loaded: no VLAN interfaces exist
        return 0;
    vid = vlan_parse(fp, name, lower, lowerlen);
    (void)fclose(fp);
    return vid;
}

void vlan_of_interface(const char *name, uint16_t *outer, uint16_t *inner) {
    char parent[64];
    char grandparent[64];
    const uint16_t vid = lookup(name, parent, sizeof(parent));
    const uint16_t below = vid ? lookup(parent, grandparent, sizeof(grandparent)) : 0;

    *outer = below ? below : vid;
    *inner = below ? vid : 0;
}
