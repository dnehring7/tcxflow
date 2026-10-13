// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file config.c
 * @brief Configuration: options and the configuration file
 */

#include "config.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collector.h"
#include "flow.h"

static constexpr size_t LINE_MAX_LEN = 512; ///< longest configuration file line, including the newline

static int set_number(const char *key, const char *value, unsigned long min, unsigned long max, uint32_t *out,
                      char *err, size_t errlen) {
    char *end = nullptr;
    unsigned long num = 0;

    errno = 0;
    num = strtoul(value, &end, 10);
    if (value[0] < '0' || value[0] > '9' || errno || *end || num < min || num > max) {
        (void)snprintf(err, errlen, "%s must be a number from %lu to %lu", key, min, max);
        return -1;
    }
    *out = (uint32_t)num;
    return 0;
}

static int set_string(const char *key, const char *value, char *dst, size_t dstlen, char *err, size_t errlen) {
    const size_t len = strlen(value);

    if (len >= dstlen) {
        (void)snprintf(err, errlen, "%s is too long (at most %zu characters)", key, dstlen - 1);
        return -1;
    }
    memcpy(dst, value, len + 1);
    return 0;
}

/* "eth0" (both directions), "eth0:in", "eth0:out" or "eth0:both" */
static int add_interface(struct config *cfg, const char *value, char *err, size_t errlen) {
    const char *colon = strchr(value, ':');
    const size_t len = colon ? (size_t)(colon - value) : strlen(value);
    struct iface_config *ifc = &cfg->ifaces[cfg->n_ifaces];

    if (cfg->n_ifaces == CONFIG_MAX_IFACES) {
        (void)snprintf(err, errlen, "too many interfaces (at most %d)", CONFIG_MAX_IFACES);
        return -1;
    }
    if (len == 0 || len >= CONFIG_NAME_MAX) {
        (void)snprintf(err, errlen, "interface: invalid name \"%s\"", value);
        return -1;
    }
    memset(ifc, 0, sizeof(*ifc));
    memcpy(ifc->name, value, len);
    ifc->dir[FLOW_DIR_IN] = !colon || !strcmp(colon, ":in") || !strcmp(colon, ":both");
    ifc->dir[FLOW_DIR_OUT] = !colon || !strcmp(colon, ":out") || !strcmp(colon, ":both");
    if (!ifc->dir[FLOW_DIR_IN] && !ifc->dir[FLOW_DIR_OUT]) {
        (void)snprintf(err, errlen, "interface %s: direction must be in, out or both", ifc->name);
        return -1;
    }
    for (int i = 0; i < cfg->n_ifaces; i++) {
        if (!strcmp(cfg->ifaces[i].name, ifc->name)) {
            (void)snprintf(err, errlen, "interface %s is given twice", ifc->name);
            return -1;
        }
    }
    cfg->n_ifaces++;
    return 0;
}

static int add_collector(struct config *cfg, const char *value, char *err, size_t errlen) {
    char host[CONFIG_STRING_MAX];
    char port[8];

    if (cfg->n_collectors == CONFIG_MAX_COLLECTORS) {
        (void)snprintf(err, errlen, "too many collectors (at most %d)", CONFIG_MAX_COLLECTORS);
        return -1;
    }
    if (collector_split(value, host, sizeof(host), port, sizeof(port))) {
        (void)snprintf(err, errlen, "collector: invalid address \"%s\" (use host:port or [ipv6]:port)", value);
        return -1;
    }
    if (set_string("collector", value, cfg->collectors[cfg->n_collectors], CONFIG_STRING_MAX, err, errlen))
        return -1;
    cfg->n_collectors++;
    return 0;
}

void config_init(struct config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->template_refresh = 60;
    cfg->inactive_timeout = 15;
    cfg->active_timeout = 1800;
    cfg->max_flows = 131072;
    // RFC 7011 reserves domain 0 for messages without a specific observation domain; flow
    // records have one (the metered interfaces).
    cfg->observation_domain = 1;
    memcpy(cfg->socket, CONFIG_DEFAULT_SOCKET, sizeof(CONFIG_DEFAULT_SOCKET));
}

/*
 * The one place that knows the options: the command line and the configuration file both come
 * here, so they cannot drift apart and every check exists only once.
 */
int config_set(struct config *cfg, const char *key, const char *value, char *err, size_t errlen) {
    if (!strcmp(key, "interface"))
        return add_interface(cfg, value, err, errlen);
    if (!strcmp(key, "collector"))
        return add_collector(cfg, value, err, errlen);
    if (!strcmp(key, "inactive-timeout"))
        return set_number(key, value, 1, 86400, &cfg->inactive_timeout, err, errlen);
    if (!strcmp(key, "active-timeout"))
        return set_number(key, value, 1, 604800, &cfg->active_timeout, err, errlen);
    if (!strcmp(key, "max-flows"))
        return set_number(key, value, 1024, 1UL << 24, &cfg->max_flows, err, errlen);
    if (!strcmp(key, "cache-flows"))
        return set_number(key, value, 1024, 1UL << 27, &cfg->cache_flows, err, errlen);
    if (!strcmp(key, "template-refresh"))
        return set_number(key, value, 1, 86400, &cfg->template_refresh, err, errlen);
    if (!strcmp(key, "observation-domain"))
        return set_number(key, value, 0, UINT32_MAX, &cfg->observation_domain, err, errlen);
    if (!strcmp(key, "netns")) {
        if (strchr(value, '/') && value[0] != '/') {
            (void)snprintf(err, errlen, "netns must be a name or an absolute path");
            return -1;
        }
        return set_string(key, value, cfg->netns, sizeof(cfg->netns), err, errlen);
    }
    if (!strcmp(key, "socket")) {
        if (value[0] != '/') {
            (void)snprintf(err, errlen, "socket must be an absolute path");
            return -1;
        }
        return set_string(key, value, cfg->socket, sizeof(cfg->socket), err, errlen);
    }
    (void)snprintf(err, errlen, "unknown option \"%s\"", key);
    return -1;
}

/* Cut a line at '#' or at its end and strip the blanks around what is left. */
static char *clean_line(char *line) {
    char *start = line;
    char *last = nullptr; // one past the last non-blank character

    while (*start == ' ' || *start == '\t')
        start++;
    last = start;
    for (char *p = start; *p && *p != '#' && *p != '\r' && *p != '\n'; p++)
        if (*p != ' ' && *p != '\t')
            last = p + 1;
    *last = '\0';
    return start;
}

/* Split "key value" or "key = value": terminate the key, return the value ("" if none). */
static char *split_value(char *key) {
    char *p = key;

    while (*p && *p != ' ' && *p != '\t' && *p != '=')
        p++;
    if (*p)
        *p++ = '\0';
    while (*p == ' ' || *p == '\t' || *p == '=')
        p++;
    return p;
}

int config_read(struct config *cfg, FILE *fp, const char *name, char *err, size_t errlen) {
    char line[LINE_MAX_LEN];
    char msg[256];
    int lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *key = nullptr;
        char *value = nullptr;

        lineno++;
        if (!strchr(line, '\n') && !feof(fp)) {
            (void)snprintf(err, errlen, "%s:%d: line too long", name, lineno);
            return -1;
        }
        key = clean_line(line);
        if (!*key)
            continue;
        value = split_value(key);
        if (!*value) {
            (void)snprintf(err, errlen, "%s:%d: %s needs a value", name, lineno, key);
            return -1;
        }
        if (config_set(cfg, key, value, msg, sizeof(msg))) {
            (void)snprintf(err, errlen, "%s:%d: %s", name, lineno, msg);
            return -1;
        }
    }
    // fgets() also stops on a read error: a half-read file must not pass as complete.
    if (ferror(fp)) {
        (void)snprintf(err, errlen, "%s: %s", name, strerror(errno));
        return -1;
    }
    return 0;
}

int config_load(struct config *cfg, const char *path, char *err, size_t errlen) {
    FILE *fp = fopen(path, "re");
    int rc = 0;

    if (!fp) {
        (void)snprintf(err, errlen, "%s: %s", path, strerror(errno));
        return -1;
    }
    rc = config_read(cfg, fp, path, err, errlen);
    (void)fclose(fp);
    return rc;
}

int config_validate(const struct config *cfg, char *err, size_t errlen) {
    if (cfg->n_ifaces == 0) {
        (void)snprintf(err, errlen, "no interface configured");
        return -1;
    }
    if (cfg->n_collectors == 0) {
        (void)snprintf(err, errlen, "no collector configured");
        return -1;
    }
    return 0;
}
