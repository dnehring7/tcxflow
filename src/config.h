// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file config.h
 * @brief Configuration: command line options and the configuration file
 *
 * The configuration file holds the same options as the command line, one per line:
 *
 *     # comment
 *     netns            dataplane
 *     interface        eth0
 *     interface        eth1:in
 *     collector        192.0.2.10:4739
 *     inactive-timeout 15
 *
 * "option value" and "option = value" are both accepted. Command line and file are
 * handled by the same function, config_set().
 */

#ifndef TCXFLOW_CONFIG_H
#define TCXFLOW_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef CONFIG_DEFAULT_PATH // the Makefile sets it from SYSCONFDIR, where `make install` puts the file
#define CONFIG_DEFAULT_PATH "/etc/tcxflow/tcxflow.conf" ///< configuration file read when --config is not given
#endif
#define CONFIG_DEFAULT_SOCKET "/run/tcxflow/tcxflow.sock" ///< default control socket

#define CONFIG_MAX_IFACES 64    ///< interfaces at most
#define CONFIG_MAX_COLLECTORS 8 ///< collectors at most
#define CONFIG_NAME_MAX 16      ///< interface name buffer (IFNAMSIZ)
#define CONFIG_STRING_MAX 256   ///< netns and collector address buffer
#define CONFIG_SOCKET_MAX 108   ///< control socket path buffer (sizeof(sockaddr_un.sun_path))

/** One metered interface. */
struct iface_config {
    char name[CONFIG_NAME_MAX]; /**< interface name inside the namespace */
    bool dir[2];                /**< meter [FLOW_DIR_IN] and/or [FLOW_DIR_OUT] */
};

/** Complete configuration: fixed-size arrays, so it needs no allocation and nothing to free. */
struct config {
    char netns[CONFIG_STRING_MAX];                             /**< namespace of the interfaces, "" = tcxflow's own */
    struct iface_config ifaces[CONFIG_MAX_IFACES];             /**< interfaces to meter */
    int n_ifaces;                                              /**< entries used in ifaces */
    char collectors[CONFIG_MAX_COLLECTORS][CONFIG_STRING_MAX]; /**< "host:port" or "[v6]:port" */
    int n_collectors;                                          /**< entries used in collectors */
    uint32_t observation_domain;                               /**< IPFIX observation domain id */
    uint32_t inactive_timeout;                                 /**< seconds */
    uint32_t active_timeout;                                   /**< seconds */
    uint32_t max_flows;                                        /**< BPF flow table size per one-second interval */
    char socket[CONFIG_SOCKET_MAX];                            /**< control socket path */
};

/**
 * Fill a configuration with the defaults (no interfaces, no collectors).
 *
 * @param cfg  configuration to initialise
 */
void config_init(struct config *cfg);

/**
 * Apply one option, e.g. key "interface", value "eth0:in".
 *
 * @param cfg     configuration to change
 * @param key     option name without the dashes
 * @param value   option value
 * @param err     receives the error message
 * @param errlen  size of @p err
 * @return 0, or -1 with a message in @p err
 */
int config_set(struct config *cfg, const char *key, const char *value, char *err, size_t errlen);

/**
 * Apply every option in @p fp, one per line; '#' starts a comment.
 *
 * @param cfg     configuration to change
 * @param fp      file to read
 * @param name    used in messages: "name:line: problem"
 * @param err     receives the error message
 * @param errlen  size of @p err
 * @return 0, or -1 with a message in @p err
 */
int config_read(struct config *cfg, FILE *fp, const char *name, char *err, size_t errlen);

/**
 * config_read() on a file.
 *
 * @param cfg     configuration to change
 * @param path    file to read
 * @param err     receives the error message
 * @param errlen  size of @p err
 * @return 0, or -1 with a message in @p err
 */
int config_load(struct config *cfg, const char *path, char *err, size_t errlen);

/**
 * Check that at least one interface and one collector are configured.
 *
 * @param cfg     configuration to check
 * @param err     receives the error message
 * @param errlen  size of @p err
 * @return 0, or -1 with a message in @p err
 */
int config_validate(const struct config *cfg, char *err, size_t errlen);

#endif // TCXFLOW_CONFIG_H
