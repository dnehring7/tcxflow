// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file daemon.h
 * @brief The exporter: attach, meter, aggregate, export, answer control requests
 */

#ifndef TCXFLOW_DAEMON_H
#define TCXFLOW_DAEMON_H

#include "config.h"

/**
 * Run the exporter until SIGTERM, SIGINT or SIGHUP, until a metered interface or its network
 * namespace disappears, or until the flow maps cannot be drained for a while. Every cached flow
 * is exported before it returns.
 *
 * Order of startup: collector sockets and control socket are created first, in the
 * namespace tcxflow was started in; then the BPF program is loaded, tcxflow switches
 * to cfg->netns (if set) and attaches to the interfaces there.
 *
 * @param cfg  validated configuration
 * @return process exit status: 0 after a normal stop; 1 on errors, a vanished interface or
 *         messages of the final export that could not be sent
 */
[[nodiscard]] int daemon_run(const struct config *cfg);

#endif // TCXFLOW_DAEMON_H
