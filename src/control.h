// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file control.h
 * @brief Control socket: lets "tcxflow stats" and "tcxflow interfaces" query the running exporter
 *
 * Protocol: the client connects to the Unix socket, sends one command line ("stats" or
 * "interfaces"), and reads plain text until the daemon closes the connection.
 */

#ifndef TCXFLOW_CONTROL_H
#define TCXFLOW_CONTROL_H

#include <stddef.h>
#include <stdio.h>

/**
 * Create the listening socket at @p path (mode 0600, parent directory created if missing).
 * An exclusive lock on "path.lock" guards it: fails with EADDRINUSE if another tcxflow holds
 * the lock or another program listens at @p path, and with EEXIST if something other than a
 * socket is there. A socket nobody listens on is left over and replaced.
 *
 * @param path     socket path
 * @param lock_fd  receives the lock file descriptor; keep it open as long as the socket
 * @return listening descriptor or -1 (errno set)
 */
[[nodiscard]] int control_listen(const char *path, int *lock_fd);

/**
 * Accept one pending client and read its command line, waiting 200 ms at most. The client
 * descriptor is non-blocking.
 *
 * @param listen_fd  descriptor from control_listen()
 * @param cmd        receives the command, without the newline
 * @param cmdlen     size of @p cmd
 * @return client descriptor (reply with dprintf(), then close it) or -1
 */
[[nodiscard]] int control_accept(int listen_fd, char *cmd, size_t cmdlen);

/**
 * Client side: send @p cmd to the daemon at @p path and copy the reply to @p out.
 *
 * @param path  control socket of the daemon
 * @param cmd   "stats" or "interfaces"
 * @param out   receives the reply
 * @return 0 or -1 (errno set; ENODATA: no reply at all, not tcxflow at @p path)
 */
[[nodiscard]] int control_request(const char *path, const char *cmd, FILE *out);

#endif // TCXFLOW_CONTROL_H
