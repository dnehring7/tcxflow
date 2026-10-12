// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file util.h
 * @brief Version, logging and time helpers
 */

#ifndef TCXFLOW_UTIL_H
#define TCXFLOW_UTIL_H

#include <stdint.h>
#include <time.h>

#define TCXFLOW_VERSION "v1.0.0" ///< release version, the same as its git tag; the Makefile reads it from here

#define NSEC_PER_SEC ((uint64_t)1000000000) ///< nanoseconds per second

/**
 * Log a message to stderr (journald when run by systemd), prefixed with "tcxflow: ".
 *
 * @param fmt  printf() format, followed by its arguments
 */
void log_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Current time of a clock.
 *
 * @param clk  CLOCK_MONOTONIC, CLOCK_REALTIME, ...
 * @return nanoseconds
 */
uint64_t clock_ns(clockid_t clk);

#endif // TCXFLOW_UTIL_H
