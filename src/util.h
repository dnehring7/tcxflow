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

#define TCXFLOW_VERSION "v1.1.0" ///< release version, the same as its git tag; the Makefile reads it from here

constexpr uint64_t NSEC_PER_SEC = 1'000'000'000; ///< nanoseconds per second
constexpr uint64_t NSEC_PER_MSEC = 1'000'000;    ///< nanoseconds per millisecond

/**
 * Log a message to stderr (journald when run by systemd), prefixed with "tcxflow: ".
 *
 * @param fmt  printf() format, followed by its arguments
 */
[[gnu::format(printf, 1, 2)]] void log_msg(const char *fmt, ...);

/**
 * Current time of a clock.
 *
 * @param clk  CLOCK_MONOTONIC, CLOCK_REALTIME, ...
 * @return nanoseconds
 */
[[nodiscard]] uint64_t clock_ns(clockid_t clk);

#endif // TCXFLOW_UTIL_H
