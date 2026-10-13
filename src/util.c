// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file util.c
 * @brief Logging and time helpers
 */

#include "util.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

void log_msg(const char *fmt, ...) {
    va_list ap;

    (void)fputs("tcxflow: ", stderr);
    va_start(ap, fmt);
    // clang-tidy 22 does not see C23's va_start (__builtin_c23_va_start) initialise ap.
    (void)vfprintf(stderr, fmt, ap); // NOLINT(clang-analyzer-security.VAList)
    va_end(ap);
    (void)fputc('\n', stderr);
}

uint64_t clock_ns(clockid_t clk) {
    struct timespec ts = {};

    (void)clock_gettime(clk, &ts);
    return ((uint64_t)ts.tv_sec * NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;
}
