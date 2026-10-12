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
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fputc('\n', stderr);
}

uint64_t clock_ns(clockid_t clk) {
    struct timespec ts = {0};

    (void)clock_gettime(clk, &ts);
    return ((uint64_t)ts.tv_sec * NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;
}
