// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file test.h
 * @brief Minimal test helpers: CHECK macros and a test runner, no dependencies
 */

#ifndef TCXFLOW_TEST_H
#define TCXFLOW_TEST_H

#include <stdio.h>
#include <string.h>

static int test_errors; // failed checks in the running test
static int tests_run;
static int tests_failed;

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            test_errors++;                                                                                             \
            (void)fprintf(stderr, "    %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);                         \
        }                                                                                                              \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                                     \
    do {                                                                                                               \
        const unsigned long long act_ = (unsigned long long)(actual);                                                  \
        const unsigned long long exp_ = (unsigned long long)(expected);                                                \
        if (act_ != exp_) {                                                                                            \
            test_errors++;                                                                                             \
            (void)fprintf(stderr, "    %s:%d: %s is %llu, expected %llu\n", __FILE__, __LINE__, #actual, act_, exp_);  \
        }                                                                                                              \
    } while (0)

#define CHECK_STR(actual, expected)                                                                                    \
    do {                                                                                                               \
        const char *act_ = (actual);                                                                                   \
        const char *exp_ = (expected);                                                                                 \
        if (strcmp(act_, exp_) != 0) {                                                                                 \
            test_errors++;                                                                                             \
            (void)fprintf(stderr, "    %s:%d: %s is \"%s\", expected \"%s\"\n", __FILE__, __LINE__, #actual, act_,     \
                          exp_);                                                                                       \
        }                                                                                                              \
    } while (0)

/* The string @p haystack contains @p needle. */
#define CHECK_CONTAINS(haystack, needle) CHECK(strstr((haystack), (needle)) != nullptr)

#define RUN_TEST(fn)                                                                                                   \
    do {                                                                                                               \
        test_errors = 0;                                                                                               \
        fn();                                                                                                          \
        tests_run++;                                                                                                   \
        tests_failed += test_errors != 0;                                                                              \
        (void)printf("%-48s %s\n", #fn, test_errors ? "FAIL" : "ok");                                                  \
    } while (0)

/* Print the summary and return the process exit status. */
static inline int test_summary(void) {
    (void)printf("%d tests, %d failed\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}

#endif // TCXFLOW_TEST_H
