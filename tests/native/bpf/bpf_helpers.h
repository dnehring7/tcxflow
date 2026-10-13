/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net> */
/**
 * @file bpf_helpers.h
 * @brief Stand-in for libbpf's bpf_helpers.h: tests/test_bpf_native.c compiles the BPF program as
 * ordinary C, with the helpers it calls implemented by the test.
 */

#ifndef TCXFLOW_NATIVE_BPF_HELPERS_H
#define TCXFLOW_NATIVE_BPF_HELPERS_H

#include <linux/bpf.h>
#include <linux/types.h>

// libbpf's names, which the program uses: reserved identifiers, and a type that cannot be in
// parentheses. NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp,bugprone-macro-parentheses)
#define SEC(name)                                        ///< no ELF sections outside BPF
#define __uint(name, val) int(*name)[val]                ///< as in libbpf: map attributes become members
#define __type(name, val) val *name                      ///< as in libbpf
#define __array(name, val) val *name[]                   ///< as in libbpf
#define __ksym                                           ///< kernel functions: implemented by the test
#define barrier_var(var) __asm__ volatile("" : "+r"(var)) ///< as in libbpf
// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp,bugprone-macro-parentheses)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline)) ///< as in libbpf
#endif

long bpf_skb_load_bytes(const void *skb, __u32 offset, void *to, __u32 len); ///< reads the test packet
void *bpf_map_lookup_elem(void *map, const void *key);                      ///< the test's maps
long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags); ///< the test's maps
__u64 bpf_ktime_get_coarse_ns(void);                                        ///< the test's clock

#endif // TCXFLOW_NATIVE_BPF_HELPERS_H
