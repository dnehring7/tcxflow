// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file bpfobj.h
 * @brief The compiled BPF program, embedded into the tcxflow binary by bpfobj.c
 */

#ifndef TCXFLOW_BPFOBJ_H
#define TCXFLOW_BPFOBJ_H

#include <stdint.h>

extern const unsigned char tcxflow_bpf_obj[]; ///< compiled BPF object (ELF)
extern const uint64_t tcxflow_bpf_obj_len;    ///< size of tcxflow_bpf_obj in bytes

#endif // TCXFLOW_BPFOBJ_H
