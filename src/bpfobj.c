// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file bpfobj.c
 * @brief Embeds the compiled BPF object (path in BPF_OBJ, set by the Makefile)
 *
 * C rather than assembler source: the compiler gives this object the same property notes
 * (x86 CET, arm64 BTI) and non-executable stack note as every other one, so the binary keeps
 * its hardening marks. ccache does not cache files that use .incbin.
 */

#include "bpfobj.h"

#ifndef BPF_OBJ
#error "BPF_OBJ must name the compiled BPF object"
#endif

/// @cond EMBED (no API: Doxygen would take the asm statement for an undocumented function)
__asm__(".section .rodata\n"
        ".balign 8\n"
        ".global tcxflow_bpf_obj\n"
        "tcxflow_bpf_obj:\n"
        ".incbin \"" BPF_OBJ "\"\n"
        "tcxflow_bpf_obj_end:\n"
        ".balign 8\n"
        ".global tcxflow_bpf_obj_len\n"
        "tcxflow_bpf_obj_len:\n"
        ".quad tcxflow_bpf_obj_end - tcxflow_bpf_obj\n"
        ".previous\n");
/// @endcond
