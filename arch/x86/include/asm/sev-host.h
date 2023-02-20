/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD SVM-SEV Host Support.
 *
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 *
 * Author: Ashish Kalra <ashish.kalra@amd.com>
 *
 */

#ifndef __ASM_X86_SEV_HOST_H
#define __ASM_X86_SEV_HOST_H

#include <asm/sev-common.h>

#ifdef CONFIG_KVM_AMD_SEV
int snp_lookup_rmpentry(u64 pfn, int *level);
void sev_dump_rmpentry(u64 pfn);
#else
static inline int snp_lookup_rmpentry(u64 pfn, int *level) { return 0; }
static inline void sev_dump_rmpentry(u64 pfn) {}
#endif

#endif
