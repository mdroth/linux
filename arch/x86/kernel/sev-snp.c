// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2021 Advanced Micro Devices
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#define pr_fmt(fmt)	"SEV-SNP: " fmt

#include <linux/mem_encrypt.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/sev-es.h>
#include <asm/sev-snp.h>

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

/* Provides sev_es_terminate() */
#include "sev-common-shared.c"

void sev_snp_register_ghcb(unsigned long paddr)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 old, val;

	/* save the old GHCB MSR */
	old = sev_es_rd_ghcb_msr();

	/* Issue VMGEXIT */
	sev_es_wr_ghcb_msr(GHCB_REGISTER_GPA_REQ_VAL(pfn));
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();

	/* If the response GPA is not ours then abort the guest */
	if ((GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_REGISTER_GPA_RESP) ||
	    (GHCB_REGISTER_GPA_RESP_VAL(val) != pfn))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(old);
}
