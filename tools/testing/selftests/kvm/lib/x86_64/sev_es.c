// SPDX-License-Identifier: GPL-2.0-only
/*
 * VC handler and helpers used for SEV-ES/SEV-SNP guests
 *
 * Partially copied from arch/x86/kernel/sev-es*.c
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#include <linux/bitops.h>
#include <kvm_util.h>			/* for kvm_util_internal.h */
#include "../kvm_util_internal.h"	/* for processor.h */
#include "processor.h"			/* for struct ex_regs */
#include "svm.h"

#define MSR_SEV_ES_GHCB 0xc0010130
#define SVM_EXIT_CPUID 0x72

#define GHCB_CPUID_REQ_EAX 0
#define GHCB_CPUID_REQ_EBX 1
#define GHCB_CPUID_REQ_ECX 2
#define GHCB_CPUID_REQ_EDX 3

#define GHCB_CPUID_REQ(fn, reg) \
	(0x4UL | (((uint64_t)reg & 3) << 30) | (((uint64_t)fn) << 32))

#define GHCB_RESP_CODE(resp) ((resp) & 0xfff)
#define GHCB_RESP_CODE_CPUID 0x5UL

#define GHCB_TERMINATE 0x100UL
#define GHCB_TERMINATE_REASON(reason_set, reason_val)	\
	(((((u64)reason_set) &  0x7) << 12) |			\
	 ((((u64)reason_val) & 0xff) << 16))

#define GHCB_TERMINATE_REASON_UNSPEC 0

#define GHCB_PROTOCOL_MAX	1
#define GHCB_DEFAULT_USAGE	0

#define VMGEXIT() { asm volatile("rep; vmmcall\n\r"); }

struct ghcb {
	struct vmcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct vmcb_save_area)];
	u8 shared_buffer[2032];
	u8 reserved_1[10];
	u16 protocol_version;
	u32 ghcb_usage;
};

/* GHCB Accessor functions */

#define GHCB_BITMAP_IDX(field)							\
	(offsetof(struct vmcb_save_area, field) / sizeof(u64))

#define DEFINE_GHCB_ACCESSORS(field)						\
	static inline bool ghcb_##field##_is_valid(const struct ghcb *ghcb)	\
	{									\
		return test_bit(GHCB_BITMAP_IDX(field),				\
				(unsigned long *)&ghcb->save.valid_bitmap);	\
	}									\
										\
	static inline u64 ghcb_get_##field(struct ghcb *ghcb)			\
	{									\
		return ghcb->save.field;					\
	}									\
										\
	static inline u64 ghcb_get_##field##_if_valid(struct ghcb *ghcb)	\
	{									\
		return ghcb_##field##_is_valid(ghcb) ? ghcb->save.field : 0;	\
	}									\
										\
	static inline void ghcb_set_##field(struct ghcb *ghcb, u64 value)	\
	{									\
		__set_bit(GHCB_BITMAP_IDX(field),				\
			  (unsigned long *)&ghcb->save.valid_bitmap);		\
		ghcb->save.field = value;					\
	}

DEFINE_GHCB_ACCESSORS(cpl)
DEFINE_GHCB_ACCESSORS(rip)
DEFINE_GHCB_ACCESSORS(rsp)
DEFINE_GHCB_ACCESSORS(rax)
DEFINE_GHCB_ACCESSORS(rcx)
DEFINE_GHCB_ACCESSORS(rdx)
DEFINE_GHCB_ACCESSORS(rbx)
DEFINE_GHCB_ACCESSORS(rbp)
DEFINE_GHCB_ACCESSORS(rsi)
DEFINE_GHCB_ACCESSORS(rdi)
DEFINE_GHCB_ACCESSORS(r8)
DEFINE_GHCB_ACCESSORS(r9)
DEFINE_GHCB_ACCESSORS(r10)
DEFINE_GHCB_ACCESSORS(r11)
DEFINE_GHCB_ACCESSORS(r12)
DEFINE_GHCB_ACCESSORS(r13)
DEFINE_GHCB_ACCESSORS(r14)
DEFINE_GHCB_ACCESSORS(r15)
DEFINE_GHCB_ACCESSORS(sw_exit_code)
DEFINE_GHCB_ACCESSORS(sw_exit_info_1)
DEFINE_GHCB_ACCESSORS(sw_exit_info_2)
DEFINE_GHCB_ACCESSORS(sw_scratch)
DEFINE_GHCB_ACCESSORS(xcr0)

static uint64_t sev_es_rdmsr_ghcb(void)
{
	uint64_t lo, hi;

	asm volatile("rdmsr"
		     : "=a" (lo), "=d" (hi)
		     : "c" (MSR_SEV_ES_GHCB));

	return ((hi << 32) | lo);
}

static void sev_es_wrmsr_ghcb(uint64_t val)
{
	uint64_t lo, hi;

	lo = val & 0xFFFFFFFF;
	hi = val >> 32;

	asm volatile("wrmsr"
		     :: "c" (MSR_SEV_ES_GHCB), "a" (lo), "d" (hi)
		     : "memory");
}

static void sev_es_terminate(int reason)
{
	uint64_t val = GHCB_TERMINATE;

	val |= GHCB_TERMINATE_REASON(0, reason);

	sev_es_wrmsr_ghcb(val);
	VMGEXIT();

	while (true)
		asm volatile("hlt" : : : "memory");
}

static int sev_es_ghcb_hv_call(struct ghcb *ghcb, u64 exit_code)
{
	ghcb->protocol_version = GHCB_PROTOCOL_MAX;
	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	/* this only works if we ensure shared memslot is identity-mapped */
	sev_es_wrmsr_ghcb((uint64_t)ghcb);

	VMGEXIT();

	/* we don't currently handle anything other than #VC exceptions */
	if ((ghcb->save.sw_exit_info_1 & 0xffffffff) == 1)
		sev_es_terminate(GHCB_TERMINATE_REASON_UNSPEC);

	return 0;
}

static int handle_vc_cpuid(struct ghcb *ghcb, struct ex_regs *regs)
{
	int ret;

	ghcb_set_rax(ghcb, regs->rax);
	ghcb_set_rcx(ghcb, regs->rcx);

	/* ignore additional XSAVE states for now */
	ghcb_set_xcr0(ghcb, 1);

	ret = sev_es_ghcb_hv_call(ghcb, SVM_EXIT_CPUID);
	if (ret)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) &&
	      ghcb_rbx_is_valid(ghcb) &&
	      ghcb_rcx_is_valid(ghcb) &&
	      ghcb_rdx_is_valid(ghcb)))
		return 1;

	regs->rax = ghcb->save.rax;
	regs->rbx = ghcb->save.rbx;
	regs->rcx = ghcb->save.rcx;
	regs->rdx = ghcb->save.rdx;

	regs->rip += 2;

	return 0;
}

static int handle_msr_vc_cpuid(struct ex_regs *regs)
{
	uint32_t fn = regs->rax & 0xFFFFFFFF;
	uint64_t resp;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EAX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_RESP_CODE(resp) != GHCB_RESP_CODE_CPUID)
		return 1;
	regs->rax = resp >> 32;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EBX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_RESP_CODE(resp) != GHCB_RESP_CODE_CPUID)
		return 1;
	regs->rbx = resp >> 32;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_ECX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_RESP_CODE(resp) != GHCB_RESP_CODE_CPUID)
		return 1;
	regs->rcx = resp >> 32;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EDX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_RESP_CODE(resp) != GHCB_RESP_CODE_CPUID)
		return 1;
	regs->rdx = resp >> 32;

	regs->rip += 2;

	return 0;
}

/*
 * It's not yet clear how best to handle dealing with multiple GHCBs for use
 * with multiple VCPUs. One approach is adding percpu data via GDT, similarly
 * to how linux SEV-ES guests implement it. Another approach is via IDT by
 * baking GHCB location into a wrapper #VC handler and using a unique #VC
 * handler wrapper for each VCPU.
 *
 * We leave the latter option open for now by implementing this as a helper to
 * be called by the actual handler/wrapper. This also avoids the need to track
 * the GHCB in library code in the meantime.
 *
 * However, both approaches require changes to core test library, so for now
 * we're limited to one GHCB, and when in use only 1 VCPU can generate #VCs at
 * any point in time unless the test implementation itself implements some sort
 * of synchronization to share the GHCB.
 */
void sev_es_handle_vc(void *ghcb, struct ex_regs *regs)
{
	int r = 1;

	/*
	 * TODO: We currently only support MSR and GHCB-based handling of cpuid
	 * instructions. Handling others will likely involve the need to do
	 * instruction decoding, which ideally would re-use the library from
	 * arch/x86/lib/insn.c, but alternatively we can make a copy, or
	 * implement some lightweight alternative for our purposes.
	 */
	if (regs->error_code != SVM_EXIT_CPUID)
		goto fail;

	if (ghcb)
		r = handle_vc_cpuid(ghcb, regs);
	else
		r = handle_msr_vc_cpuid(regs);

	if (r)
		goto fail;

	return;

fail:
	sev_es_terminate(GHCB_TERMINATE_REASON_UNSPEC);
}
