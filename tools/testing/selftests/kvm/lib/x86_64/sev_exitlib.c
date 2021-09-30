// SPDX-License-Identifier: GPL-2.0-only
/*
 * GHCB/#VC/instruction helpers for use with SEV-ES/SEV-SNP guests.
 *
 * Partially copied from arch/x86/kernel/sev*.c
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#include <linux/bitops.h>
#include <kvm_util.h>			/* needed by kvm_util_internal.h */
#include "../kvm_util_internal.h"	/* needed by processor.h */
#include "processor.h"			/* for struct ex_regs */
#include "svm_util.h"			/* for additional SVM_EXIT_* definitions */
#include "svm.h"			/* for VMCB/VMSA layout */
#include "sev_exitlib.h"

#define PAGE_SHIFT 12

#define MSR_SEV_ES_GHCB 0xc0010130

#define VMGEXIT() { asm volatile("rep; vmmcall\n\r"); }

#define GHCB_PROTOCOL_MAX	1
#define GHCB_DEFAULT_USAGE	0

/* Guest-requested termination codes */
#define GHCB_TERMINATE 0x100UL
#define GHCB_TERMINATE_REASON(reason_set, reason_val)	\
	(((((u64)reason_set) &  0x7) << 12) |			\
	 ((((u64)reason_val) & 0xff) << 16))

#define GHCB_TERMINATE_REASON_UNSPEC 0

/* GHCB MSR protocol for CPUID */
#define GHCB_CPUID_REQ_EAX 0
#define GHCB_CPUID_REQ_EBX 1
#define GHCB_CPUID_REQ_ECX 2
#define GHCB_CPUID_REQ_EDX 3
#define GHCB_CPUID_REQ_CODE 0x4UL
#define GHCB_CPUID_REQ(fn, reg) \
	(GHCB_CPUID_REQ_CODE | (((uint64_t)reg & 3) << 30) | (((uint64_t)fn) << 32))
#define GHCB_CPUID_RESP_CODE 0x5UL
#define GHCB_CPUID_RESP(resp) ((resp) & 0xfff)

/* GHCB MSR protocol for GHCB registration */
#define GHCB_REG_GPA_REQ_CODE 0x12UL
#define GHCB_REG_GPA_REQ(gfn) \
	(((unsigned long)((gfn) & GENMASK_ULL(51, 0)) << 12) | GHCB_REG_GPA_REQ_CODE)
#define GHCB_REG_GPA_RESP_CODE 0x13UL
#define GHCB_REG_GPA_RESP(resp) ((resp) & GENMASK_ULL(11, 0))
#define GHCB_REG_GPA_RESP_VAL(resp) ((resp) >> 12)

/* GHCB format/accessors */

struct ghcb {
	struct vmcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct vmcb_save_area)];
	u8 shared_buffer[2032];
	u8 reserved_1[10];
	u16 protocol_version;
	u32 ghcb_usage;
};

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

void sev_es_terminate(int reason)
{
	uint64_t val = GHCB_TERMINATE;

	val |= GHCB_TERMINATE_REASON(2, reason);

	sev_es_wrmsr_ghcb(val);
	VMGEXIT();

	while (true)
		asm volatile("hlt" : : : "memory");
}

static int sev_es_ghcb_hv_call(struct ghcb *ghcb, u64 ghcb_gpa, u64 exit_code)
{
	ghcb->protocol_version = GHCB_PROTOCOL_MAX;
	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wrmsr_ghcb(ghcb_gpa);

	VMGEXIT();

	/* Only #VC exceptions are currently handled. */
	if ((ghcb->save.sw_exit_info_1 & 0xffffffff) == 1)
		sev_es_terminate(GHCB_TERMINATE_REASON_UNSPEC);

	return 0;
}

static int handle_vc_cpuid(struct ghcb *ghcb, u64 ghcb_gpa, struct ex_regs *regs)
{
	int ret;

	ghcb_set_rax(ghcb, regs->rax);
	ghcb_set_rcx(ghcb, regs->rcx);

	/* ignore additional XSAVE states for now */
	ghcb_set_xcr0(ghcb, 1);

	ret = sev_es_ghcb_hv_call(ghcb, ghcb_gpa, SVM_EXIT_CPUID);
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
	if (GHCB_CPUID_RESP(resp) != GHCB_CPUID_RESP_CODE)
		return 1;
	regs->rax = resp >> 32;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EBX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_CPUID_RESP(resp) != GHCB_CPUID_RESP_CODE)
		return 1;
	regs->rbx = resp >> 32;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_ECX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_CPUID_RESP(resp) != GHCB_CPUID_RESP_CODE)
		return 1;
	regs->rcx = resp >> 32;

	sev_es_wrmsr_ghcb(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EDX));
	VMGEXIT();
	resp = sev_es_rdmsr_ghcb();
	if (GHCB_CPUID_RESP(resp) != GHCB_CPUID_RESP_CODE)
		return 1;
	regs->rdx = resp >> 32;

	regs->rip += 2;

	return 0;
}

int sev_es_handle_vc(void *ghcb, u64 ghcb_gpa, struct ex_regs *regs)
{
	if (regs->error_code != SVM_EXIT_CPUID)
		return 1;

	if (!ghcb)
		return handle_msr_vc_cpuid(regs);

	return handle_vc_cpuid(ghcb, ghcb_gpa, regs);
}
