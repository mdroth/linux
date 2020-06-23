// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt)	"SEV-ES: " fmt

#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/lockdep.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <generated/asm-offsets.h>
#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/trap_defs.h>
#include <asm/sev-es.h>
#include <asm/insn-eval.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/svm.h>

/* For early boot hypervisor communication in SEV-ES enabled guests */
static struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
static struct ghcb __initdata *boot_ghcb;
DEFINE_PER_CPU(struct cea_vmm_exception_stacks *, cea_vmm_exception_stacks);

static char vc_stack_names[N_VC_STACKS][8];

/* #VC handler runtime per-cpu data */
struct sev_es_runtime_data {
	struct ghcb ghcb_page;

	/* Physical storage for the per-cpu IST stacks of the #VC handler */
	struct vmm_exception_stacks vc_stacks __aligned(PAGE_SIZE);

	/* Reserve on page per CPU as backup storage for the unencrypted GHCB */
	struct ghcb backup_ghcb;

	/*
	 * Mark the per-cpu GHCBs as in-use to detect nested #VC exceptions.
	 * There is no need for it to be atomic, because nothing is written to
	 * the GHCB between the read and the write of ghcb_active. So it is safe
	 * to use it when a nested #VC exception happens before the write.
	 */
	bool ghcb_active;
	bool backup_ghcb_active;
};

static DEFINE_PER_CPU(struct sev_es_runtime_data*, runtime_data);

struct ghcb_state {
	struct ghcb *ghcb;
};

/*
 * Shift/Unshift the IST entry for the #VC handler during
 * nmi_enter()/nmi_exit().  This is needed when an NMI hits in the #VC handlers
 * entry code before it has shifted its IST entry. This way #VC exceptions
 * caused by the NMI handler are guaranteed to use a new stack.
 */
void sev_es_nmi_enter(void)
{
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);

	tss->x86_tss.ist[IST_INDEX_VC] -= VC_STACK_OFFSET;
}

void sev_es_nmi_exit(void)
{
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);

	tss->x86_tss.ist[IST_INDEX_VC] += VC_STACK_OFFSET;
}

static struct ghcb *sev_es_get_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (unlikely(data->ghcb_active)) {
		/* GHCB is already in use - save its contents */

		if (unlikely(data->backup_ghcb_active))
			return NULL;

		/* Mark backup_ghcb active before writing to it */
		data->backup_ghcb_active = true;

		state->ghcb = &data->backup_ghcb;

		/* Backup GHCB content */
		*state->ghcb = *ghcb;
	} else {
		state->ghcb = NULL;
		data->ghcb_active = true;
	}

	return ghcb;
}

static void sev_es_put_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (state->ghcb) {
		/* Restore GHCB from Backup */
		*ghcb = *state->ghcb;
		data->backup_ghcb_active = false;
		state->ghcb = NULL;
	} else {
		data->ghcb_active = false;
	}
}

/* Needed in vc_early_vc_forward_exception */
void do_early_exception(struct pt_regs *regs, int trapnr);

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return native_read_msr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_write_msr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static int vc_fetch_insn_kernel(struct es_em_ctxt *ctxt,
				unsigned char *buffer)
{
	return probe_kernel_read(buffer, (unsigned char *)ctxt->regs->ip,
				 MAX_INSN_SIZE);
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	enum es_result ret;
	int res;

	if (!user_mode(ctxt->regs)) {
		res = vc_fetch_insn_kernel(ctxt, buffer);
		if (unlikely(res == -EFAULT)) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.error_code = 0;
			ctxt->fi.cr2        = ctxt->regs->ip;
			return ES_EXCEPTION;
		}

		insn_init(&ctxt->insn, buffer, MAX_INSN_SIZE - res, 1);
		insn_get_length(&ctxt->insn);
	} else {
		res = insn_fetch_from_user(ctxt->regs, buffer);
		if (res == 0) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.cr2        = ctxt->regs->ip;
			ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
			return ES_EXCEPTION;
		}

		if (!insn_decode(ctxt->regs, &ctxt->insn, buffer, res))
			return ES_DECODE_FAILED;
	}

	ret = ctxt->insn.immediate.got ? ES_OK : ES_DECODE_FAILED;

	return ret;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   char *dst, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT | X86_PF_WRITE;
	char __user *target = (char __user *)dst;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	switch (size) {
	case 1:
		memcpy(&d1, buf, 1);
		if (put_user(d1, target))
			goto fault;
		break;
	case 2:
		memcpy(&d2, buf, 2);
		if (put_user(d2, target))
			goto fault;
		break;
	case 4:
		memcpy(&d4, buf, 4);
		if (put_user(d4, target))
			goto fault;
		break;
	case 8:
		memcpy(&d8, buf, 8);
		if (put_user(d8, target))
			goto fault;
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)dst;

	return ES_EXCEPTION;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  char *src, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT;
	char __user *s = (char __user *)src;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	switch (size) {
	case 1:
		if (get_user(d1, s))
			goto fault;
		memcpy(buf, &d1, 1);
		break;
	case 2:
		if (get_user(d2, s))
			goto fault;
		memcpy(buf, &d2, 2);
		break;
	case 4:
		if (get_user(d4, s))
			goto fault;
		memcpy(buf, &d4, 4);
		break;
	case 8:
		if (get_user(d8, s))
			goto fault;
		memcpy(buf, &d8, 8);
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)src;

	return ES_EXCEPTION;
}

static phys_addr_t vc_slow_virt_to_phys(struct ghcb *ghcb, unsigned long vaddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = pgd_offset(current->active_mm, va);
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte)
		return 0;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	return pa;
}

/* Include code shared with pre-decompression boot stage */
#include "sev-es-shared.c"

/*
 * This function runs on the first #VC exception after the kernel
 * switched to virtual addresses.
 */
static bool __init sev_es_setup_ghcb(void)
{
	/* First make sure the hypervisor talks a supported protocol. */
	if (!sev_es_negotiate_protocol())
		return false;
	/*
	 * Clear the boot_ghcb. The first exception comes in before the bss
	 * section is cleared.
	 */
	memset(&boot_ghcb_page, 0, PAGE_SIZE);

	/* Alright - Make the boot-ghcb public */
	boot_ghcb = &boot_ghcb_page;

	return true;
}

static void __init sev_es_alloc_runtime_data(int cpu)
{
	struct sev_es_runtime_data *data;

	data = memblock_alloc(sizeof(*data), PAGE_SIZE);
	if (!data)
		panic("Can't allocate SEV-ES runtime data");

	per_cpu(runtime_data, cpu) = data;
}

static void __init sev_es_init_ghcb(int cpu)
{
	struct sev_es_runtime_data *data;
	int err;

	data = per_cpu(runtime_data, cpu);

	err = early_set_memory_decrypted((unsigned long)&data->ghcb_page,
					 sizeof(data->ghcb_page));
	if (err)
		panic("Can not map GHCBs unencrypted");

	memset(&data->ghcb_page, 0, sizeof(data->ghcb_page));

	data->ghcb_active = false;
	data->backup_ghcb_active = false;
}

static void __init init_vc_stack_names(void)
{
	int i;

	for (i = 0; i < N_VC_STACKS; i++) {
		snprintf(vc_stack_names[i], sizeof(vc_stack_names[i]),
			 "#VC%d", i);
	}
}

static void __init sev_es_setup_vc_stack(int cpu)
{
	struct vmm_exception_stacks *stack;
	struct sev_es_runtime_data *data;
	struct cpu_entry_area *cea;
	struct tss_struct *tss;
	unsigned long size;
	char *first_stack;
	int i;

	data  = per_cpu(runtime_data, cpu);
	stack = &data->vc_stacks;
	cea   = get_cpu_entry_area(cpu);

	/* Map the stacks to the cpu_entry_area */
	for (i = 0; i < N_VC_STACKS; i++) {
		void *vaddr = cea->vc_stacks.stacks[i].stack;
		phys_addr_t pa = __pa(stack->stacks[i].stack);

		cea_set_pte(vaddr, pa, PAGE_KERNEL);
	}

	/*
	 * The #VC handler IST stack is needed in secondary CPU bringup before
	 * cpu_init() had a chance to setup the rest of the TSS. So setup the
	 * #VC handlers stack pointer up here for all CPUs
	 */
	first_stack = cea->vc_stacks.stacks[N_VC_STACKS - 1].stack;
	size        = sizeof(cea->vc_stacks.stacks[N_VC_STACKS - 1].stack);
	tss         = per_cpu_ptr(&cpu_tss_rw, cpu);

	tss->x86_tss.ist[IST_INDEX_VC] = (unsigned long)first_stack + size;

	per_cpu(cea_vmm_exception_stacks, cpu) = &cea->vc_stacks;
}

void __init sev_es_init_vc_handling(void)
{
	int cpu;

	BUILD_BUG_ON((offsetof(struct sev_es_runtime_data, ghcb_page) % PAGE_SIZE) != 0);
	BUILD_BUG_ON((offsetof(struct sev_es_runtime_data, vc_stacks) % PAGE_SIZE) != 0);

	if (!sev_es_active())
		return;

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		sev_es_alloc_runtime_data(cpu);
		sev_es_init_ghcb(cpu);
		sev_es_setup_vc_stack(cpu);
	}

	init_vc_stack_names();
}

const char *vc_stack_name(enum stack_type type)
{
	if (type < STACK_TYPE_VC || type > STACK_TYPE_VC_LAST)
		return NULL;

	return vc_stack_names[type - STACK_TYPE_VC];
}

static void __init vc_early_vc_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	do_early_exception(ctxt->regs, trapnr);
}

static long *vc_insn_get_reg(struct es_em_ctxt *ctxt)
{
	long *reg_array;
	int offset;

	reg_array = (long *)ctxt->regs;
	offset    = insn_get_modrm_reg_off(&ctxt->insn, ctxt->regs);

	if (offset < 0)
		return NULL;

	offset /= sizeof(long);

	return reg_array + offset;
}

static enum es_result vc_do_mmio(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
				 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;
	unsigned long ghcb_pa = __pa(ghcb);
	void __user *ref;

	ref = insn_get_addr_ref(&ctxt->insn, ctxt->regs);
	if (ref == (void __user *)-1L)
		return ES_UNSUPPORTED;

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	exit_info_1 = vc_slow_virt_to_phys(ghcb, (unsigned long)ref);
	exit_info_2 = bytes;    /* Can never be greater than 8 */

	ghcb->save.sw_scratch = ghcb_pa + offsetof(struct ghcb, shared_buffer);

	return sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, exit_info_1, exit_info_2);
}

static enum es_result vc_handle_mmio_twobyte_ops(struct ghcb *ghcb,
						 struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	int sign_byte;
	long *reg_data;

	switch (insn->opcode.bytes[1]) {
		/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		/* Fallthrough */
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		memset(reg_data, 0, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MMIO Read w/ sign-extension */
	case 0xbe:
		bytes = 1;
		/* Fallthrough */
	case 0xbf:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0xff : 0x00;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0xff : 0x00;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

/*
 * The MOVS instruction has two memory operands, which raises the
 * problem that it is not known whether the access to the source or the
 * destination caused the #VC exception (and hence whether an MMIO read
 * or write operation needs to be emulated).
 *
 * Instead of playing games with walking page-tables and trying to guess
 * whether the source or destination is an MMIO range, this code splits
 * the move into two operations, a read and a write with only one
 * memory operand. This will cause a nested #VC exception on the MMIO
 * address which can then be handled.
 *
 * This implementation has the benefit that it also supports MOVS where
 * source _and_ destination are MMIO regions.
 *
 * It will slow MOVS on MMIO down a lot, but in SEV-ES guests it is a
 * rare operation. If it turns out to be a performance problem the split
 * operations can be moved to memcpy_fromio() and memcpy_toio().
 */
static enum es_result vc_handle_mmio_movs(struct es_em_ctxt *ctxt,
					  unsigned int bytes)
{
	unsigned long ds_base, es_base;
	unsigned char *src, *dst;
	unsigned char buffer[8];
	enum es_result ret;
	bool rep;
	int off;

	ds_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_DS);
	es_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_ES);

	if (ds_base == -1L || es_base == -1L) {
		ctxt->fi.vector = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		return ES_EXCEPTION;
	}

	src = ds_base + (unsigned char *)ctxt->regs->si;
	dst = es_base + (unsigned char *)ctxt->regs->di;

	ret = vc_read_mem(ctxt, src, buffer, bytes);
	if (ret != ES_OK)
		return ret;

	ret = vc_write_mem(ctxt, dst, buffer, bytes);
	if (ret != ES_OK)
		return ret;

	if (ctxt->regs->flags & X86_EFLAGS_DF)
		off = -bytes;
	else
		off =  bytes;

	ctxt->regs->si += off;
	ctxt->regs->di += off;

	rep = insn_has_rep_prefix(&ctxt->insn);

	if (rep)
		ctxt->regs->cx -= 1;

	if (!rep || ctxt->regs->cx == 0)
		return ES_OK;
	else
		return ES_RETRY;
}

static enum es_result vc_handle_mmio(struct ghcb *ghcb,
				     struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	long *reg_data;

	switch (insn->opcode.bytes[0]) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		/* Fallthrough */
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vc_insn_get_reg(ctxt);
		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		/* Fallthrough */
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

		/* MMIO Read */
	case 0x8a:
		bytes = 1;
		/* Fallthrough */
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		reg_data = vc_insn_get_reg(ctxt);
		if (bytes == 4)
			*reg_data = 0;  /* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MOVS instruction */
	case 0xa4:
		bytes = 1;
		/* Fallthrough */
	case 0xa5:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_handle_mmio_movs(ctxt, bytes);
		break;
		/* Two-Byte Opcodes */
	case 0x0f:
		ret = vc_handle_mmio_twobyte_ops(ghcb, ctxt);
		break;
	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
		break;
	case SVM_EXIT_NPF:
		result = vc_handle_mmio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

static void vc_forward_exception(struct es_em_ctxt *ctxt)
{
	long error_code = ctxt->fi.error_code;
	int trapnr = ctxt->fi.vector;

	ctxt->regs->orig_ax = ctxt->fi.error_code;

	switch (trapnr) {
	case X86_TRAP_GP:
		do_general_protection(ctxt->regs, error_code);
		break;
	case X86_TRAP_UD:
		do_invalid_op(ctxt->regs, 0);
		break;
	default:
		pr_emerg("Unsupported exception in #VC instruction emulation - can't continue\n");
		BUG();
	}
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs,
					unsigned long exit_code)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;

	lockdep_assert_irqs_disabled();

	/*
	 * This is invoked through an interrupt gate, so IRQs are disabled. The
	 * code below might walk page-tables for user or kernel addresses, so
	 * keep the IRQs disabled to protect us against concurrent TLB flushes.
	 */

	ghcb = sev_es_get_ghcb(&state);
	if (!ghcb) {
		/*
		 * Mark GHCBs inactive so that panic() is able to print the
		 * message.
		 */
		data->ghcb_active        = false;
		data->backup_ghcb_active = false;

		panic("Unable to handle #VC exception! GHCB and Backup GHCB are already in use");
	}

	vc_ghcb_invalidate(ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, exit_code);

	sev_es_put_ghcb(&state);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_err_ratelimited("Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		pr_err_ratelimited("Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		pr_err_ratelimited("Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		pr_emerg("Unknown result in %s():%d\n", __func__, result);
		/*
		 * Emulating the instruction which caused the #VC exception
		 * failed - can't continue so print debug information
		 */
		BUG();
	}

	return;

fail:
	if (user_mode(regs)) {
		/*
		 * Do not kill the machine if user-space triggered the
		 * exception. Send SIGBUS instead and let user-space deal with
		 * it.
		 */
		force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)0);
	} else {
		pr_emerg("PANIC: Unhandled #VC exception in kernel space (result=%d)\n",
			 result);

		/* Show some debug info */
		show_regs(regs);

		/* Ask hypervisor to sev_es_terminate */
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

		/* If that fails and we get here - just panic */
		panic("Returned from Terminate-Request to Hypervisor\n");
	}
}

bool __init vc_boot_ghcb(struct pt_regs *regs)
{
	unsigned long exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	/* Do initial setup or terminate the guest */
	if (unlikely(boot_ghcb == NULL && !sev_es_setup_ghcb()))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, boot_ghcb, exit_code);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		early_printk("PANIC: Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		early_printk("PANIC: Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		early_printk("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_early_vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return true;

fail:
	show_regs(regs);

	while (true)
		halt();
}
