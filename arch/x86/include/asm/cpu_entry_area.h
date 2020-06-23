/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_CPU_ENTRY_AREA_H
#define _ASM_X86_CPU_ENTRY_AREA_H

#include <linux/percpu-defs.h>
#include <asm/processor.h>
#include <asm/intel_ds.h>
#include <asm/pgtable_areas.h>

#ifdef CONFIG_X86_64

/* Macro to enforce the same ordering and stack sizes */
#define ESTACKS_MEMBERS(guardsize, db2_holesize)\
	char	DF_stack_guard[guardsize];	\
	char	DF_stack[EXCEPTION_STKSZ];	\
	char	NMI_stack_guard[guardsize];	\
	char	NMI_stack[EXCEPTION_STKSZ];	\
	char	DB2_stack_guard[guardsize];	\
	char	DB2_stack[db2_holesize];	\
	char	DB1_stack_guard[guardsize];	\
	char	DB1_stack[EXCEPTION_STKSZ];	\
	char	DB_stack_guard[guardsize];	\
	char	DB_stack[EXCEPTION_STKSZ];	\
	char	MCE_stack_guard[guardsize];	\
	char	MCE_stack[EXCEPTION_STKSZ];	\
	char	IST_top_guard[guardsize];	\

/* The exception stacks' physical storage. No guard pages required */
struct exception_stacks {
	ESTACKS_MEMBERS(0, 0)
};

/* The effective cpu entry area mapping with guard pages. */
struct cea_exception_stacks {
	ESTACKS_MEMBERS(PAGE_SIZE, EXCEPTION_STKSZ)
};

/*
 * The exception stack ordering in [cea_]exception_stacks
 */
enum exception_stack_ordering {
	ESTACK_DF,
	ESTACK_NMI,
	ESTACK_DB2,
	ESTACK_DB1,
	ESTACK_DB,
	ESTACK_MCE,
	N_EXCEPTION_STACKS
};

#define CEA_ESTACK_SIZE(st)					\
	sizeof(((struct cea_exception_stacks *)0)->st## _stack)

#define CEA_ESTACK_BOT(ceastp, st)				\
	((unsigned long)&(ceastp)->st## _stack)

#define CEA_ESTACK_TOP(ceastp, st)				\
	(CEA_ESTACK_BOT(ceastp, st) + CEA_ESTACK_SIZE(st))

#define CEA_ESTACK_OFFS(st)					\
	offsetof(struct cea_exception_stacks, st## _stack)

#define CEA_ESTACK_PAGES					\
	(sizeof(struct cea_exception_stacks) / PAGE_SIZE)

/*
 * VC Handler IST Stacks
 *
 * The IST stacks for the #VC handler are only allocated when SEV-ES is active,
 * so they are not part of 'struct exception_stacks'.
 *
 * The VC handler uses shift_ist so that #VC can be nested. Nesting happens for
 * example when the #VC handler has to call printk in the case of and error or
 * when emulating 'movs' instructions.
 *
 * NMIs are another special case which can cause nesting of #VC handlers. The
 * do_nmi() code path can cause #VC, e.g. for RDPMC. An NMI can also hit in
 * the time window when the #VC handler is raised but before it has shifted its
 * IST entry. To make sure any #VC raised from the NMI code path uses a new
 * stack, the NMI handler unconditionally shifts the #VC handlers IST entry.
 * This can cause one IST stack for #VC to be omitted.
 *
 * To support sufficient levels of nesting for the #VC handler, make the number
 * of nesting levels configurable. It is currently set to 5 to support this
 * scenario:
 *
 * #VC - IST stack 4, IST entry already shifted to 3
 *
 *     -> NMI - shifts #VC IST entry to 2
 *
 *     -> #VC(RDPMC) - shifts #VC IST to 1, something goes wrong, print
 *                     an error message
 *
 *     -> #VC(printk) - shifts #VC IST entry to 0, output driver
 *                      uses 'movs'
 *
 *     -> #VC(movs) - shifts IST to unmapped stack, further #VCs will
 *                    cause #DF
 *
 */
#define N_VC_STACKS		5

#define VC_STACK_MEMBERS(guardsize, holesize)			\
	char	hole[holesize];					\
	struct {						\
		char guard[guardsize];				\
		char stack[EXCEPTION_STKSZ];			\
	} stacks[N_VC_STACKS];					\
	char top_guard[guardsize];				\

/* Physical storage */
struct vmm_exception_stacks {
	VC_STACK_MEMBERS(0, 0)
};

/* Mapping in cpu_entry_area */
struct cea_vmm_exception_stacks {
	VC_STACK_MEMBERS(PAGE_SIZE, EXCEPTION_STKSZ)
};

#endif

#ifdef CONFIG_X86_32
struct doublefault_stack {
	unsigned long stack[(PAGE_SIZE - sizeof(struct x86_hw_tss)) / sizeof(unsigned long)];
	struct x86_hw_tss tss;
} __aligned(PAGE_SIZE);
#endif

/*
 * cpu_entry_area is a percpu region that contains things needed by the CPU
 * and early entry/exit code.  Real types aren't used for all fields here
 * to avoid circular header dependencies.
 *
 * Every field is a virtual alias of some other allocated backing store.
 * There is no direct allocation of a struct cpu_entry_area.
 */
struct cpu_entry_area {
	char gdt[PAGE_SIZE];

	/*
	 * The GDT is just below entry_stack and thus serves (on x86_64) as
	 * a read-only guard page. On 32-bit the GDT must be writeable, so
	 * it needs an extra guard page.
	 */
#ifdef CONFIG_X86_32
	char guard_entry_stack[PAGE_SIZE];
#endif
	struct entry_stack_page entry_stack_page;

#ifdef CONFIG_X86_32
	char guard_doublefault_stack[PAGE_SIZE];
	struct doublefault_stack doublefault_stack;
#endif

	/*
	 * On x86_64, the TSS is mapped RO.  On x86_32, it's mapped RW because
	 * we need task switches to work, and task switches write to the TSS.
	 */
	struct tss_struct tss;

#ifdef CONFIG_X86_64
	/*
	 * Exception stacks used for IST entries with guard pages.
	 */
	struct cea_exception_stacks estacks;

	/*
	 * IST Exception stacks for VC handler - Only allocated and mapped when
	 * SEV-ES is active.
	 */
	struct cea_vmm_exception_stacks vc_stacks;
#endif
	/*
	 * Per CPU debug store for Intel performance monitoring. Wastes a
	 * full page at the moment.
	 */
	struct debug_store cpu_debug_store;
	/*
	 * The actual PEBS/BTS buffers must be mapped to user space
	 * Reserve enough fixmap PTEs.
	 */
	struct debug_store_buffers cpu_debug_buffers;
};

#define CPU_ENTRY_AREA_SIZE		(sizeof(struct cpu_entry_area))
#define CPU_ENTRY_AREA_ARRAY_SIZE	(CPU_ENTRY_AREA_SIZE * NR_CPUS)

/* Total size includes the readonly IDT mapping page as well: */
#define CPU_ENTRY_AREA_TOTAL_SIZE	(CPU_ENTRY_AREA_ARRAY_SIZE + PAGE_SIZE)

DECLARE_PER_CPU(struct cpu_entry_area *, cpu_entry_area);
DECLARE_PER_CPU(struct cea_exception_stacks *, cea_exception_stacks);
DECLARE_PER_CPU(struct cea_vmm_exception_stacks *, cea_vmm_exception_stacks);

extern void setup_cpu_entry_areas(void);
extern void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags);

extern struct cpu_entry_area *get_cpu_entry_area(int cpu);

static inline struct entry_stack *cpu_entry_stack(int cpu)
{
	return &get_cpu_entry_area(cpu)->entry_stack_page.stack;
}

#define __this_cpu_ist_top_va(name)					\
	CEA_ESTACK_TOP(__this_cpu_read(cea_exception_stacks), name)

#endif
