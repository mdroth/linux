// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SVM-SEV Host Support.
 *
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 *
 * Author: Ashish Kalra <ashish.kalra@amd.com>
 *
 */

#include <linux/cc_platform.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/iommu.h>
#include <linux/amd-iommu.h>

#include <asm/sev.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/cpuid.h>
#include <asm/cmdline.h>
#include <asm/iommu.h>

/*
 * The RMP entry format is not architectural. The format is defined in PPR
 * Family 19h Model 01h, Rev B1 processor.
 */
struct rmpentry {
	u64	assigned	: 1,
		pagesize	: 1,
		immutable	: 1,
		rsvd1		: 9,
		gpa		: 39,
		asid		: 10,
		vmsa		: 1,
		validated	: 1,
		rsvd2		: 1;
	u64 rsvd3;
} __packed;

/*
 * The first 16KB from the RMP_BASE is used by the processor for the
 * bookkeeping, the range needs to be added during the RMP entry lookup.
 */
#define RMPTABLE_CPU_BOOKKEEPING_SZ	0x4000

/* Mask to apply to a PFN to get the first PFN of a 2MB page */
#define PFN_PMD_MASK	GENMASK_ULL(63, PMD_SHIFT - PAGE_SHIFT)

static u64 probed_rmp_base __ro_after_init;
static u64 probed_rmp_size __ro_after_init;
static struct rmpentry *rmptable __ro_after_init;
static u64 rmptable_max_pfn __ro_after_init;

#undef pr_fmt
#define pr_fmt(fmt)	"SEV-SNP: " fmt

static int __mfd_enable(unsigned int cpu)
{
	u64 val;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_MFDM;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void mfd_enable(void *arg)
{
	__mfd_enable(smp_processor_id());
}

static int __snp_enable(unsigned int cpu)
{
	u64 val;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	rdmsrl(MSR_AMD64_SYSCFG, val);

	val |= MSR_AMD64_SYSCFG_SNP_EN;
	val |= MSR_AMD64_SYSCFG_SNP_VMPL_EN;

	wrmsrl(MSR_AMD64_SYSCFG, val);

	return 0;
}

static __init void snp_enable(void *arg)
{
	__snp_enable(smp_processor_id());
}

#define RMP_ADDR_MASK GENMASK_ULL(51, 13)

bool __init snp_probe_rmptable_info(void)
{
	u64 max_rmp_pfn, calc_rmp_sz, rmp_sz, rmp_base, rmp_end;

	rdmsrl(MSR_AMD64_RMP_BASE, rmp_base);
	rdmsrl(MSR_AMD64_RMP_END, rmp_end);

	if (!(rmp_base & RMP_ADDR_MASK) || !(rmp_end & RMP_ADDR_MASK)) {
		pr_err("Memory for the RMP table has not been reserved by BIOS\n");
		return false;
	}

	if (rmp_base > rmp_end) {
		pr_err("RMP configuration not valid: base=%#llx, end=%#llx\n", rmp_base, rmp_end);
		return false;
	}

	rmp_sz = rmp_end - rmp_base + 1;

	/*
	 * Calculate the amount the memory that must be reserved by the BIOS to
	 * address the whole RAM, including the bookkeeping area. The RMP itself
	 * must also be covered.
	 */
	max_rmp_pfn = max_pfn;
	if (PHYS_PFN(rmp_end) > max_pfn)
		max_rmp_pfn = PHYS_PFN(rmp_end);

	calc_rmp_sz = (max_rmp_pfn << 4) + RMPTABLE_CPU_BOOKKEEPING_SZ;

	if (calc_rmp_sz > rmp_sz) {
		pr_err("Memory reserved for the RMP table does not cover full system RAM (expected 0x%llx got 0x%llx)\n",
		       calc_rmp_sz, rmp_sz);
		return false;
	}

	probed_rmp_base = rmp_base;
	probed_rmp_size = rmp_sz;

	pr_info("RMP table physical range [0x%016llx - 0x%016llx]\n",
		probed_rmp_base, probed_rmp_base + probed_rmp_size - 1);

	return true;
}

static int __init __snp_rmptable_init(void)
{
	u64 rmptable_size;
	void *rmptable_start;
	u64 val;

	if (!probed_rmp_size)
		return 1;

	rmptable_start = memremap(probed_rmp_base, probed_rmp_size, MEMREMAP_WB);
	if (!rmptable_start) {
		pr_err("Failed to map RMP table\n");
		return 1;
	}

	/*
	 * Check if SEV-SNP is already enabled, this can happen in case of
	 * kexec boot.
	 */
	rdmsrl(MSR_AMD64_SYSCFG, val);
	if (val & MSR_AMD64_SYSCFG_SNP_EN)
		goto skip_enable;

	memset(rmptable_start, 0, probed_rmp_size);

	/* Flush the caches to ensure that data is written before SNP is enabled. */
	wbinvd_on_all_cpus();

	/* MtrrFixDramModEn must be enabled on all the CPUs prior to enabling SNP. */
	on_each_cpu(mfd_enable, NULL, 1);

	on_each_cpu(snp_enable, NULL, 1);

skip_enable:
	rmptable_start += RMPTABLE_CPU_BOOKKEEPING_SZ;
	rmptable_size = probed_rmp_size - RMPTABLE_CPU_BOOKKEEPING_SZ;

	rmptable = (struct rmpentry *)rmptable_start;
	rmptable_max_pfn = rmptable_size / sizeof(struct rmpentry) - 1;

	return 0;
}

static int __init snp_rmptable_init(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	if (!amd_iommu_snp_en)
		return 0;

	if (__snp_rmptable_init())
		goto nosnp;

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/rmptable_init:online", __snp_enable, NULL);

	return 0;

nosnp:
	setup_clear_cpu_cap(X86_FEATURE_SEV_SNP);
	return -ENOSYS;
}

/*
 * This must be called after the IOMMU has been initialized.
 */
device_initcall(snp_rmptable_init);

static struct rmpentry *get_rmpentry(u64 pfn)
{
	if (WARN_ON_ONCE(pfn > rmptable_max_pfn))
		return ERR_PTR(-EFAULT);

	return &rmptable[pfn];
}

static struct rmpentry *__snp_lookup_rmpentry(u64 pfn, int *level)
{
	struct rmpentry *large_entry, *entry;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return ERR_PTR(-ENODEV);

	entry = get_rmpentry(pfn);
	if (IS_ERR(entry))
		return entry;

	/*
	 * Find the authoritative RMP entry for a PFN. This can be either a 4K
	 * RMP entry or a special large RMP entry that is authoritative for a
	 * whole 2M area.
	 */
	large_entry = get_rmpentry(pfn & PFN_PMD_MASK);
	if (IS_ERR(large_entry))
		return large_entry;

	*level = RMP_TO_PG_LEVEL(large_entry->pagesize);

	return entry;
}

int snp_lookup_rmpentry(u64 pfn, bool *assigned, int *level)
{
	struct rmpentry *e;

	e = __snp_lookup_rmpentry(pfn, level);
	if (IS_ERR(e))
		return PTR_ERR(e);

	*assigned = !!e->assigned;
	return 0;
}
EXPORT_SYMBOL_GPL(snp_lookup_rmpentry);

/*
 * Dump the raw RMP entry for a particular PFN. These bits are documented in the
 * PPR for a particular CPU model and provide useful information about how a
 * particular PFN is being utilized by the kernel/firmware at the time certain
 * unexpected events occur, such as RMP faults.
 */
static void dump_rmpentry(u64 pfn)
{
	u64 pfn_current, pfn_end;
	struct rmpentry *e;
	u64 *e_data;
	int level;

	e = __snp_lookup_rmpentry(pfn, &level);
	if (IS_ERR(e)) {
		pr_info("Failed to read RMP entry for PFN 0x%llx, error %ld\n",
			pfn, PTR_ERR(e));
		return;
	}

	e_data = (u64 *)e;
	if (e->assigned) {
		pr_info("RMP entry for PFN 0x%llx: [high=0x%016llx low=0x%016llx]\n",
			pfn, e_data[1], e_data[0]);
		return;
	}

	/*
	 * If the RMP entry for a particular PFN is not in an assigned state,
	 * then it is sometimes useful to get an idea of whether or not any RMP
	 * entries for other PFNs within the same 2MB region are assigned, since
	 * those too can affect the ability to access a particular PFN in
	 * certain situations, such as when the PFN is being accessed via a 2MB
	 * mapping in the host page table.
	 */
	pfn_current = ALIGN(pfn, PTRS_PER_PMD);
	pfn_end = pfn_current + PTRS_PER_PMD;

	while (pfn_current < pfn_end) {
		e = __snp_lookup_rmpentry(pfn_current, &level);
		if (IS_ERR(e)) {
			pfn_current++;
			continue;
		}

		e_data = (u64 *)e;
		if (e_data[0] || e_data[1]) {
			pr_info("No assigned RMP entry for PFN 0x%llx, but the 2MB region contains populated RMP entries, e.g.: PFN 0x%llx: [high=0x%016llx low=0x%016llx]\n",
				pfn, pfn_current, e_data[1], e_data[0]);
			return;
		}
		pfn_current++;
	}

	pr_info("No populated RMP entries in the 2MB region containing PFN 0x%llx\n",
		pfn);
}

void snp_dump_hva_rmpentry(unsigned long hva)
{
	unsigned int level;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd += pgd_index(hva);
	pte = lookup_address_in_pgd(pgd, hva, &level);

	if (!pte) {
		pr_info("Can't dump RMP entry for HVA %lx: no PTE/PFN found\n", hva);
		return;
	}

	dump_rmpentry(pte_pfn(*pte));
}
EXPORT_SYMBOL_GPL(snp_dump_hva_rmpentry);
