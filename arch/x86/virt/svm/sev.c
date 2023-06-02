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
#define PFN_PMD_MASK	(~((1ULL << (PMD_SHIFT - PAGE_SHIFT)) - 1))

static struct rmpentry *rmptable_start __ro_after_init;
static u64 rmptable_max_pfn __ro_after_init;

/* list of pages which are leaked and cannot be reclaimed */
static LIST_HEAD(snp_leaked_pages_list);
static DEFINE_SPINLOCK(snp_leaked_pages_list_lock);

static atomic_long_t snp_nr_leaked_pages = ATOMIC_LONG_INIT(0);

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

bool snp_get_rmptable_info(u64 *start, u64 *len)
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

	*start = rmp_base;
	*len = rmp_sz;

	return true;
}

static __init int __snp_rmptable_init(void)
{
	u64 rmp_base, rmp_size;
	void *rmp_start;
	u64 val;

	if (!snp_get_rmptable_info(&rmp_base, &rmp_size))
		return 1;

	pr_info("RMP table physical address [0x%016llx - 0x%016llx]\n",
		rmp_base, rmp_base + rmp_size - 1);

	rmp_start = memremap(rmp_base, rmp_size, MEMREMAP_WB);
	if (!rmp_start) {
		pr_err("Failed to map RMP table addr 0x%llx size 0x%llx\n", rmp_base, rmp_size);
		return 1;
	}

	/*
	 * Check if SEV-SNP is already enabled, this can happen in case of
	 * kexec boot.
	 */
	rdmsrl(MSR_AMD64_SYSCFG, val);
	if (val & MSR_AMD64_SYSCFG_SNP_EN)
		goto skip_enable;

	/* Initialize the RMP table to zero */
	memset(rmp_start, 0, rmp_size);

	/* Flush the caches to ensure that data is written before SNP is enabled. */
	wbinvd_on_all_cpus();

	/* MFDM must be enabled on all the CPUs prior to enabling SNP. */
	on_each_cpu(mfd_enable, NULL, 1);

	/* Enable SNP on all CPUs. */
	on_each_cpu(snp_enable, NULL, 1);

skip_enable:
	rmp_start += RMPTABLE_CPU_BOOKKEEPING_SZ;
	rmp_size -= RMPTABLE_CPU_BOOKKEEPING_SZ;

	rmptable_start = (struct rmpentry *)rmp_start;
	rmptable_max_pfn = rmp_size / sizeof(struct rmpentry) - 1;

	return 0;
}

static int __init snp_rmptable_init(void)
{
	int family, model;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return 0;

	family = boot_cpu_data.x86;
	model  = boot_cpu_data.x86_model;

	/*
	 * RMP table entry format is not architectural and it can vary by processor and
	 * is defined by the per-processor PPR. Restrict SNP support on the known CPU
	 * model and family for which the RMP table entry format is currently defined for.
	 */
	if (!(family == 0x19 && model <= 0xaf) && !(family == 0x1a && model <= 0xf))
		goto nosnp;

	if (amd_iommu_snp_enable())
		goto nosnp;

	if (__snp_rmptable_init())
		goto nosnp;

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/rmptable_init:online", __snp_enable, NULL);

	return 0;

nosnp:
	setup_clear_cpu_cap(X86_FEATURE_SEV_SNP);
	return -ENOSYS;
}

/*
 * This must be called after the PCI subsystem. This is because amd_iommu_snp_enable()
 * is called to ensure the IOMMU supports the SEV-SNP feature, which can only be
 * called after subsys_initcall().
 *
 * NOTE: IOMMU is enforced by SNP to ensure that hypervisor cannot program DMA
 * directly into guest private memory. In case of SNP, the IOMMU ensures that
 * the page(s) used for DMA are hypervisor owned.
 */
fs_initcall(snp_rmptable_init);

static int rmptable_entry(u64 pfn, struct rmpentry *entry)
{
	if (WARN_ON_ONCE(pfn > rmptable_max_pfn))
		return -EFAULT;

	*entry = rmptable_start[pfn];

	return 0;
}

static int __snp_lookup_rmpentry(u64 pfn, struct rmpentry *entry, int *level)
{
	struct rmpentry large_entry;
	int ret;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	ret = rmptable_entry(pfn, entry);
	if (ret)
		return ret;

	/*
	 * Find the authoritative RMP entry for a PFN. This can be either a 4K
	 * RMP entry or a special large RMP entry that is authoritative for a
	 * whole 2M area.
	 */
	ret = rmptable_entry(pfn & PFN_PMD_MASK, &large_entry);
	if (ret)
		return ret;

	*level = RMP_TO_X86_PG_LEVEL(large_entry.pagesize);

	return 0;
}

int snp_lookup_rmpentry(u64 pfn, bool *assigned, int *level)
{
	struct rmpentry e;
	int ret;

	ret = __snp_lookup_rmpentry(pfn, &e, level);
	if (ret)
		return ret;

	*assigned = !!e.assigned;
	return 0;
}
EXPORT_SYMBOL_GPL(snp_lookup_rmpentry);

/*
 * Dump the raw RMP entry for a particular PFN. These bits are documented in the
 * PPR for a particular CPU model and provide useful information about how a
 * particular PFN is being utilized by the kernel/firmware at the time certain
 * unexpected events occur, such as RMP faults.
 */
static void sev_dump_rmpentry(u64 dumped_pfn)
{
	struct rmpentry e;
	u64 pfn, pfn_end;
	int level, ret;
	u64 *e_data;

	ret = __snp_lookup_rmpentry(dumped_pfn, &e, &level);
	if (ret) {
		pr_info("Failed to read RMP entry for PFN 0x%llx, error %d\n",
			dumped_pfn, ret);
		return;
	}

	e_data = (u64 *)&e;
	if (e.assigned) {
		pr_info("RMP entry for PFN 0x%llx: [high=0x%016llx low=0x%016llx]\n",
			dumped_pfn, e_data[1], e_data[0]);
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
	pfn = ALIGN(dumped_pfn, PTRS_PER_PMD);
	pfn_end = pfn + PTRS_PER_PMD;

	while (pfn < pfn_end) {
		ret = __snp_lookup_rmpentry(pfn, &e, &level);
		if (ret) {
			pr_info_ratelimited("Failed to read RMP entry for PFN 0x%llx\n", pfn);
			pfn++;
			continue;
		}

		if (e_data[0] || e_data[1]) {
			pr_info("No assigned RMP entry for PFN 0x%llx, but the 2MB region contains populated RMP entries, e.g.: PFN 0x%llx: [high=0x%016llx low=0x%016llx]\n",
				dumped_pfn, pfn, e_data[1], e_data[0]);
			return;
		}
		pfn++;
	}

	pr_info("No populated RMP entries in the 2MB region containing PFN 0x%llx\n",
		dumped_pfn);
}

void sev_dump_hva_rmpentry(unsigned long hva)
{
	unsigned int level;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd += pgd_index(hva);
	pte = lookup_address_in_pgd(pgd, hva, &level);

	if (pte) {
		pr_info("Can't dump RMP entry for HVA %lx: no PTE/PFN found\n", hva);
		return;
	}

	sev_dump_rmpentry(pte_pfn(*pte));
}
EXPORT_SYMBOL_GPL(sev_dump_hva_rmpentry);

/*
 * PSMASH a 2MB aligned page into 4K pages in the RMP table while preserving the
 * Validated bit.
 */
int psmash(u64 pfn)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret;

	pr_debug("%s: PFN: 0x%llx\n", __func__, pfn);

	if (!pfn_valid(pfn))
		return -EINVAL;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	/* Binutils version 2.36 supports the PSMASH mnemonic. */
	asm volatile(".byte 0xF3, 0x0F, 0x01, 0xFF"
		      : "=a"(ret)
		      : "a"(paddr)
		      : "memory", "cc");

	return ret;
}
EXPORT_SYMBOL_GPL(psmash);

static int restore_direct_map(u64 pfn, int npages)
{
	int i, ret = 0;

	for (i = 0; i < npages; i++) {
		ret = set_direct_map_default_noflush(pfn_to_page(pfn + i));
		if (ret)
			break;
	}

	if (ret)
		pr_warn("Failed to restore direct map for pfn 0x%llx, ret: %d\n",
			pfn + i, ret);

	return ret;
}

static int invalidate_direct_map(u64 pfn, int npages)
{
	int i, ret = 0;

	for (i = 0; i < npages; i++) {
		ret = set_direct_map_invalid_noflush(pfn_to_page(pfn + i));
		if (ret)
			break;
	}

	if (ret) {
		pr_warn("Failed to invalidate direct map for pfn 0x%llx, ret: %d\n",
			pfn + i, ret);
		restore_direct_map(pfn, i);
	}

	return ret;
}

static int rmpupdate(u64 pfn, struct rmp_state *val)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	int ret, level, npages;
	int attempts = 0;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENXIO;

	level = RMP_TO_X86_PG_LEVEL(val->pagesize);
	npages = page_level_size(level) / PAGE_SIZE;

	/*
	 * If page is getting assigned in the RMP table then unmap it from the
	 * direct map.
	 */
	if (val->assigned) {
		if (invalidate_direct_map(pfn, npages)) {
			pr_err("Failed to unmap %d pages at pfn 0x%llx from the direct_map\n",
			       npages, pfn);
			return -EFAULT;
		}
	}

	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a"(ret)
			     : "a"(paddr), "c"((unsigned long)val)
			     : "memory", "cc");

		attempts++;
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	if (ret) {
		pr_err("RMPUPDATE failed after %d attempts, ret: %d, pfn: %llx, npages: %d, level: %d\n",
		       attempts, ret, pfn, npages, level);
		sev_dump_rmpentry(pfn);
		dump_stack();
		return -EFAULT;
	}

	/*
	 * Restore the direct map after the page is removed from the RMP table.
	 */
	if (!val->assigned) {
		if (restore_direct_map(pfn, npages)) {
			pr_err("Failed to map %d pages at pfn 0x%llx into the direct_map\n",
			       npages, pfn);
			return -EFAULT;
		}
	}

	return 0;
}

/*
 * Assign a page to guest using the RMPUPDATE instruction.
 */
int rmp_make_private(u64 pfn, u64 gpa, enum pg_level level, int asid, bool immutable)
{
	struct rmp_state val;

	memset(&val, 0, sizeof(val));
	val.assigned = 1;
	val.asid = asid;
	val.immutable = immutable;
	val.gpa = gpa;
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);

	return rmpupdate(pfn, &val);
}
EXPORT_SYMBOL_GPL(rmp_make_private);

/*
 * Transition a page to hypervisor/shared state using the RMPUPDATE instruction.
 */
int rmp_make_shared(u64 pfn, enum pg_level level)
{
	struct rmp_state val;

	memset(&val, 0, sizeof(val));
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);

	return rmpupdate(pfn, &val);
}
EXPORT_SYMBOL_GPL(rmp_make_shared);

void snp_leak_pages(u64 pfn, unsigned int npages)
{
	struct page *page = pfn_to_page(pfn);

	pr_debug("%s: leaking PFN range 0x%llx-0x%llx\n", __func__, pfn, pfn + npages);

	spin_lock(&snp_leaked_pages_list_lock);
	while (npages--) {
		/*
		 * Reuse the page's buddy list for chaining into the leaked
		 * pages list. This page should not be on a free list currently
		 * and is also unsafe to be added to a free list.
		 */
		list_add_tail(&page->buddy_list, &snp_leaked_pages_list);
		sev_dump_rmpentry(pfn);
		pfn++;
	}
	spin_unlock(&snp_leaked_pages_list_lock);
	atomic_long_inc(&snp_nr_leaked_pages);
}
EXPORT_SYMBOL_GPL(snp_leak_pages);
