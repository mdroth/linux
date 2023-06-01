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
	union {
		struct {
			u64	assigned	: 1,
				pagesize	: 1,
				immutable	: 1,
				rsvd1		: 9,
				gpa		: 39,
				asid		: 10,
				vmsa		: 1,
				validated	: 1,
				rsvd2		: 1;
		} info;
		u64 low;
	};
	u64 high;
} __packed;

/*
 * The first 16KB from the RMP_BASE is used by the processor for the
 * bookkeeping, the range needs to be added during the RMP entry lookup.
 */
#define RMPTABLE_CPU_BOOKKEEPING_SZ	0x4000
#define RMPENTRY_SHIFT			8
#define rmptable_page_offset(x)	(RMPTABLE_CPU_BOOKKEEPING_SZ +		\
				 (((unsigned long)x) >> RMPENTRY_SHIFT))

static unsigned long rmptable_start __ro_after_init;
static unsigned long rmptable_end __ro_after_init;

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

static bool get_rmptable_info(u64 *start, u64 *len)
{
	u64 calc_rmp_sz, rmp_sz, rmp_base, rmp_end;

	rdmsrl(MSR_AMD64_RMP_BASE, rmp_base);
	rdmsrl(MSR_AMD64_RMP_END, rmp_end);

	if (!rmp_base || !rmp_end) {
		pr_err("Memory for the RMP table has not been reserved by BIOS\n");
		return false;
	}

	rmp_sz = rmp_end - rmp_base + 1;

	/*
	 * Calculate the amount the memory that must be reserved by the BIOS to
	 * address the whole RAM. The reserved memory should also cover the
	 * RMP table itself.
	 */
	calc_rmp_sz = (max_pfn << 4) + RMPTABLE_CPU_BOOKKEEPING_SZ;

	if (calc_rmp_sz > rmp_sz) {
		pr_err("Memory reserved for the RMP table does not cover full system RAM (expected 0x%llx got 0x%llx)\n",
		       calc_rmp_sz, rmp_sz);
		return false;
	}

	*start = rmp_base;
	*len = rmp_sz;

	pr_info("RMP table physical address [0x%016llx - 0x%016llx]\n", rmp_base, rmp_end);

	return true;
}

static __init int __snp_rmptable_init(void)
{
	u64 rmp_base, sz;
	void *start;
	u64 val;

	if (!get_rmptable_info(&rmp_base, &sz))
		return 1;

	start = memremap(rmp_base, sz, MEMREMAP_WB);
	if (!start) {
		pr_err("Failed to map RMP table addr 0x%llx size 0x%llx\n", rmp_base, sz);
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
	memset(start, 0, sz);

	/* Flush the caches to ensure that data is written before SNP is enabled. */
	wbinvd_on_all_cpus();

	/* MFDM must be enabled on all the CPUs prior to enabling SNP. */
	on_each_cpu(mfd_enable, NULL, 1);

	/* Enable SNP on all CPUs. */
	on_each_cpu(snp_enable, NULL, 1);

skip_enable:
	rmptable_start = (unsigned long)start;
	rmptable_end = rmptable_start + sz - 1;

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
	if (family != 0x19 || model > 0xaf)
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

static inline unsigned int rmpentry_assigned(struct rmpentry *e)
{
	return e->info.assigned;
}

static inline unsigned int rmpentry_pagesize(struct rmpentry *e)
{
	return e->info.pagesize;
}

static struct rmpentry *rmptable_entry(unsigned long paddr)
{
	unsigned long vaddr;

	vaddr = rmptable_start + rmptable_page_offset(paddr);
	if (unlikely(vaddr > rmptable_end))
		return ERR_PTR(-EFAULT);

	return (struct rmpentry *)vaddr;
}

static struct rmpentry *__snp_lookup_rmpentry(u64 pfn, int *level)
{
	unsigned long paddr = pfn << PAGE_SHIFT;
	struct rmpentry *entry, *large_entry;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return ERR_PTR(-ENXIO);

	if (!pfn_valid(pfn))
		return ERR_PTR(-EINVAL);

	entry = rmptable_entry(paddr);
	if (IS_ERR(entry))
		return entry;

	/* Read a large RMP entry to get the correct page level used in RMP entry. */
	large_entry = rmptable_entry(paddr & PMD_MASK);
	*level = RMP_TO_X86_PG_LEVEL(rmpentry_pagesize(large_entry));

	return entry;
}

void sev_dump_rmpentry(u64 pfn)
{
	unsigned long pfn_end;
	struct rmpentry *e;
	int level;

	e = __snp_lookup_rmpentry(pfn, &level);
	if (IS_ERR(e)) {
		pr_info("Failed to read RMP entry for PFN 0x%llx\n", pfn);
		return;
	}

	if (rmpentry_assigned(e)) {
		pr_info("RMPEntry paddr 0x%llx: [high=0x%016llx low=0x%016llx]\n",
			pfn << PAGE_SHIFT, e->high, e->low);
		return;
	}

	/*
	 * If the RMP entry at the faulting pfn was not assigned, then not sure
	 * what caused the RMP violation. To get some useful debug information,
	 * iterate through the entire 2MB region, and dump the RMP entries if
	 * one of the bit in the RMP entry is set.
	 */
	pfn = pfn & ~(PTRS_PER_PMD - 1);
	pfn_end = pfn + PTRS_PER_PMD;

	while (pfn < pfn_end) {
		e = __snp_lookup_rmpentry(pfn, &level);
		if (IS_ERR(e)) {
			pr_info("Failed to read RMP entry for PFN 0x%llx\n", pfn);
			pfn++;
			continue;
		}

		if (e->low || e->high)
			pr_info("RMPEntry paddr 0x%llx: [high=0x%016llx low=0x%016llx]\n",
				pfn << PAGE_SHIFT, e->high, e->low);
		pfn++;
	}
}
EXPORT_SYMBOL_GPL(sev_dump_rmpentry);

void sev_dump_rmpentry_pfn(u64 pfn, char *s)
{
	struct rmpentry *e;
	int level;

	e = __snp_lookup_rmpentry(pfn, &level);
	if (!e) {
		pr_info("failed to read RMP entry pfn 0x%llx\n", pfn);
		return;
	}

	pr_info("%s: RMPEntry paddr 0x%llx [assigned=%d immutable=%d pagesize=%d gpa=0x%lx"
		" asid=%d vmsa=%d validated=%d]\n", s, pfn << PAGE_SHIFT,
		rmpentry_assigned(e), e->info.immutable, rmpentry_pagesize(e),
		(unsigned long)e->info.gpa, e->info.asid, e->info.vmsa,
		e->info.validated);
	return;
}
EXPORT_SYMBOL_GPL(sev_dump_rmpentry_pfn);

/*
 * Return 1 if the RMP entry is assigned, 0 if it exists but is not assigned,
 * and -errno if there is no corresponding RMP entry.
 */
int snp_lookup_rmpentry(u64 pfn, int *level)
{
	struct rmpentry *e;

	e = __snp_lookup_rmpentry(pfn, level);
	if (IS_ERR(e))
		return PTR_ERR(e);

	return !!rmpentry_assigned(e);
}
EXPORT_SYMBOL_GPL(snp_lookup_rmpentry);

/*
 * psmash is used to smash a 2MB aligned page into 4K
 * pages while preserving the Validated bit in the RMP.
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

	pr_debug("%s: GPA: 0x%llx, PFN: 0x%llx, level: %d, immutable: %d\n",
		 __func__, gpa, pfn, level, immutable);

	if (!pfn_valid(pfn))
		return -EINVAL;

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

	pr_debug("%s: PFN: 0x%llx, level: %d\n", __func__, pfn, level);

	if (!pfn_valid(pfn))
		return -EINVAL;

	memset(&val, 0, sizeof(val));
	val.pagesize = X86_TO_RMP_PG_LEVEL(level);

	return rmpupdate(pfn, &val);
}
EXPORT_SYMBOL_GPL(rmp_make_shared);

/*
 * Return gpa of the RMP entry if assigned to guest
 */
u64 snp_rmpentry_get_gpa(u64 pfn, int *level, unsigned int asid)
{
	struct rmpentry *e;

	e = __snp_lookup_rmpentry(pfn, level);
	if (IS_ERR(e))
		return 0;

	if (rmpentry_assigned(e) && (!asid || e->info.asid == asid))
		return (e->info.gpa << PAGE_SHIFT);

	return 0;
}
EXPORT_SYMBOL_GPL(snp_rmpentry_get_gpa);
