// SPDX-License-Identifier: GPL-2.0-only
/*
 * SEV-SNP tests for pvalidate and page-state changes.
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"
#include "sev_exitlib.h"

#define VCPU_ID			0
#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_STRIDE		64

/* NOTE: private/shared pages must each number at least 4 and be power of 2. */

#define SHARED_PAGES		512
#define SHARED_VADDR_MIN	0x1000000

#define PRIVATE_PAGES		512
#define PRIVATE_VADDR_MIN	(SHARED_VADDR_MIN + SHARED_PAGES * PAGE_SIZE)

#define TOTAL_PAGES		(512 + SHARED_PAGES + PRIVATE_PAGES)
#define LINEAR_MAP_GVA		(PRIVATE_VADDR_MIN + PRIVATE_PAGES * PAGE_SIZE)

struct pageTableEntry {
	uint64_t present:1;
	uint64_t ignored_11_01:11;
	uint64_t pfn:40;
	uint64_t ignored_63_52:12;
};

/* Globals for use by #VC handler and helpers. */
static int page_not_validated_count;
static struct sev_sync_data *guest_sync;
static uint8_t enc_bit;

static void fill_buf(uint8_t *buf, size_t pages, size_t stride, uint8_t val)
{
	int i, j;

	for (i = 0; i < pages; i++)
		for (j = 0; j < PAGE_SIZE; j += stride)
			buf[i * PAGE_SIZE + j] = val;
}

static bool check_buf_nostop(uint8_t *buf, size_t pages, size_t stride, uint8_t val)
{
	bool matches = true;
	int i, j;

	for (i = 0; i < pages; i++)
		for (j = 0; j < PAGE_SIZE; j += stride)
			if (buf[i * PAGE_SIZE + j] != val)
				matches = false;
	return matches;
}

static bool check_buf(uint8_t *buf, size_t pages, size_t stride, uint8_t val)
{
	int i, j;

	for (i = 0; i < pages; i++)
		for (j = 0; j < PAGE_SIZE; j += stride)
			if (buf[i * PAGE_SIZE + j] != val)
				return false;

	return true;
}

static void vc_handler(struct ex_regs *regs)
{
	int ret;

	if (regs->error_code == SVM_EXIT_NOT_VALIDATED) {
		unsigned long gva;

		page_not_validated_count++;

		asm volatile("mov %%cr2,%0" : "=r" (gva));
		ret = snp_pvalidate((void *)gva, 0, true);
		SEV_GUEST_ASSERT(guest_sync, 9001, !ret);

		return;
	}

	ret = sev_es_handle_vc(NULL, 0, regs);
	SEV_GUEST_ASSERT(guest_sync, 20000 + regs->error_code, !ret);
}

#define gpa_mask(gpa) (gpa & ~(1ULL << enc_bit))
#define gfn_mask(gfn) (gfn & ~((1ULL << enc_bit) >> PAGE_SHIFT))
#define va(gpa) ((void *)(LINEAR_MAP_GVA + (gpa & ~(1ULL << enc_bit))))
#define gfn2va(gfn) va(gfn_mask(gfn) * PAGE_SIZE)

static void set_pte_bit(void *ptr, uint8_t pos, bool enable)
{
	struct pageTableEntry *pml4e, *pdpe, *pde, *pte;
	uint16_t index[4];
	uint64_t *pte_val;
	uint64_t gva = (uint64_t)ptr;

	index[0] = (gva >> 12) & 0x1FFU;
	index[1] = (gva >> 21) & 0x1FFU;
	index[2] = (gva >> 30) & 0x1FFU;
	index[3] = (gva >> 39) & 0x1FFU;

	pml4e = (struct pageTableEntry *)va(gpa_mask(get_cr3()));
	SEV_GUEST_ASSERT(guest_sync, 1001, pml4e[index[3]].present);

	pdpe = (struct pageTableEntry *)gfn2va(pml4e[index[3]].pfn);
	SEV_GUEST_ASSERT(guest_sync, 1002, pdpe[index[2]].present);

	pde = (struct pageTableEntry *)gfn2va(pdpe[index[2]].pfn);
	SEV_GUEST_ASSERT(guest_sync, 1003, pde[index[1]].present);

	pte = (struct pageTableEntry *)gfn2va(pde[index[1]].pfn);
	SEV_GUEST_ASSERT(guest_sync, 1004, pte[index[0]].present);

	pte_val = (uint64_t *)&pte[index[0]];
	if (enable)
		*pte_val |= (1UL << pos);
	else
		*pte_val &= ~(1UL << pos);

	asm volatile("invlpg (%0)" ::"r" (gva) : "memory");
}

static void guest_test_psc(uint64_t shared_buf_gpa, uint8_t *shared_buf,
			   uint64_t private_buf_gpa, uint8_t *private_buf)
{
	bool success;
	int rc, i;

	sev_guest_sync(guest_sync, 100, 0);

	/* Flip 1st half of private pages to shared and verify VMM can read them. */
	for (i = 0; i < (PRIVATE_PAGES / 2); i++) {
		rc = snp_pvalidate(&private_buf[i * PAGE_SIZE], 0, false);
		SEV_GUEST_ASSERT(guest_sync, 101, !rc);
		snp_psc_set_shared(private_buf_gpa + i * PAGE_SIZE);
		set_pte_bit(&private_buf[i * PAGE_SIZE], enc_bit, false);
	}
	fill_buf(private_buf, PRIVATE_PAGES / 2, PAGE_STRIDE, 0x43);

	sev_guest_sync(guest_sync, 200, 0);

	/*
	 * Flip 2nd half of private pages to shared and hand them to the VMM.
	 *
	 * This time leave the C-bit set, which should cause a 0x404
	 * (PAGE_NOT_VALIDATED) #VC when guest later attempts to access each
	 * page.
	 */
	for (i = PRIVATE_PAGES / 2; i < PRIVATE_PAGES; i++) {
		rc = snp_pvalidate(&private_buf[i * PAGE_SIZE], 0, false);
		if (rc)
			sev_guest_abort(guest_sync, rc, 0);
		snp_psc_set_shared(private_buf_gpa + i * PAGE_SIZE);
	}

	sev_guest_sync(guest_sync, 300, 0);

	/*
	 * VMM has filled up the newly-shared pages, but C-bit is still set, so
	 * verify the contents still show up as encrypted, and make sure to
	 * access each to verify #VC records the PAGE_NOT_VALIDATED exceptions.
	 */
	WRITE_ONCE(page_not_validated_count, 0);
	success = check_buf_nostop(&private_buf[(PRIVATE_PAGES / 2) * PAGE_SIZE],
				   PRIVATE_PAGES / 2, PAGE_STRIDE, 0x44);
	SEV_GUEST_ASSERT(guest_sync, 301, !success);
	SEV_GUEST_ASSERT(guest_sync, 302,
			 READ_ONCE(page_not_validated_count) == (PRIVATE_PAGES / 2));

	/* Now flip the C-bit off and verify the VMM-provided values are intact. */
	for (i = PRIVATE_PAGES / 2; i < PRIVATE_PAGES; i++)
		set_pte_bit(&private_buf[i * PAGE_SIZE], enc_bit, false);
	success = check_buf(&private_buf[(PRIVATE_PAGES / 2) * PAGE_SIZE],
			    PRIVATE_PAGES / 2, PAGE_STRIDE, 0x44);
	SEV_GUEST_ASSERT(guest_sync, 303, success);

	/* Flip the 1st half back to private pages. */
	for (i = 0; i < (PRIVATE_PAGES / 2); i++) {
		snp_psc_set_private(private_buf_gpa + i * PAGE_SIZE);
		set_pte_bit(&private_buf[i * PAGE_SIZE], enc_bit, true);
		rc = snp_pvalidate(&private_buf[i * PAGE_SIZE], 0, true);
		SEV_GUEST_ASSERT(guest_sync, 304, !rc);
	}
	/* Pages are private again, write over them with new encrypted data. */
	fill_buf(private_buf, PRIVATE_PAGES / 2, PAGE_STRIDE, 0x45);

	sev_guest_sync(guest_sync, 400, 0);

	/*
	 * Take some private pages and flip the C-bit off. Subsequent access
	 * should cause an RMP fault, which should lead to the VMM doing a
	 * PSC to shared on our behalf.
	 */
	for (i = 0; i < (PRIVATE_PAGES / 4); i++)
		set_pte_bit(&private_buf[i * PAGE_SIZE], enc_bit, false);
	fill_buf(private_buf, PRIVATE_PAGES / 4, PAGE_STRIDE, 0x46);

	sev_guest_sync(guest_sync, 500, 0);

	/* Flip all even-numbered shared pages to private. */
	for (i = 0; i < SHARED_PAGES; i++) {
		if ((i % 2) != 0)
			continue;

		snp_psc_set_private(shared_buf_gpa + i * PAGE_SIZE);
		set_pte_bit(&shared_buf[i * PAGE_SIZE], enc_bit, true);
		rc = snp_pvalidate(&shared_buf[i * PAGE_SIZE], 0, true);
		SEV_GUEST_ASSERT(guest_sync, 501, !rc);
	}

	/* Write across the entire range and hand it back to VMM to verify. */
	fill_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x47);

	sev_guest_sync(guest_sync, 600, 0);
}

static void check_test_psc(struct kvm_vm *vm, struct sev_sync_data *sync,
			   uint8_t *shared_buf, uint8_t *private_buf)
{
	struct kvm_run *run = vcpu_state(vm, VCPU_ID);
	bool success;
	int i;

	/* Initial check-in for PSC tests. */
	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 100);

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 200);

	/* 1st half of private buffer should be shared now, check contents. */
	success = check_buf(private_buf, PRIVATE_PAGES / 2, PAGE_STRIDE, 0x43);
	TEST_ASSERT(success, "Unexpected contents in newly-shared buffer.");

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 300);

	/* 2nd half of private buffer should be shared now, write to it. */
	fill_buf(&private_buf[(PRIVATE_PAGES / 2) * PAGE_SIZE],
		 PRIVATE_PAGES / 2, PAGE_STRIDE, 0x44);

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 400);

	/* 1st half of private buffer should no longer be shared. Verify. */
	success = check_buf(private_buf, PRIVATE_PAGES / 2, PAGE_STRIDE, 0x45);
	TEST_ASSERT(!success, "Unexpected contents in newly-private buffer.");

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 500);

	/* 1st quarter of private buffer should be shared again. Verify. */
	success = check_buf(private_buf, PRIVATE_PAGES / 4, PAGE_STRIDE, 0x46);
	TEST_ASSERT(success, "Unexpected contents in newly-shared buffer.");

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 600);

	/* Verify even-numbered pages in shared_buf are now private. */
	for (i = 0; i < SHARED_PAGES; i++) {
		success = check_buf(&shared_buf[i * PAGE_SIZE], 1, PAGE_STRIDE, 0x47);
		if ((i % 2) == 0)
			TEST_ASSERT(!success, "Private buffer contains plain-text.");
		else
			TEST_ASSERT(success, "Shared buffer contains cipher-text.");
	}
}

static void __attribute__((__flatten__))
guest_code(struct sev_sync_data *sync, uint64_t shared_buf_gpa, uint8_t *shared_buf,
	   uint64_t private_buf_gpa, uint8_t *private_buf)
{
	uint32_t eax, ebx, ecx, edx;

	/* Initial check-in. */
	guest_sync = sync;
	sev_guest_sync(guest_sync, 1, 0);

	/* Get encryption bit via CPUID. */
	eax = 0x8000001f;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);
	enc_bit = ebx & 0x3F;

	/* Do the tests. */
	guest_test_psc(shared_buf_gpa, shared_buf, private_buf_gpa, private_buf);

	sev_guest_done(guest_sync, 10000, 0);
}

int main(int argc, char *argv[])
{
	vm_vaddr_t shared_vaddr, private_vaddr, sync_vaddr;
	uint8_t *shared_buf, *private_buf;
	struct sev_sync_data *sync;
	struct kvm_run *run;
	struct sev_vm *sev;
	struct kvm_vm *vm;

	/* Create VM and main memslot/region. */
	sev = sev_snp_vm_create(SNP_POLICY_SMT, TOTAL_PAGES);
	if (!sev)
		exit(KSFT_SKIP);
	vm = sev_get_vm(sev);

	/* Set up VCPU and #VC handler. */
	vm_vcpu_add_default(vm, VCPU_ID, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name);
	vm_init_descriptor_tables(vm);
	vm_install_exception_handler(vm, 29, vc_handler);
	vcpu_init_descriptor_tables(vm, VCPU_ID);

	/* Set up shared page for sync buffer. */
	sync_vaddr = vm_vaddr_alloc_shared(vm, PAGE_SIZE, 0);
	sync = addr_gva2hva(vm, sync_vaddr);

	/* Set up additional buffer for reserved shared memory. */
	shared_vaddr = vm_vaddr_alloc_shared(vm, SHARED_PAGES * PAGE_SIZE,
					     SHARED_VADDR_MIN);
	shared_buf = addr_gva2hva(vm, shared_vaddr);
	memset(shared_buf, 0, SHARED_PAGES * PAGE_SIZE);

	/* Set up additional buffer for reserved private memory. */
	private_vaddr = vm_vaddr_alloc(vm, PRIVATE_PAGES * PAGE_SIZE,
				       PRIVATE_VADDR_MIN);
	private_buf = addr_gva2hva(vm, private_vaddr);
	memset(private_buf, 0, PRIVATE_PAGES * PAGE_SIZE);

	/*
	 * Create a linear mapping of all guest memory. This will map all pages
	 * as encrypted, which is okay in this case, because the linear mapping
	 * will only be used to access page tables, which are always treated
	 * as encrypted.
	 */
	virt_map(vm, LINEAR_MAP_GVA, 1UL << sev_get_enc_bit(sev), TOTAL_PAGES);

	/* Set up guest params. */
	vcpu_args_set(vm, VCPU_ID, 5, sync_vaddr,
		      addr_gva2gpa(vm, shared_vaddr), shared_vaddr,
		      addr_gva2gpa(vm, private_vaddr), private_vaddr);

	/* Encrypt initial guest payload and prepare to run it. */
	sev_snp_vm_launch(sev);

	/* Initial guest check-in. */
	run = vcpu_state(vm, VCPU_ID);
	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 1);

	/* Do the tests. */
	check_test_psc(vm, sync, shared_buf, private_buf);

	/* Wait for guest to finish up. */
	vcpu_run(vm, VCPU_ID);
	sev_check_guest_done(run, sync, 10000);

	sev_snp_vm_free(sev);

	return 0;
}
