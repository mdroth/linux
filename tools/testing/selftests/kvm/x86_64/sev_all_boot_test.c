// SPDX-License-Identifier: GPL-2.0-only
/*
 * Basic SEV boot tests.
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

#define VCPU_ID			2
#define PAGE_SIZE		4096
#define PAGE_STRIDE		32

#define SHARED_PAGES		8192
#define SHARED_VADDR_MIN	0x1000000

#define PRIVATE_PAGES		2048
#define PRIVATE_VADDR_MIN	(SHARED_VADDR_MIN + SHARED_PAGES * PAGE_SIZE)

#define TOTAL_PAGES		(512 + SHARED_PAGES + PRIVATE_PAGES)

static void fill_buf(uint8_t *buf, size_t pages, size_t stride, uint8_t val)
{
	int i, j;

	for (i = 0; i < pages; i++)
		for (j = 0; j < PAGE_SIZE; j += stride)
			buf[i * PAGE_SIZE + j] = val;
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

static void guest_test_start(struct ucall *uc)
{
	/* Initial guest check-in. */
	GUEST_SHARED_SYNC(uc, 1);
}

static void test_start(struct kvm_vm *vm, struct ucall *uc)
{
	vcpu_run(vm, VCPU_ID);

	/* Initial guest check-in. */
	CHECK_SHARED_SYNC(vm, VCPU_ID, uc, 1);
}

static void
guest_test_common(struct ucall *uc, uint8_t *shared_buf, uint8_t *private_buf)
{
	bool success;

	/* Initial check-in for common. */
	GUEST_SHARED_SYNC(uc, 100);

	/* Ensure initial shared pages are intact. */
	success = check_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x41);
	GUEST_SHARED_ASSERT(uc, success);

	/* Ensure initial private pages are intact/encrypted. */
	success = check_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x42);
	GUEST_SHARED_ASSERT(uc, success);

	/* Ensure host userspace can't read newly-written encrypted data. */
	fill_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x43);

	GUEST_SHARED_SYNC(uc, 101);

	/* Ensure guest can read newly-written shared data from host. */
	success = check_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x44);
	GUEST_SHARED_ASSERT(uc, success);

	/* Ensure host can read newly-written shared data from guest. */
	fill_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x45);

	GUEST_SHARED_SYNC(uc, 102);
}

static void
test_common(struct kvm_vm *vm, struct ucall *uc,
		  uint8_t *shared_buf, uint8_t *private_buf)
{
	bool success;

	/* Initial guest check-in. */
	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_SYNC(vm, VCPU_ID, uc, 100);

	/* Ensure initial private pages are intact/encrypted. */
	success = check_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x42);
	TEST_ASSERT(!success, "Initial guest memory not encrypted!");

	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_SYNC(vm, VCPU_ID, uc, 101);

	/* Ensure host userspace can't read newly-written encrypted data. */
	success = check_buf(private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x43);
	TEST_ASSERT(!success, "Modified guest memory not encrypted!");

	/* Ensure guest can read newly-written shared data from host. */
	fill_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x44);

	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_SYNC(vm, VCPU_ID, uc, 102);

	/* Ensure host can read newly-written shared data from guest. */
	success = check_buf(shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x45);
	TEST_ASSERT(success, "Host can't read shared guest memory!");
}

static void
guest_test_done(struct ucall *uc)
{
	GUEST_SHARED_DONE(uc);
}

static void
test_done(struct kvm_vm *vm, struct ucall *uc)
{
	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_DONE(vm, VCPU_ID, uc);
}

static void __attribute__((__flatten__))
guest_sev_code(struct ucall *uc, uint8_t *shared_buf, uint8_t *private_buf)
{
	uint32_t eax, ebx, ecx, edx;
	uint64_t sev_status;

	guest_test_start(uc);

	/* Check SEV CPUID bit. */
	eax = 0x8000001f;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);
	GUEST_SHARED_ASSERT(uc, eax & (1 << 1));

	/* Check SEV MSR bit. */
	sev_status = rdmsr(MSR_AMD64_SEV);
	GUEST_SHARED_ASSERT(uc, (sev_status & 0x1) == 1);

	guest_test_common(uc, shared_buf, private_buf);

	guest_test_done(uc);
}

static struct sev_vm *
setup_test_common(void *guest_code, uint64_t policy, struct ucall **uc,
		  uint8_t **shared_buf, uint8_t **private_buf)
{
	vm_vaddr_t uc_vaddr, shared_vaddr, private_vaddr;
	uint8_t measurement[512];
	struct sev_vm *sev;
	struct kvm_vm *vm;
	int i;

	sev = sev_vm_create(policy, TOTAL_PAGES);
	if (!sev)
		return NULL;
	vm = sev_get_vm(sev);

	/* Set up VCPU and initial guest kernel. */
	vm_vcpu_add_default(vm, VCPU_ID, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name);

	/* Set up shared ucall buffer. */
	uc_vaddr = ucall_shared_alloc(vm, 1);

	/* Set up buffer for reserved shared memory. */
	shared_vaddr = vm_vaddr_alloc_shared(vm, SHARED_PAGES * PAGE_SIZE,
					     SHARED_VADDR_MIN);
	*shared_buf = addr_gva2hva(vm, shared_vaddr);
	fill_buf(*shared_buf, SHARED_PAGES, PAGE_STRIDE, 0x41);

	/* Set up buffer for reserved private memory. */
	private_vaddr = vm_vaddr_alloc(vm, PRIVATE_PAGES * PAGE_SIZE,
				       PRIVATE_VADDR_MIN);
	*private_buf = addr_gva2hva(vm, private_vaddr);
	fill_buf(*private_buf, PRIVATE_PAGES, PAGE_STRIDE, 0x42);

	/* Set up guest params. */
	vcpu_args_set(vm, VCPU_ID, 4, uc_vaddr, shared_vaddr, private_vaddr);

	/*
	 * Hand these back to test harness, translation is needed now since page
	 * table will be encrypted after SEV VM launch.
	 */
	*uc = addr_gva2hva(vm, uc_vaddr);
	*shared_buf = addr_gva2hva(vm, shared_vaddr);
	*private_buf = addr_gva2hva(vm, private_vaddr);

	/* Allocations/setup done. Encrypt initial guest payload. */
	sev_vm_launch(sev);

	/* Dump the initial measurement. A test to actually verify it would be nice. */
	sev_vm_launch_measure(sev, measurement);
	pr_info("guest measurement: ");
	for (i = 0; i < 32; ++i)
		pr_info("%02x", measurement[i]);
	pr_info("\n");

	sev_vm_launch_finish(sev);

	return sev;
}

static void test_sev(void *guest_code, uint64_t policy)
{
	uint8_t *shared_buf, *private_buf;
	struct sev_vm *sev;
	struct kvm_vm *vm;
	struct ucall *uc;

	sev = setup_test_common(guest_code, policy, &uc, &shared_buf, &private_buf);
	if (!sev)
		return;
	vm = sev_get_vm(sev);

	/* Guest is ready to run. Do the tests. */
	test_start(vm, uc);
	test_common(vm, uc, shared_buf, private_buf);
	test_done(vm, uc);

	sev_vm_free(sev);
}

int main(int argc, char *argv[])
{
	/* SEV tests */
	test_sev(guest_sev_code, SEV_POLICY_NO_DBG);
	test_sev(guest_sev_code, 0);

	return 0;
}
