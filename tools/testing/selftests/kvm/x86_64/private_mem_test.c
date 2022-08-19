// SPDX-License-Identifier: GPL-2.0
/*
 * tools/testing/selftests/kvm/lib/kvm_util.c
 *
 * Copyright (C) 2022, Google LLC.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/memfd.h>

#include <test_util.h>
#include <kvm_util.h>
#include <private_mem.h>
#include <processor.h>

#define VM_MEMSLOT0_PAGES	(512 * 10)

#define TEST_AREA_SLOT		10
#define TEST_AREA_GPA		0xC0000000
#define TEST_AREA_SIZE		(2 * 1024 * 1024)
#define GUEST_TEST_MEM_OFFSET	(1 * 1024 * 1024)
#define GUEST_TEST_MEM_SIZE	(10 * 4096)

#define VM_STAGE_PROCESSED(x)	pr_info("Processed stage %s\n", #x)

#define TEST_MEM_DATA_PAT1	0x66
#define TEST_MEM_DATA_PAT2	0x99
#define TEST_MEM_DATA_PAT3	0x33
#define TEST_MEM_DATA_PAT4	0xaa
#define TEST_MEM_DATA_PAT5	0x12

static bool verify_mem_contents(void *mem, uint32_t size, uint8_t pat)
{
	uint8_t *buf = (uint8_t *)mem;

	for (uint32_t i = 0; i < size; i++) {
		if (buf[i] != pat)
			return false;
	}

	return true;
}

/*
 * Add custom implementation for memset to avoid using standard/builtin memset
 * which may use features like SSE/GOT that don't work with guest vm execution
 * within selftests.
 */
void *memset(void *mem, int byte, size_t size)
{
	uint8_t *buf = (uint8_t *)mem;

	for (uint32_t i = 0; i < size; i++)
		buf[i] = byte;

	return buf;
}

static void populate_test_area(void *test_area_base, uint64_t pat)
{
	memset(test_area_base, pat, TEST_AREA_SIZE);
}

static void populate_guest_test_mem(void *guest_test_mem, uint64_t pat)
{
	memset(guest_test_mem, pat, GUEST_TEST_MEM_SIZE);
}

static bool verify_test_area(void *test_area_base, uint64_t area_pat,
	uint64_t guest_pat)
{
	void *test_area1_base = test_area_base;
	uint64_t test_area1_size = GUEST_TEST_MEM_OFFSET;
	void *guest_test_mem = test_area_base + test_area1_size;
	uint64_t guest_test_size = GUEST_TEST_MEM_SIZE;
	void *test_area2_base = guest_test_mem + guest_test_size;
	uint64_t test_area2_size = (TEST_AREA_SIZE - (GUEST_TEST_MEM_OFFSET +
			GUEST_TEST_MEM_SIZE));

	return (verify_mem_contents(test_area1_base, test_area1_size, area_pat) &&
		verify_mem_contents(guest_test_mem, guest_test_size, guest_pat) &&
		verify_mem_contents(test_area2_base, test_area2_size, area_pat));
}

#define GUEST_STARTED			0
#define GUEST_PRIVATE_MEM_POPULATED	1
#define GUEST_SHARED_MEM_POPULATED	2
#define GUEST_PRIVATE_MEM_POPULATED2	3
#define GUEST_IMPLICIT_MEM_CONV1	4
#define GUEST_IMPLICIT_MEM_CONV2	5

/*
 * Run memory conversion tests supporting two types of conversion:
 * 1) Explicit: Execute KVM hypercall to map/unmap gpa range which will cause
 *   userspace exit to back/unback private memory. Subsequent accesses by guest
 *   to the gpa range will not cause exit to userspace.
 * 2) Implicit: Execute KVM hypercall to update memory access to a gpa range as
 *   private/shared without exiting to userspace. Subsequent accesses by guest
 *   to the gpa range will result in KVM EPT/NPT faults and then exit to
 *   userspace for each page.
 *
 * Test memory conversion scenarios with following steps:
 * 1) Access private memory using private access and verify that memory contents
 *   are not visible to userspace.
 * 2) Convert memory to shared using explicit/implicit conversions and ensure
 *   that userspace is able to access the shared regions.
 * 3) Convert memory back to private using explicit/implicit conversions and
 *   ensure that userspace is again not able to access converted private
 *   regions.
 */
static void guest_conv_test_fn(bool test_explicit_conv)
{
	void *test_area_base = (void *)TEST_AREA_GPA;
	void *guest_test_mem = (void *)(TEST_AREA_GPA + GUEST_TEST_MEM_OFFSET);
	uint64_t guest_test_size = GUEST_TEST_MEM_SIZE;

	guest_map_ucall_page_shared();
	GUEST_SYNC(GUEST_STARTED);

	populate_test_area(test_area_base, TEST_MEM_DATA_PAT1);
	GUEST_SYNC(GUEST_PRIVATE_MEM_POPULATED);
	GUEST_ASSERT(verify_test_area(test_area_base, TEST_MEM_DATA_PAT1,
		TEST_MEM_DATA_PAT1));

	if (test_explicit_conv)
		guest_update_mem_map(TO_SHARED, (uint64_t)guest_test_mem,
			guest_test_size);
	else {
		guest_update_mem_access(TO_SHARED, (uint64_t)guest_test_mem,
			guest_test_size);
		GUEST_SYNC(GUEST_IMPLICIT_MEM_CONV1);
	}

	populate_guest_test_mem(guest_test_mem, TEST_MEM_DATA_PAT2);

	GUEST_SYNC(GUEST_SHARED_MEM_POPULATED);
	GUEST_ASSERT(verify_test_area(test_area_base, TEST_MEM_DATA_PAT1,
		TEST_MEM_DATA_PAT5));

	if (test_explicit_conv)
		guest_update_mem_map(TO_PRIVATE, (uint64_t)guest_test_mem,
			guest_test_size);
	else {
		guest_update_mem_access(TO_PRIVATE, (uint64_t)guest_test_mem,
			guest_test_size);
		GUEST_SYNC(GUEST_IMPLICIT_MEM_CONV2);
	}

	populate_guest_test_mem(guest_test_mem, TEST_MEM_DATA_PAT3);
	GUEST_SYNC(GUEST_PRIVATE_MEM_POPULATED2);

	GUEST_ASSERT(verify_test_area(test_area_base, TEST_MEM_DATA_PAT1,
		TEST_MEM_DATA_PAT3));
	GUEST_DONE();
}

static void conv_test_ioexit_fn(struct kvm_vm *vm, uint32_t uc_arg1)
{
	void *test_area_hva = addr_gpa2hva(vm, TEST_AREA_GPA);
	void *guest_test_mem_hva = (test_area_hva + GUEST_TEST_MEM_OFFSET);
	uint64_t guest_mem_gpa = (TEST_AREA_GPA + GUEST_TEST_MEM_OFFSET);
	uint64_t guest_test_size = GUEST_TEST_MEM_SIZE;

	switch (uc_arg1) {
	case GUEST_STARTED:
		populate_test_area(test_area_hva, TEST_MEM_DATA_PAT4);
		VM_STAGE_PROCESSED(GUEST_STARTED);
		break;
	case GUEST_PRIVATE_MEM_POPULATED:
		TEST_ASSERT(verify_test_area(test_area_hva, TEST_MEM_DATA_PAT4,
				TEST_MEM_DATA_PAT4), "failed");
		VM_STAGE_PROCESSED(GUEST_PRIVATE_MEM_POPULATED);
		break;
	case GUEST_SHARED_MEM_POPULATED:
		TEST_ASSERT(verify_test_area(test_area_hva, TEST_MEM_DATA_PAT4,
				TEST_MEM_DATA_PAT2), "failed");
		populate_guest_test_mem(guest_test_mem_hva, TEST_MEM_DATA_PAT5);
		VM_STAGE_PROCESSED(GUEST_SHARED_MEM_POPULATED);
		break;
	case GUEST_PRIVATE_MEM_POPULATED2:
		TEST_ASSERT(verify_test_area(test_area_hva, TEST_MEM_DATA_PAT4,
				TEST_MEM_DATA_PAT5), "failed");
		VM_STAGE_PROCESSED(GUEST_PRIVATE_MEM_POPULATED2);
		break;
	case GUEST_IMPLICIT_MEM_CONV1:
		/*
		 * For first implicit conversion, memory is already private so
		 * mark it private again just to zap the pte entries for the gpa
		 * range, so that subsequent accesses from the guest will
		 * generate ept/npt fault and memory conversion path will be
		 * exercised by KVM.
		 */
		vm_update_private_mem(vm, guest_mem_gpa, guest_test_size,
				ALLOCATE_MEM);
		VM_STAGE_PROCESSED(GUEST_IMPLICIT_MEM_CONV1);
		break;
	case GUEST_IMPLICIT_MEM_CONV2:
		/*
		 * For second implicit conversion, memory is already shared so
		 * mark it shared again just to zap the pte entries for the gpa
		 * range, so that subsequent accesses from the guest will
		 * generate ept/npt fault and memory conversion path will be
		 * exercised by KVM.
		 */
		vm_update_private_mem(vm, guest_mem_gpa, guest_test_size,
				UNBACK_MEM);
		VM_STAGE_PROCESSED(GUEST_IMPLICIT_MEM_CONV2);
		break;
	default:
		TEST_FAIL("Unknown stage %d\n", uc_arg1);
		break;
	}
}

static void guest_explicit_conv_test_fn(void)
{
	guest_conv_test_fn(true);
}

static void guest_implicit_conv_test_fn(void)
{
	guest_conv_test_fn(false);
}

static void execute_memory_conversion_test(void)
{
	struct vm_setup_info info;
	struct test_setup_info *test_info = &info.test_info;

	info.vm_mem_src = VM_MEM_SRC_ANONYMOUS;
	info.memslot0_pages = VM_MEMSLOT0_PAGES;
	test_info->test_area_gpa = TEST_AREA_GPA;
	test_info->test_area_size = TEST_AREA_SIZE;
	test_info->test_area_slot = TEST_AREA_SLOT;
	info.ioexit_cb = conv_test_ioexit_fn;

	info.guest_fn = guest_explicit_conv_test_fn;
	execute_vm_with_private_mem(&info);

	info.guest_fn = guest_implicit_conv_test_fn;
	execute_vm_with_private_mem(&info);
}

int main(int argc, char *argv[])
{
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	execute_memory_conversion_test();
	return 0;
}
