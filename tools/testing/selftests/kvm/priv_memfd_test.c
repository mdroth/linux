// SPDX-License-Identifier: GPL-2.0
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
#include <processor.h>

#define BYTE_MASK 0xFF

// flags for mmap
#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)

// page sizes
#define PAGE_SIZE_4KB ((size_t)0x1000)
#define PAGE_SIZE_2MB (PAGE_SIZE_4KB * (size_t)512)
#define PAGE_SIZE_1GB ((PAGE_SIZE_4KB * 256) * 1024)

#define TEST_MEM_GPA		0xb0000000
#define TEST_MEM_DATA_PAT1	0x6666666666666666
#define TEST_MEM_DATA_PAT2	0x9999999999999999
#define TEST_MEM_DATA_PAT3	0x3333333333333333
#define TEST_MEM_DATA_PAT4	0xaaaaaaaaaaaaaaaa

enum mem_op {
	SET_PAT,
	VERIFY_PAT
};

#define TEST_MEM_SLOT		10

#define VCPU_ID			0

// address where guests can receive the mem size of the data
// allocated to them by the vmm
#define MEM_SIZE_MMIO_ADDRESS 0xa0000000

#define VM_STAGE_PROCESSED(x)	pr_info("Processed stage %s\n", #x)

// global used for storing the current mem allocation size
// for the running test
static size_t test_mem_size;

typedef bool (*vm_stage_handler_fn)(struct kvm_vm *,
				void *, uint64_t);
typedef void (*guest_code_fn)(void);
struct test_run_helper {
	char *test_desc;
	vm_stage_handler_fn vmst_handler;
	guest_code_fn guest_fn;
	void *shared_mem;
	int priv_memfd;
};

enum page_size {
	PAGE_4KB,
	PAGE_2MB,
	PAGE_1GB
};

struct page_combo {
	enum page_size shared;
	enum page_size private;
};

static char *page_size_to_str(enum page_size x)
{
	switch (x) {
	case PAGE_4KB:
		return "PAGE_4KB";
	case PAGE_2MB:
		return "PAGE_2MB";
	case PAGE_1GB:
		return "PAGE_1GB";
	default:
		return "UNKNOWN";
	}
}

static uint64_t test_mem_end(const uint64_t start, const uint64_t size)
{
	return start + size;
}

/* Guest code in selftests is loaded to guest memory using kvm_vm_elf_load
 * which doesn't handle global offset table updates. Calling standard libc
 * functions would normally result in referring to the global offset table.
 * Adding O1 here seems to prohibit compiler from replacing the memory
 * operations with standard libc functions such as memset.
 */
static bool __attribute__((optimize("O1"))) do_mem_op(enum mem_op op,
		void *mem, uint64_t pat, uint32_t size)
{
	uint64_t *buf = (uint64_t *)mem;
	uint32_t chunk_size = sizeof(pat);
	uint64_t mem_addr = (uint64_t)mem;

	if (((mem_addr % chunk_size) != 0) || ((size % chunk_size) != 0))
		return false;

	for (uint32_t i = 0; i < (size / chunk_size); i++) {
		if (op == SET_PAT)
			buf[i] = pat;
		if (op == VERIFY_PAT) {
			if (buf[i] != pat)
				return false;
		}
	}

	return true;
}

/* Test to verify guest private accesses on private memory with following steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM populates the shared memory with known pattern and continues guest
 *    execution.
 * 3) Guest writes a different pattern on the private memory and signals VMM
 *      that it has updated private memory.
 * 4) VMM verifies its shared memory contents to be same as the data populated
 *      in step 2 and continues guest execution.
 * 5) Guest verifies its private memory contents to be same as the data
 *      populated in step 3 and marks the end of the guest execution.
 */
#define PMPAT_ID				0
#define PMPAT_DESC				"PrivateMemoryPrivateAccessTest"

/* Guest code execution stages for private mem access test */
#define PMPAT_GUEST_STARTED			0ULL
#define PMPAT_GUEST_PRIV_MEM_UPDATED		1ULL

static bool pmpat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;

	switch (stage) {
	case PMPAT_GUEST_STARTED: {
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory update failure");
		VM_STAGE_PROCESSED(PMPAT_GUEST_STARTED);
		break;
	}
	case PMPAT_GUEST_PRIV_MEM_UPDATED: {
		/* verify host updated data is still intact */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PMPAT_GUEST_PRIV_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void pmpat_guest_code(void)
{
	void *priv_mem = (void *)TEST_MEM_GPA;
	int ret;

	GUEST_SYNC(PMPAT_GUEST_STARTED);

	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, priv_mem, TEST_MEM_DATA_PAT2,
			mem_size));
	GUEST_SYNC(PMPAT_GUEST_PRIV_MEM_UPDATED);

	GUEST_ASSERT(do_mem_op(VERIFY_PAT, priv_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	GUEST_DONE();
}

/* Test to verify guest shared accesses on private memory with following steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM populates the shared memory with known pattern and continues guest
 *    execution.
 * 3) Guest reads private gpa range in a shared fashion and verifies that it
 *    reads what VMM has written in step2.
 * 3) Guest writes a different pattern on the shared memory and signals VMM
 *      that it has updated the shared memory.
 * 4) VMM verifies shared memory contents to be same as the data populated
 *      in step 3 and continues guest execution.
 */
#define PMSAT_ID				1
#define PMSAT_DESC				"PrivateMemorySharedAccessTest"

/* Guest code execution stages for private mem access test */
#define PMSAT_GUEST_STARTED			0ULL
#define PMSAT_GUEST_TEST_MEM_UPDATED		1ULL

static bool pmsat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;

	switch (stage) {
	case PMSAT_GUEST_STARTED: {
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory update failed");
		VM_STAGE_PROCESSED(PMSAT_GUEST_STARTED);
		break;
	}
	case PMSAT_GUEST_TEST_MEM_UPDATED: {
		/* verify data to be same as what guest wrote */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PMSAT_GUEST_TEST_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void pmsat_guest_code(void)
{
	void *shared_mem = (void *)TEST_MEM_GPA;
	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	GUEST_SYNC(PMSAT_GUEST_STARTED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, mem_size));

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));
	GUEST_SYNC(PMSAT_GUEST_TEST_MEM_UPDATED);

	GUEST_DONE();
}

/* Test to verify guest shared accesses on shared memory with following steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM deallocates the backing private memory and populates the shared memory
 *    with known pattern and continues guest execution.
 * 3) Guest reads shared gpa range in a shared fashion and verifies that it
 *    reads what VMM has written in step2.
 * 3) Guest writes a different pattern on the shared memory and signals VMM
 *      that it has updated the shared memory.
 * 4) VMM verifies shared memory contents to be same as the data populated
 *      in step 3 and continues guest execution.
 */
#define SMSAT_ID				2
#define SMSAT_DESC				"SharedMemorySharedAccessTest"

#define SMSAT_GUEST_STARTED			0ULL
#define SMSAT_GUEST_TEST_MEM_UPDATED		1ULL

static bool smsat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;
	int priv_memfd = ((struct test_run_helper *)test_info)->priv_memfd;

	switch (stage) {
	case SMSAT_GUEST_STARTED: {
		/* Remove the backing private memory storage */
		int ret = fallocate(priv_memfd,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				0, test_mem_size);
		TEST_ASSERT(ret != -1,
			"fallocate failed in smsat handling");
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory updated failed");
		VM_STAGE_PROCESSED(SMSAT_GUEST_STARTED);
		break;
	}
	case SMSAT_GUEST_TEST_MEM_UPDATED: {
		/* verify data to be same as what guest wrote */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(SMSAT_GUEST_TEST_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void smsat_guest_code(void)
{
	void *shared_mem = (void *)TEST_MEM_GPA;
	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	GUEST_SYNC(SMSAT_GUEST_STARTED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, mem_size));

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));
	GUEST_SYNC(SMSAT_GUEST_TEST_MEM_UPDATED);

	GUEST_DONE();
}

/* Test to verify guest private accesses on shared memory with following steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM deallocates the backing private memory and populates the shared memory
 *    with known pattern and continues guest execution.
 * 3) Guest writes gpa range via private access and signals VMM.
 * 4) VMM verifies shared memory contents to be same as the data populated
 *    in step 2 and continues guest execution.
 * 5) Guest reads gpa range via private access and verifies that the contents
 *    are same as written in step 3.
 */
#define SMPAT_ID				3
#define SMPAT_DESC				"SharedMemoryPrivateAccessTest"

#define SMPAT_GUEST_STARTED			0ULL
#define SMPAT_GUEST_TEST_MEM_UPDATED		1ULL

static bool smpat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;
	int priv_memfd = ((struct test_run_helper *)test_info)->priv_memfd;

	switch (stage) {
	case SMPAT_GUEST_STARTED: {
		/* Remove the backing private memory storage */
		int ret = fallocate(priv_memfd,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				0, test_mem_size);
		TEST_ASSERT(ret != -1,
			"fallocate failed in smpat handling");
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory updated failed");
		VM_STAGE_PROCESSED(SMPAT_GUEST_STARTED);
		break;
	}
	case SMPAT_GUEST_TEST_MEM_UPDATED: {
		/* verify data to be same as what vmm wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(SMPAT_GUEST_TEST_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void smpat_guest_code(void)
{
	void *shared_mem = (void *)TEST_MEM_GPA;
	int ret;

	GUEST_SYNC(SMPAT_GUEST_STARTED);

	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));
	GUEST_SYNC(SMPAT_GUEST_TEST_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	GUEST_DONE();
}

/* Test to verify guest shared and private accesses on memory with following
 * steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM populates the shared memory with known pattern and continues guest
 *    execution.
 * 3) Guest writes shared gpa range in a private fashion and signals VMM
 * 4) VMM verifies that shared memory still contains the pattern written in
 *    step 2 and continues guest execution.
 * 5) Guest verifies private memory contents to be same as the data populated
 *    in step 3 and signals VMM.
 * 6) VMM removes the private memory backing which should also clear out the
 *    second stage mappings for the VM
 * 6) Guest does shared write access on shared memory and signals vmm
 * 7) VMM reads the shared memory and verifies that the data is same as what
 *    guest wrote in step 6 and continues guest execution.
 * 8) Guest reads the private memory and verifies that the data is same as
 *    written in step 6.
 */
#define PSAT_ID			4
#define PSAT_DESC		"PrivateSharedAccessTest"

#define PSAT_GUEST_STARTED			0ULL
#define PSAT_GUEST_PRIVATE_MEM_UPDATED		1ULL
#define PSAT_GUEST_PRIVATE_MEM_VERIFIED		2ULL
#define PSAT_GUEST_SHARED_MEM_UPDATED		3ULL

static bool psat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;
	int priv_memfd = ((struct test_run_helper *)test_info)->priv_memfd;

	switch (stage) {
	case PSAT_GUEST_STARTED: {
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory update failed");
		VM_STAGE_PROCESSED(PSAT_GUEST_STARTED);
		break;
	}
	case PSAT_GUEST_PRIVATE_MEM_UPDATED: {
		/* verify data to be same as what vmm wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSAT_GUEST_PRIVATE_MEM_UPDATED);
		break;
	}
	case PSAT_GUEST_PRIVATE_MEM_VERIFIED: {
		/* Remove the backing private memory storage so that
		 * subsequent accesses from guest cause a second stage
		 * page fault
		 */
		int ret = fallocate(priv_memfd,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				0, test_mem_size);
		TEST_ASSERT(ret != -1,
			"fallocate failed in smpat handling");
		VM_STAGE_PROCESSED(PSAT_GUEST_PRIVATE_MEM_VERIFIED);
		break;
	}
	case PSAT_GUEST_SHARED_MEM_UPDATED: {
		/* verify data to be same as what guest wrote */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSAT_GUEST_SHARED_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void psat_guest_code(void)
{
	void *shared_mem = (void *)TEST_MEM_GPA;
	int ret;

	GUEST_SYNC(PSAT_GUEST_STARTED);

	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));
	GUEST_SYNC(PSAT_GUEST_PRIVATE_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	GUEST_SYNC(PSAT_GUEST_PRIVATE_MEM_VERIFIED);

	/* Mark no GPA range to be treated as accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, 0,
		0, KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);
	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));
	GUEST_SYNC(PSAT_GUEST_SHARED_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	GUEST_DONE();
}

/* Test to verify guest shared and private accesses on memory with following
 * steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM removes the private memory backing and populates the shared memory
 *    with known pattern and continues guest execution.
 * 3) Guest reads shared gpa range in a shared fashion and verifies that it
 *    reads what VMM has written in step2.
 * 4) Guest writes a different pattern on the shared memory and signals VMM
 *      that it has updated the shared memory.
 * 5) VMM verifies shared memory contents to be same as the data populated
 *      in step 4 and installs private memory backing again to allow guest
 *      to do private access and invalidate second stage mappings.
 * 6) Guest does private write access on shared memory and signals vmm
 * 7) VMM reads the shared memory and verified that the data is still same
 *    as in step 4 and continues guest execution.
 * 8) Guest reads the private memory and verifies that the data is same as
 *    written in step 6.
 */
#define SPAT_ID					5
#define SPAT_DESC				"SharedPrivateAccessTest"

#define SPAT_GUEST_STARTED			0ULL
#define SPAT_GUEST_SHARED_MEM_UPDATED		1ULL
#define SPAT_GUEST_PRIVATE_MEM_UPDATED		2ULL

static bool spat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;
	int priv_memfd = ((struct test_run_helper *)test_info)->priv_memfd;

	switch (stage) {
	case SPAT_GUEST_STARTED: {
		/* Remove the backing private memory storage so that
		 * subsequent accesses from guest cause a second stage
		 * page fault
		 */
		int ret = fallocate(priv_memfd,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				0, test_mem_size);
		TEST_ASSERT(ret != -1,
			"fallocate failed in spat handling");

		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory updated failed");
		VM_STAGE_PROCESSED(SPAT_GUEST_STARTED);
		break;
	}
	case SPAT_GUEST_SHARED_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		/* Allocate memory for private backing store */
		int ret = fallocate(priv_memfd,
				0, 0, test_mem_size);
		TEST_ASSERT(ret != -1,
			"fallocate failed in spat handling");
		VM_STAGE_PROCESSED(SPAT_GUEST_SHARED_MEM_UPDATED);
		break;
	}
	case SPAT_GUEST_PRIVATE_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(SPAT_GUEST_PRIVATE_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void spat_guest_code(void)
{
	void *shared_mem = (void *)TEST_MEM_GPA;
	int ret;

	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	GUEST_SYNC(SPAT_GUEST_STARTED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, mem_size));
	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	GUEST_SYNC(SPAT_GUEST_SHARED_MEM_UPDATED);
	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, mem_size));
	GUEST_SYNC(PSAT_GUEST_PRIVATE_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, mem_size));
	GUEST_DONE();
}

/* Test to verify guest private, shared, private accesses on memory with
 * following steps:
 * 1) Upon entry, guest signals VMM that it has started.
 * 2) VMM initializes the shared memory with known pattern and continues guest
 *    execution
 * 3) Guest writes the private memory privately via a known pattern and
 *    signals VMM
 * 4) VMM reads the shared memory and verifies that it's same as whats written
 *    in step 2 and continues guest execution
 * 5) Guest reads the private memory privately and verifies that the contents
 *    are same as written in step 3.
 * 6) Guest invokes KVM_HC_MAP_GPA_RANGE to map the hpa range as shared
 *    and marks the range to be accessed via shared access.
 * 7) Guest does a shared access to shared memory and verifies that the
 *    contents are same as written in step 2.
 * 8) Guest writes known pattern to test memory and signals VMM.
 * 9) VMM verifies the memory contents to be same as written by guest in step
 *    8
 * 10) Guest invokes KVM_HC_MAP_GPA_RANGE to map the hpa range as private
 *    and marks the range to be accessed via private access.
 * 11) Guest writes a known pattern to the test memory and signals VMM.
 * 12) VMM verifies the memory contents to be same as written by guest in step
 *     8 and continues guest execution.
 * 13) Guest verififes the memory pattern to be same as written in step 11.
 */
#define PSPAHCT_ID		6
#define PSPAHCT_DESC		"PrivateSharedPrivateAccessHyperCallTest"

#define PSPAHCT_GUEST_STARTED				0ULL
#define PSPAHCT_GUEST_PRIVATE_MEM_UPDATED		1ULL
#define PSPAHCT_GUEST_SHARED_MEM_UPDATED		2ULL
#define PSPAHCT_GUEST_PRIVATE_MEM_UPDATED2		3ULL

static bool pspahct_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;

	switch (stage) {
	case PSPAHCT_GUEST_STARTED: {
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory update failed");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_STARTED);
		break;
	}
	case PSPAHCT_GUEST_PRIVATE_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED);
		break;
	}
	case PSPAHCT_GUEST_SHARED_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_SHARED_MEM_UPDATED);
		break;
	}
	case PSPAHCT_GUEST_PRIVATE_MEM_UPDATED2: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, test_mem_size),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED2);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void pspahct_guest_code(void)
{
	void *test_mem = (void *)TEST_MEM_GPA;
	int ret;

	GUEST_SYNC(PSPAHCT_GUEST_STARTED);

	const size_t mem_size = *((size_t *)MEM_SIZE_MMIO_ADDRESS);

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);
	GUEST_ASSERT(do_mem_op(SET_PAT, test_mem,
		TEST_MEM_DATA_PAT2, mem_size));

	GUEST_SYNC(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	/* Map the GPA range to be treated as shared */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MAP_GPA_RANGE_DECRYPTED | KVM_MAP_GPA_RANGE_PAGE_SZ_4K, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	/* Mark the GPA range to be treated as always accessed via shared
	 * access
	 */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, 0, 0,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT1, mem_size));
	GUEST_ASSERT(do_mem_op(SET_PAT, test_mem,
			TEST_MEM_DATA_PAT2, mem_size));
	GUEST_SYNC(PSPAHCT_GUEST_SHARED_MEM_UPDATED);

	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT2, mem_size));

	/* Map the GPA range to be treated as private */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MAP_GPA_RANGE_ENCRYPTED | KVM_MAP_GPA_RANGE_PAGE_SZ_4K, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	/* Mark the GPA range to be treated as always accessed via private
	 * access
	 */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		mem_size >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, test_mem,
			TEST_MEM_DATA_PAT1, mem_size));
	GUEST_SYNC(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED2);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT1, mem_size));
	GUEST_DONE();
}

static struct test_run_helper priv_memfd_testsuite[] = {
	[PMPAT_ID] = {
		.test_desc = PMPAT_DESC,
		.vmst_handler = pmpat_handle_vm_stage,
		.guest_fn = pmpat_guest_code,
	},
	[PMSAT_ID] = {
		.test_desc = PMSAT_DESC,
		.vmst_handler = pmsat_handle_vm_stage,
		.guest_fn = pmsat_guest_code,
	},
	[SMSAT_ID] = {
		.test_desc = SMSAT_DESC,
		.vmst_handler = smsat_handle_vm_stage,
		.guest_fn = smsat_guest_code,
	},
	[SMPAT_ID] = {
		.test_desc = SMPAT_DESC,
		.vmst_handler = smpat_handle_vm_stage,
		.guest_fn = smpat_guest_code,
	},
	[PSAT_ID] = {
		.test_desc = PSAT_DESC,
		.vmst_handler = psat_handle_vm_stage,
		.guest_fn = psat_guest_code,
	},
	[SPAT_ID] = {
		.test_desc = SPAT_DESC,
		.vmst_handler = spat_handle_vm_stage,
		.guest_fn = spat_guest_code,
	},
	[PSPAHCT_ID] = {
		.test_desc = PSPAHCT_DESC,
		.vmst_handler = pspahct_handle_vm_stage,
		.guest_fn = pspahct_guest_code,
	},
};

static void handle_vm_exit_hypercall(struct kvm_run *run,
	uint32_t test_id)
{
	uint64_t gpa, npages, attrs, mem_end;
	int priv_memfd =
		priv_memfd_testsuite[test_id].priv_memfd;
	int ret;
	int fallocate_mode;

	if (run->hypercall.nr != KVM_HC_MAP_GPA_RANGE) {
		TEST_FAIL("Unhandled Hypercall %lld\n",
					run->hypercall.nr);
	}

	gpa = run->hypercall.args[0];
	npages = run->hypercall.args[1];
	attrs = run->hypercall.args[2];
	mem_end = test_mem_end(gpa, test_mem_size);

	if ((gpa < TEST_MEM_GPA) || ((gpa +
		(npages << MIN_PAGE_SHIFT)) > mem_end)) {
		TEST_FAIL("Unhandled gpa 0x%lx npages %ld\n",
			gpa, npages);
	}

	if (attrs & KVM_MAP_GPA_RANGE_ENCRYPTED)
		fallocate_mode = 0;
	else {
		fallocate_mode = (FALLOC_FL_PUNCH_HOLE |
			FALLOC_FL_KEEP_SIZE);
	}
	pr_info("Converting off 0x%lx pages 0x%lx to %s\n",
		(gpa - TEST_MEM_GPA), npages,
		fallocate_mode ?
			"shared" : "private");
	ret = fallocate(priv_memfd, fallocate_mode,
		(gpa - TEST_MEM_GPA),
		npages << MIN_PAGE_SHIFT);
	TEST_ASSERT(ret != -1,
		"fallocate failed in hc handling");
	run->hypercall.ret = 0;
}

static void handle_vm_exit_memory_error(struct kvm_run *run,
	uint32_t test_id)
{
	uint64_t gpa, size, flags, mem_end;
	int ret;
	int priv_memfd =
		priv_memfd_testsuite[test_id].priv_memfd;
	int fallocate_mode;

	gpa = run->memory.gpa;
	size = run->memory.size;
	flags = run->memory.flags;
	mem_end = test_mem_end(gpa, test_mem_size);

	if ((gpa < TEST_MEM_GPA) || ((gpa + size)
					> mem_end)) {
		TEST_FAIL("Unhandled gpa 0x%lx size 0x%lx\n",
			gpa, size);
	}

	if (flags & KVM_MEMORY_EXIT_FLAG_PRIVATE)
		fallocate_mode = 0;
	else {
		fallocate_mode = (FALLOC_FL_PUNCH_HOLE |
				FALLOC_FL_KEEP_SIZE);
	}
	pr_info("Converting off 0x%lx size 0x%lx to %s\n",
		(gpa - TEST_MEM_GPA), size,
		fallocate_mode ?
			"shared" : "private");
	ret = fallocate(priv_memfd, fallocate_mode,
		(gpa - TEST_MEM_GPA), size);
	TEST_ASSERT(ret != -1,
		"fallocate failed in memory error handling");
}

static void vcpu_work(struct kvm_vm *vm, uint32_t test_id)
{
	struct kvm_run *run;
	struct ucall uc;
	uint64_t cmd;

	/*
	 * Loop until the guest is done.
	 */
	run = vcpu_state(vm, VCPU_ID);

	while (true) {
		vcpu_run(vm, VCPU_ID);

		if (run->exit_reason == KVM_EXIT_IO) {
			cmd = get_ucall(vm, VCPU_ID, &uc);
			if (cmd != UCALL_SYNC)
				break;

			if (!priv_memfd_testsuite[test_id].vmst_handler(
				vm, &priv_memfd_testsuite[test_id], uc.args[1]))
				break;

			continue;
		}

		if (run->exit_reason == KVM_EXIT_MMIO) {
			if (run->mmio.phys_addr == MEM_SIZE_MMIO_ADDRESS) {
				// tell the guest the size of the memory
				// it's been allocated
				int shift_amount = 0;

				for (int i = 0; i < sizeof(uint64_t); ++i) {
					run->mmio.data[i] =
						(test_mem_size >>
							shift_amount) & BYTE_MASK;
					shift_amount += CHAR_BIT;
				}
			}
			continue;
		}

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_vm_exit_hypercall(run, test_id);
			continue;
		}

		if (run->exit_reason == KVM_EXIT_MEMORY_FAULT) {
			handle_vm_exit_memory_error(run, test_id);
			continue;
		}

		TEST_FAIL("Unhandled VCPU exit reason %d\n", run->exit_reason);
		break;
	}

	if (run->exit_reason == KVM_EXIT_IO && cmd == UCALL_ABORT)
		TEST_FAIL("%s at %s:%ld, val = %lu", (const char *)uc.args[0],
			  __FILE__, uc.args[1], uc.args[2]);
}

static void priv_memory_region_add(struct kvm_vm *vm, void *mem, uint32_t slot,
				uint32_t size, uint64_t guest_addr,
				uint32_t priv_fd, uint64_t priv_offset)
{
	struct kvm_userspace_memory_region_ext region_ext;
	int ret;

	region_ext.region.slot = slot;
	region_ext.region.flags = KVM_MEM_PRIVATE;
	region_ext.region.guest_phys_addr = guest_addr;
	region_ext.region.memory_size = size;
	region_ext.region.userspace_addr = (uintptr_t) mem;
	region_ext.private_fd = priv_fd;
	region_ext.private_offset = priv_offset;
	ret = ioctl(vm_get_fd(vm), KVM_SET_USER_MEMORY_REGION, &region_ext);
	TEST_ASSERT(ret == 0, "Failed to register user region for gpa 0x%lx\n",
		guest_addr);
}

static void setup_and_execute_test(uint32_t test_id,
	const enum page_size shared,
	const enum page_size private)
{
	struct kvm_vm *vm;
	int priv_memfd;
	int ret;
	void *shared_mem;
	struct kvm_enable_cap cap;

	vm = vm_create_default(VCPU_ID, 0,
				priv_memfd_testsuite[test_id].guest_fn);

	// use 2 pages by default
	size_t mem_size = PAGE_SIZE_4KB * 2;
	bool using_hugepages = false;

	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;

	switch (shared) {
	case PAGE_4KB:
		// no additional flags are needed
		break;
	case PAGE_2MB:
		mmap_flags |= MAP_HUGETLB | MAP_HUGE_2MB | MAP_POPULATE;
		mem_size = max(mem_size, PAGE_SIZE_2MB);
		using_hugepages = true;
		break;
	case PAGE_1GB:
		mmap_flags |= MAP_HUGETLB | MAP_HUGE_1GB | MAP_POPULATE;
		mem_size = max(mem_size, PAGE_SIZE_1GB);
		using_hugepages = true;
		break;
	default:
		TEST_FAIL("unknown page size for shared memory\n");
	}

	unsigned int memfd_flags = MFD_INACCESSIBLE;

	switch (private) {
	case PAGE_4KB:
		// no additional flags are needed
		break;
	case PAGE_2MB:
		memfd_flags |= MFD_HUGETLB | MFD_HUGE_2MB;
		mem_size = PAGE_SIZE_2MB;
		using_hugepages = true;
		break;
	case PAGE_1GB:
		memfd_flags |= MFD_HUGETLB | MFD_HUGE_1GB;
		mem_size = PAGE_SIZE_1GB;
		using_hugepages = true;
		break;
	default:
		TEST_FAIL("unknown page size for private memory\n");
	}

	// set global for mem size to use later
	test_mem_size = mem_size;

	/* Allocate shared memory */
	shared_mem = mmap(NULL, mem_size,
			PROT_READ | PROT_WRITE,
			mmap_flags, -1, 0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "Failed to mmap() host");

	if (using_hugepages) {
		ret = madvise(shared_mem, mem_size, MADV_WILLNEED);
		TEST_ASSERT(ret == 0, "madvise failed");
	}

	/* Allocate private memory */
	priv_memfd = memfd_create("vm_private_mem", memfd_flags);
	TEST_ASSERT(priv_memfd != -1, "Failed to create priv_memfd");
	ret = fallocate(priv_memfd, 0, 0, mem_size);
	TEST_ASSERT(ret != -1, "fallocate failed");

	priv_memory_region_add(vm, shared_mem,
				TEST_MEM_SLOT, mem_size,
				TEST_MEM_GPA, priv_memfd, 0);

	pr_info("Mapping test memory pages 0x%zx page_size 0x%x\n",
					mem_size/vm_get_page_size(vm),
					vm_get_page_size(vm));
	virt_map(vm, TEST_MEM_GPA, TEST_MEM_GPA,
					(mem_size/vm_get_page_size(vm)));

	// add mmio communication page
	virt_map(vm, MEM_SIZE_MMIO_ADDRESS, MEM_SIZE_MMIO_ADDRESS, 1);

	/* Enable exit on KVM_HC_MAP_GPA_RANGE */
	pr_info("Enabling exit on map_gpa_range hypercall\n");
	ret = ioctl(vm_get_fd(vm), KVM_CHECK_EXTENSION, KVM_CAP_EXIT_HYPERCALL);
	TEST_ASSERT(ret & (1 << KVM_HC_MAP_GPA_RANGE),
				"VM exit on MAP_GPA_RANGE HC not supported");
	cap.cap = KVM_CAP_EXIT_HYPERCALL;
	cap.flags = 0;
	cap.args[0] = (1 << KVM_HC_MAP_GPA_RANGE);
	ret = ioctl(vm_get_fd(vm), KVM_ENABLE_CAP, &cap);
	TEST_ASSERT(ret == 0,
		"Failed to enable exit on MAP_GPA_RANGE hypercall\n");

	priv_memfd_testsuite[test_id].shared_mem = shared_mem;
	priv_memfd_testsuite[test_id].priv_memfd = priv_memfd;
	vcpu_work(vm, test_id);

	munmap(shared_mem, mem_size);
	priv_memfd_testsuite[test_id].shared_mem = NULL;
	close(priv_memfd);
	priv_memfd_testsuite[test_id].priv_memfd = -1;
	kvm_vm_free(vm);
}

static void hugepage_requirements_text(const struct page_combo matrix)
{
	int pages_needed_2mb = 0;
	int pages_needed_1gb = 0;
	enum page_size sizes[] = { matrix.shared, matrix.private };

	for (int i = 0; i < ARRAY_SIZE(sizes); ++i) {
		if (sizes[i] == PAGE_2MB)
			++pages_needed_2mb;
		if (sizes[i] == PAGE_1GB)
			++pages_needed_1gb;
	}
	if (pages_needed_2mb != 0 && pages_needed_1gb != 0) {
		pr_info("This test requires %d 2MB page(s) and %d 1GB page(s)\n",
				pages_needed_2mb, pages_needed_1gb);
	} else if (pages_needed_2mb != 0) {
		pr_info("This test requires %d 2MB page(s)\n", pages_needed_2mb);
	} else if (pages_needed_1gb != 0) {
		pr_info("This test requires %d 1GB page(s)\n", pages_needed_1gb);
	}
}

static bool should_skip_test(const struct page_combo matrix,
	const bool use_2mb_pages,
	const bool use_1gb_pages)
{
	if ((matrix.shared == PAGE_2MB || matrix.private == PAGE_2MB)
		&& !use_2mb_pages)
		return true;
	if ((matrix.shared == PAGE_1GB || matrix.private == PAGE_1GB)
		&& !use_1gb_pages)
		return true;
	return false;
}

static void print_help(const char *const name)
{
	puts("");
	printf("usage %s [-h] [-m] [-g]\n", name);
	puts("");
	printf(" -h: Display this help message\n");
	printf(" -m: include test runs using 2MB page permutations\n");
	printf(" -g: include test runs using 1GB page permutations\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	// arg parsing
	int opt;
	bool use_2mb_pages = false;
	bool use_1gb_pages = false;

	while ((opt = getopt(argc, argv, "mgh")) != -1) {
		switch (opt) {
		case 'm':
			use_2mb_pages = true;
			break;
		case 'g':
			use_1gb_pages = true;
			break;
		case 'h':
		default:
			print_help(argv[0]);
		}
	}

	struct page_combo page_size_matrix[] = {
		{ .shared = PAGE_4KB, .private = PAGE_4KB },
		{ .shared = PAGE_2MB, .private = PAGE_4KB },
	};

	for (uint32_t i = 0; i < ARRAY_SIZE(priv_memfd_testsuite); i++) {
		for (uint32_t j = 0; j < ARRAY_SIZE(page_size_matrix); j++) {
			const struct page_combo current_page_matrix = page_size_matrix[j];

			if (should_skip_test(current_page_matrix,
				use_2mb_pages, use_1gb_pages))
				break;
			pr_info("=== Starting test %s... ===\n",
					priv_memfd_testsuite[i].test_desc);
			pr_info("using page sizes shared: %s private: %s\n",
					page_size_to_str(current_page_matrix.shared),
					page_size_to_str(current_page_matrix.private));
			hugepage_requirements_text(current_page_matrix);
			setup_and_execute_test(i, current_page_matrix.shared,
				current_page_matrix.private);
			pr_info("--- completed test %s ---\n\n",
					priv_memfd_testsuite[i].test_desc);
		}
	}

	return 0;
}
