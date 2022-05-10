// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
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

#define TEST_MEM_GPA		0xb0000000
#define TEST_MEM_SIZE		0x2000
#define TEST_MEM_END		(TEST_MEM_GPA + TEST_MEM_SIZE)
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

#define VM_STAGE_PROCESSED(x)	pr_info("Processed stage %s\n", #x)

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
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory update failure");
		VM_STAGE_PROCESSED(PMPAT_GUEST_STARTED);
		break;
	}
	case PMPAT_GUEST_PRIV_MEM_UPDATED: {
		/* verify host updated data is still intact */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
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

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, priv_mem, TEST_MEM_DATA_PAT2,
			TEST_MEM_SIZE));
	GUEST_SYNC(PMPAT_GUEST_PRIV_MEM_UPDATED);

	GUEST_ASSERT(do_mem_op(VERIFY_PAT, priv_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

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
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory update failed");
		VM_STAGE_PROCESSED(PMSAT_GUEST_STARTED);
		break;
	}
	case PMSAT_GUEST_TEST_MEM_UPDATED: {
		/* verify data to be same as what guest wrote */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
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

	GUEST_SYNC(PMSAT_GUEST_STARTED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
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
				0, TEST_MEM_SIZE);
		TEST_ASSERT(ret != -1,
			"fallocate failed in smsat handling");
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory updated failed");
		VM_STAGE_PROCESSED(SMSAT_GUEST_STARTED);
		break;
	}
	case SMSAT_GUEST_TEST_MEM_UPDATED: {
		/* verify data to be same as what guest wrote */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
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

	GUEST_SYNC(SMSAT_GUEST_STARTED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
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
				0, TEST_MEM_SIZE);
		TEST_ASSERT(ret != -1,
			"fallocate failed in smpat handling");
		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory updated failed");
		VM_STAGE_PROCESSED(SMPAT_GUEST_STARTED);
		break;
	}
	case SMPAT_GUEST_TEST_MEM_UPDATED: {
		/* verify data to be same as what vmm wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
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

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
	GUEST_SYNC(SMPAT_GUEST_TEST_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

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
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory update failed");
		VM_STAGE_PROCESSED(PSAT_GUEST_STARTED);
		break;
	}
	case PSAT_GUEST_PRIVATE_MEM_UPDATED: {
		/* verify data to be same as what vmm wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
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
				0, TEST_MEM_SIZE);
		TEST_ASSERT(ret != -1,
			"fallocate failed in smpat handling");
		VM_STAGE_PROCESSED(PSAT_GUEST_PRIVATE_MEM_VERIFIED);
		break;
	}
	case PSAT_GUEST_SHARED_MEM_UPDATED: {
		/* verify data to be same as what guest wrote */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
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
	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
	GUEST_SYNC(PSAT_GUEST_PRIVATE_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

	GUEST_SYNC(PSAT_GUEST_PRIVATE_MEM_VERIFIED);

	/* Mark no GPA range to be treated as accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, 0,
		0, KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);
	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
	GUEST_SYNC(PSAT_GUEST_SHARED_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

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
				0, TEST_MEM_SIZE);
		TEST_ASSERT(ret != -1,
			"fallocate failed in spat handling");

		/* Initialize the contents of shared memory */
		TEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory updated failed");
		VM_STAGE_PROCESSED(SPAT_GUEST_STARTED);
		break;
	}
	case SPAT_GUEST_SHARED_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
			"Shared memory view mismatch");
		/* Allocate memory for private backing store */
		int ret = fallocate(priv_memfd,
				0, 0, TEST_MEM_SIZE);
		TEST_ASSERT(ret != -1,
			"fallocate failed in spat handling");
		VM_STAGE_PROCESSED(SPAT_GUEST_SHARED_MEM_UPDATED);
		break;
	}
	case SPAT_GUEST_PRIVATE_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
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

	GUEST_SYNC(SPAT_GUEST_STARTED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));
	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
	GUEST_SYNC(SPAT_GUEST_SHARED_MEM_UPDATED);
	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));
	GUEST_SYNC(PSAT_GUEST_PRIVATE_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));
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
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory update failed");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_STARTED);
		break;
	}
	case PSPAHCT_GUEST_PRIVATE_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED);
		break;
	}
	case PSPAHCT_GUEST_SHARED_MEM_UPDATED: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PSPAHCT_GUEST_SHARED_MEM_UPDATED);
		break;
	}
	case PSPAHCT_GUEST_PRIVATE_MEM_UPDATED2: {
		/* verify data to be same as what guest wrote earlier */
		TEST_ASSERT(do_mem_op(VERIFY_PAT, shared_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE),
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

	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);
	GUEST_ASSERT(do_mem_op(SET_PAT, test_mem,
		TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

	GUEST_SYNC(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

	/* Map the GPA range to be treated as shared */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MAP_GPA_RANGE_DECRYPTED | KVM_MAP_GPA_RANGE_PAGE_SZ_4K, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	/* Mark the GPA range to be treated as always accessed via shared
	 * access
	 */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, 0, 0,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));
	GUEST_ASSERT(do_mem_op(SET_PAT, test_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));
	GUEST_SYNC(PSPAHCT_GUEST_SHARED_MEM_UPDATED);

	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT2, TEST_MEM_SIZE));

	/* Map the GPA range to be treated as private */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MAP_GPA_RANGE_ENCRYPTED | KVM_MAP_GPA_RANGE_PAGE_SZ_4K, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	/* Mark the GPA range to be treated as always accessed via private
	 * access
	 */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		TEST_MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	GUEST_ASSERT(do_mem_op(SET_PAT, test_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));
	GUEST_SYNC(PSPAHCT_GUEST_PRIVATE_MEM_UPDATED2);
	GUEST_ASSERT(do_mem_op(VERIFY_PAT, test_mem,
			TEST_MEM_DATA_PAT1, TEST_MEM_SIZE));
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
	uint64_t gpa, npages, attrs;
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

	if ((gpa < TEST_MEM_GPA) || ((gpa +
		(npages << MIN_PAGE_SHIFT)) > TEST_MEM_END)) {
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
	uint64_t gpa, size, flags;
	int ret;
	int priv_memfd =
		priv_memfd_testsuite[test_id].priv_memfd;
	int fallocate_mode;

	gpa = run->memory.gpa;
	size = run->memory.size;
	flags = run->memory.flags;

	if ((gpa < TEST_MEM_GPA) || ((gpa + size)
					> TEST_MEM_END)) {
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

static void setup_and_execute_test(uint32_t test_id)
{
	struct kvm_vm *vm;
	int priv_memfd;
	int ret;
	void *shared_mem;
	struct kvm_enable_cap cap;

	vm = vm_create_default(VCPU_ID, 0,
				priv_memfd_testsuite[test_id].guest_fn);

	/* Allocate shared memory */
	shared_mem = mmap(NULL, TEST_MEM_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "Failed to mmap() host");

	/* Allocate private memory */
	priv_memfd = memfd_create("vm_private_mem", MFD_INACCESSIBLE);
	TEST_ASSERT(priv_memfd != -1, "Failed to create priv_memfd");
	ret = fallocate(priv_memfd, 0, 0, TEST_MEM_SIZE);
	TEST_ASSERT(ret != -1, "fallocate failed");

	priv_memory_region_add(vm, shared_mem,
				TEST_MEM_SLOT, TEST_MEM_SIZE,
				TEST_MEM_GPA, priv_memfd, 0);

	pr_info("Mapping test memory pages 0x%x page_size 0x%x\n",
					TEST_MEM_SIZE/vm_get_page_size(vm),
					vm_get_page_size(vm));
	virt_map(vm, TEST_MEM_GPA, TEST_MEM_GPA,
					(TEST_MEM_SIZE/vm_get_page_size(vm)));

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

	munmap(shared_mem, TEST_MEM_SIZE);
	priv_memfd_testsuite[test_id].shared_mem = NULL;
	close(priv_memfd);
	priv_memfd_testsuite[test_id].priv_memfd = -1;
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	for (uint32_t i = 0; i < ARRAY_SIZE(priv_memfd_testsuite); i++) {
		pr_info("=== Starting test %s... ===\n",
				priv_memfd_testsuite[i].test_desc);
		setup_and_execute_test(i);
		pr_info("--- completed test %s ---\n\n",
				priv_memfd_testsuite[i].test_desc);
	}

	return 0;
}
