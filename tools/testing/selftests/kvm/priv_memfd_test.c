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

static struct test_run_helper priv_memfd_testsuite[] = {
	[PMPAT_ID] = {
		.test_desc = PMPAT_DESC,
		.vmst_handler = pmpat_handle_vm_stage,
		.guest_fn = pmpat_guest_code,
	},
};

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

/* Do private access to the guest's private memory */
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
