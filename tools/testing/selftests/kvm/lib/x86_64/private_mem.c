// SPDX-License-Identifier: GPL-2.0
/*
 * tools/testing/selftests/kvm/lib/kvm_util.c
 *
 * Copyright (C) 2022, Google LLC.
 */
#define _GNU_SOURCE /* for program_invocation_name */
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

#include <test_util.h>
#include <kvm_util.h>
#include <private_mem.h>
#include <processor.h>

/*
 * Execute KVM hypercall to change memory access type for a given gpa range.
 *
 * Input Args:
 *   type - memory conversion type TO_SHARED/TO_PRIVATE
 *   gpa - starting gpa address
 *   size - size of the range starting from gpa for which memory access needs
 *     to be changed
 *
 * Output Args: None
 *
 * Return: None
 *
 * Function called by guest logic in selftests to update the memory access type
 * for a given gpa range. This API is useful in exercising implicit conversion
 * path.
 */
void guest_update_mem_access(enum mem_conversion_type type, uint64_t gpa,
	uint64_t size)
{
	int ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, gpa, size >> MIN_PAGE_SHIFT,
		type == TO_PRIVATE ? KVM_MARK_GPA_RANGE_ENC_ACCESS :
			KVM_CLR_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(!ret, ret);
}

/*
 * Execute KVM hypercall to change memory type for a given gpa range.
 *
 * Input Args:
 *   type - memory conversion type TO_SHARED/TO_PRIVATE
 *   gpa - starting gpa address
 *   size - size of the range starting from gpa for which memory type needs
 *     to be changed
 *
 * Output Args: None
 *
 * Return: None
 *
 * Function called by guest logic in selftests to update the memory type for a
 * given gpa range. This API is useful in exercising explicit conversion path.
 */
void guest_update_mem_map(enum mem_conversion_type type, uint64_t gpa,
	uint64_t size)
{
	int ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, gpa, size >> MIN_PAGE_SHIFT,
		type == TO_PRIVATE ? KVM_MAP_GPA_RANGE_ENCRYPTED :
			KVM_MAP_GPA_RANGE_DECRYPTED, 0);
	GUEST_ASSERT_1(!ret, ret);
}

/*
 * Execute KVM hypercall to change memory access type for ucall page.
 *
 * Input Args: None
 *
 * Output Args: None
 *
 * Return: None
 *
 * Function called by guest logic in selftests to update the memory access type
 * for ucall page since by default all the accesses from guest to private
 * memslot are treated as private accesses.
 */
void guest_map_ucall_page_shared(void)
{
	vm_paddr_t ucall_paddr = get_ucall_pool_paddr();

	guest_update_mem_access(TO_SHARED, ucall_paddr, 1 << MIN_PAGE_SHIFT);
}

/*
 * Execute KVM ioctl to back/unback private memory for given gpa range.
 *
 * Input Args:
 *   vm - kvm_vm handle
 *   gpa - starting gpa address
 *   size - size of the gpa range
 *   op - mem_op indicating whether private memory needs to be allocated or
 *     unbacked
 *
 * Output Args: None
 *
 * Return: None
 *
 * Function called by host userspace logic in selftests to back/unback private
 * memory for gpa ranges. This function is useful to setup initial boot private
 * memory and then convert memory during runtime.
 */
void vm_update_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size,
	enum mem_op op)
{
	int priv_memfd;
	uint64_t priv_offset, guest_phys_base, fd_offset;
	struct kvm_enc_region enc_region;
	struct kvm_userspace_memory_region_ext *region_ext;
	struct kvm_userspace_memory_region *region;
	int fallocate_mode = 0;
	int ret;

	region_ext = kvm_userspace_memory_region_ext_find(vm, gpa, gpa + size);
	TEST_ASSERT(region_ext != NULL, "Region not found");
	region = &region_ext->region;
	TEST_ASSERT(region->flags & KVM_MEM_PRIVATE,
		"Can not update private memfd for non-private memslot\n");
	priv_memfd = region_ext->private_fd;
	priv_offset = region_ext->private_offset;
	guest_phys_base = region->guest_phys_addr;
	fd_offset = priv_offset + (gpa - guest_phys_base);

	if (op == UNBACK_MEM)
		fallocate_mode = (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE);

	printf("priv_memfd %d fallocate_mode 0x%x for offset 0x%lx size 0x%lx\n",
		priv_memfd, fallocate_mode, fd_offset, size);
	ret = fallocate(priv_memfd, fallocate_mode, fd_offset, size);
	TEST_ASSERT(ret == 0, "fallocate failed\n");
	enc_region.addr = gpa;
	enc_region.size = size;
	if (op == ALLOCATE_MEM) {
		printf("doing encryption for gpa 0x%lx size 0x%lx\n", gpa, size);
		vm_ioctl(vm, KVM_MEMORY_ENCRYPT_REG_REGION, &enc_region);
	} else {
		printf("undoing encryption for gpa 0x%lx size 0x%lx\n", gpa, size);
		vm_ioctl(vm, KVM_MEMORY_ENCRYPT_UNREG_REGION, &enc_region);
	}
}

static void handle_vm_exit_map_gpa_hypercall(struct kvm_vm *vm,
				volatile struct kvm_run *run)
{
	uint64_t gpa, npages, attrs, size;

	TEST_ASSERT(run->hypercall.nr == KVM_HC_MAP_GPA_RANGE,
		"Unhandled Hypercall %lld\n", run->hypercall.nr);
	gpa = run->hypercall.args[0];
	npages = run->hypercall.args[1];
	size = npages << MIN_PAGE_SHIFT;
	attrs = run->hypercall.args[2];
	pr_info("Explicit conversion off 0x%lx size 0x%lx to %s\n", gpa, size,
		(attrs & KVM_MAP_GPA_RANGE_ENCRYPTED) ? "private" : "shared");

	if (attrs & KVM_MAP_GPA_RANGE_ENCRYPTED)
		vm_update_private_mem(vm, gpa, size, ALLOCATE_MEM);
	else
		vm_update_private_mem(vm, gpa, size, UNBACK_MEM);

	run->hypercall.ret = 0;
}

static void handle_vm_exit_memory_error(struct kvm_vm *vm, volatile struct kvm_run *run)
{
	uint64_t gpa, size, flags;

	gpa = run->memory.gpa;
	size = run->memory.size;
	flags = run->memory.flags;
	pr_info("Implicit conversion off 0x%lx size 0x%lx to %s\n", gpa, size,
		(flags & KVM_MEMORY_EXIT_FLAG_PRIVATE) ? "private" : "shared");
	if (flags & KVM_MEMORY_EXIT_FLAG_PRIVATE)
		vm_update_private_mem(vm, gpa, size, ALLOCATE_MEM);
	else
		vm_update_private_mem(vm, gpa, size, UNBACK_MEM);
}

static void vcpu_work(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
	struct vm_setup_info *info)
{
	volatile struct kvm_run *run;
	struct ucall uc;
	uint64_t cmd;

	/*
	 * Loop until the guest is done.
	 */
	run = vcpu->run;

	while (true) {
		vcpu_run(vcpu);

		if (run->exit_reason == KVM_EXIT_IO) {
			cmd = get_ucall(vcpu, &uc);
			if (cmd != UCALL_SYNC)
				break;

			TEST_ASSERT(info->ioexit_cb, "ioexit cb not present");
			info->ioexit_cb(vm, uc.args[1]);
			continue;
		}

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			handle_vm_exit_map_gpa_hypercall(vm, run);
			continue;
		}

		if (run->exit_reason == KVM_EXIT_MEMORY_FAULT) {
			handle_vm_exit_memory_error(vm, run);
			continue;
		}

		TEST_FAIL("Unhandled VCPU exit reason %d\n", run->exit_reason);
		break;
	}

	if (run->exit_reason == KVM_EXIT_IO && cmd == UCALL_ABORT)
		TEST_FAIL("%s at %s:%ld, val = %lu", (const char *)uc.args[0],
			  __FILE__, uc.args[1], uc.args[2]);
}

/*
 * Execute guest vm with private memory memslots.
 *
 * Input Args:
 *   info - pointer to a structure containing information about setting up a VM
 *     with private memslots
 *
 * Output Args: None
 *
 * Return: None
 *
 * Function called by host userspace logic in selftests to execute guest vm
 * logic. It will install two memslots:
 * 1) memslot 0 : containing all the boot code/stack pages
 * 2) test_mem_slot : containing the region of memory that would be used to test
 *   private/shared memory accesses to a memory backed by private memslots
 */
void execute_vm_with_private_mem(struct vm_setup_info *info)
{
	struct kvm_vm *vm;
	struct kvm_enable_cap cap;
	struct kvm_vcpu *vcpu;
	uint32_t memslot0_pages = info->memslot0_pages;
	uint64_t test_area_gpa, test_area_size;
	struct test_setup_info *test_info = &info->test_info;

	vm = vm_create_barebones();
	vm_set_memory_encryption(vm, true, false, 0);
	vm->use_ucall_pool = true;
	vm_userspace_mem_region_add(vm, info->vm_mem_src, 0, 0,
		memslot0_pages, KVM_MEM_PRIVATE);
	kvm_vm_elf_load(vm, program_invocation_name);
	vm_create_irqchip(vm);
	TEST_ASSERT(info->guest_fn, "guest_fn not present");
	vcpu = vm_vcpu_add(vm, 0, info->guest_fn);

	vm_check_cap(vm, KVM_CAP_EXIT_HYPERCALL);
	cap.cap = KVM_CAP_EXIT_HYPERCALL;
	cap.flags = 0;
	cap.args[0] = (1 << KVM_HC_MAP_GPA_RANGE);
	vm_ioctl(vm, KVM_ENABLE_CAP, &cap);

	TEST_ASSERT(test_info->test_area_size, "Test mem size not present");

	test_area_size = test_info->test_area_size;
	test_area_gpa = test_info->test_area_gpa;
	vm_userspace_mem_region_add(vm, info->vm_mem_src, test_area_gpa,
		test_info->test_area_slot, test_area_size / vm->page_size,
		KVM_MEM_PRIVATE);
	vm_update_private_mem(vm, test_area_gpa, test_area_size, ALLOCATE_MEM);

	pr_info("Mapping test memory pages 0x%zx page_size 0x%x\n",
		test_area_size/vm->page_size, vm->page_size);
	virt_map(vm, test_area_gpa, test_area_gpa, test_area_size/vm->page_size);

	ucall_init(vm, NULL);
	vm_update_private_mem(vm, 0, (memslot0_pages << MIN_PAGE_SHIFT), ALLOCATE_MEM);

	vcpu_work(vm, vcpu, info);

	ucall_uninit(vm);
	kvm_vm_free(vm);
}
