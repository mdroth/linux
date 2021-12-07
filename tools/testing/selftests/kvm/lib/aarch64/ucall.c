// SPDX-License-Identifier: GPL-2.0
/*
 * Arch-specific ucall implementations.
 *
 * A ucall is a "hypercall to userspace".
 *
 * Copyright (C) 2018, Red Hat, Inc.
 */
#include "kvm_util_base.h"
#include "../kvm_util_internal.h"
#include "ucall.h"

static vm_vaddr_t *ucall_exit_mmio_addr;

static bool ucall_mmio_init(struct kvm_vm *vm, vm_paddr_t gpa)
{
	if (kvm_userspace_memory_region_find(vm, gpa, gpa + 1))
		return false;

	virt_pg_map(vm, gpa, gpa);

	ucall_exit_mmio_addr = (vm_vaddr_t *)gpa;
	sync_global_to_guest(vm, ucall_exit_mmio_addr);

	return true;
}

static void ucall_ops_mmio_init(struct kvm_vm *vm, void *arg)
{
	vm_paddr_t gpa, start, end, step, offset;
	unsigned int bits;
	bool ret;

	if (arg) {
		gpa = (vm_paddr_t)arg;
		ret = ucall_mmio_init(vm, gpa);
		TEST_ASSERT(ret, "Can't set ucall mmio address to %lx", gpa);
		return;
	}

	/*
	 * Find an address within the allowed physical and virtual address
	 * spaces, that does _not_ have a KVM memory region associated with
	 * it. Identity mapping an address like this allows the guest to
	 * access it, but as KVM doesn't know what to do with it, it
	 * will assume it's something userspace handles and exit with
	 * KVM_EXIT_MMIO. Well, at least that's how it works for AArch64.
	 * Here we start with a guess that the addresses around 5/8th
	 * of the allowed space are unmapped and then work both down and
	 * up from there in 1/16th allowed space sized steps.
	 *
	 * Note, we need to use VA-bits - 1 when calculating the allowed
	 * virtual address space for an identity mapping because the upper
	 * half of the virtual address space is the two's complement of the
	 * lower and won't match physical addresses.
	 */
	bits = vm->va_bits - 1;
	bits = vm->pa_bits < bits ? vm->pa_bits : bits;
	end = 1ul << bits;
	start = end * 5 / 8;
	step = end / 16;
	for (offset = 0; offset < end - start; offset += step) {
		if (ucall_mmio_init(vm, start - offset))
			return;
		if (ucall_mmio_init(vm, start + offset))
			return;
	}
	TEST_FAIL("Can't find a ucall mmio address");
}

static void ucall_ops_mmio_uninit(struct kvm_vm *vm)
{
	ucall_exit_mmio_addr = 0;
	sync_global_to_guest(vm, ucall_exit_mmio_addr);
}

static void ucall_ops_mmio_send_cmd(struct ucall *uc)
{
	*ucall_exit_mmio_addr = (vm_vaddr_t)uc;
}

static uint64_t ucall_ops_mmio_recv_cmd(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc)
{
	struct kvm_run *run = vcpu_state(vm, vcpu_id);
	struct ucall ucall = {};

	if (run->exit_reason == KVM_EXIT_MMIO &&
	    run->mmio.phys_addr == (uint64_t)ucall_exit_mmio_addr) {
		vm_vaddr_t gva;

		TEST_ASSERT(run->mmio.is_write && run->mmio.len == 8,
			    "Unexpected ucall exit mmio address access");
		memcpy(&gva, run->mmio.data, sizeof(gva));
		memcpy(&ucall, addr_gva2hva(vm, gva), sizeof(ucall));

		vcpu_run_complete_io(vm, vcpu_id);
		if (uc)
			memcpy(uc, &ucall, sizeof(ucall));
	}

	return ucall.cmd;
}

const struct ucall_ops ucall_ops_mmio = {
	.name = "MMIO",
	.init = ucall_ops_mmio_init,
	.uninit = ucall_ops_mmio_uninit,
	.send_cmd = ucall_ops_mmio_send_cmd,
	.recv_cmd = ucall_ops_mmio_recv_cmd,
};

const struct ucall_ops ucall_ops_default = ucall_ops_mmio;
