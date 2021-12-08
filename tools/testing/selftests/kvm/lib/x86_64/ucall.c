// SPDX-License-Identifier: GPL-2.0
/*
 * Arch-specific ucall implementations.
 *
 * A ucall is a "hypercall to userspace".
 *
 * Copyright (C) 2018, Red Hat, Inc.
 */
#include "kvm_util_base.h"
#include "ucall.h"

#define UCALL_PIO_PORT ((uint16_t)0x1000)

static void ucall_ops_pio_send_cmd(struct ucall *uc)
{
	asm volatile("in %[port], %%al"
		: : [port] "d" (UCALL_PIO_PORT), "D" (uc) : "rax", "memory");
}

static uint64_t ucall_ops_pio_recv_cmd(struct kvm_vm *vm, uint32_t vcpu_id,
				       struct ucall *uc)
{
	struct kvm_run *run = vcpu_state(vm, vcpu_id);
	struct ucall ucall = {};

	if (run->exit_reason == KVM_EXIT_IO && run->io.port == UCALL_PIO_PORT) {
		struct kvm_regs regs;

		vcpu_regs_get(vm, vcpu_id, &regs);
		memcpy(&ucall, addr_gva2hva(vm, (vm_vaddr_t)regs.rdi),
		       sizeof(ucall));

		vcpu_run_complete_io(vm, vcpu_id);
		if (uc)
			memcpy(uc, &ucall, sizeof(ucall));
	}

	return ucall.cmd;
}

static uint64_t ucall_ops_pio_recv_cmd_shared(struct kvm_vm *vm, uint32_t vcpu_id,
					      struct ucall *uc)
{
	struct kvm_run *run = vcpu_state(vm, vcpu_id);

	if (run->exit_reason == KVM_EXIT_IO && run->io.port == UCALL_PIO_PORT)
		vcpu_run_complete_io(vm, vcpu_id);

	return uc->cmd;
}

const struct ucall_ops ucall_ops_pio = {
	.name = "PIO",
	.send_cmd = ucall_ops_pio_send_cmd,
	.recv_cmd = ucall_ops_pio_recv_cmd,
	.send_cmd_shared = ucall_ops_pio_send_cmd,
	.recv_cmd_shared = ucall_ops_pio_recv_cmd_shared,
};

static void ucall_ops_halt_send_cmd_shared(struct ucall *uc)
{
	asm volatile("hlt" : : : "memory");
}

static uint64_t ucall_ops_halt_recv_cmd_shared(struct kvm_vm *vm, uint32_t vcpu_id,
					       struct ucall *uc)
{
	struct kvm_run *run = vcpu_state(vm, vcpu_id);

	TEST_ASSERT(run->exit_reason == KVM_EXIT_HLT,
		    "unexpected exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));

	return uc->cmd;
}

const struct ucall_ops ucall_ops_halt = {
	.name = "halt",
	.send_cmd_shared = ucall_ops_halt_send_cmd_shared,
	.recv_cmd_shared = ucall_ops_halt_recv_cmd_shared,
};

const struct ucall_ops ucall_ops_default = ucall_ops_pio;
