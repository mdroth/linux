// SPDX-License-Identifier: GPL-2.0
/*
 * Arch-specific ucall implementations.
 *
 * A ucall is a "hypercall to userspace".
 *
 * Copyright (C) 2019 Red Hat, Inc.
 */
#include "kvm_util_base.h"
#include "ucall.h"

static void
ucall_ops_diag501_send_cmd(struct ucall *uc)
{
	/* Exit via DIAGNOSE 0x501 (normally used for breakpoints) */
	asm volatile ("diag 0,%0,0x501" : : "a"(&uc) : "memory");
}

static uint64_t
ucall_ops_diag501_recv_cmd(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc)
{
	struct kvm_run *run = vcpu_state(vm, vcpu_id);
	struct ucall ucall = {};

	if (run->exit_reason == KVM_EXIT_S390_SIEIC &&
	    run->s390_sieic.icptcode == 4 &&
	    (run->s390_sieic.ipa >> 8) == 0x83 &&    /* 0x83 means DIAGNOSE */
	    (run->s390_sieic.ipb >> 16) == 0x501) {
		int reg = run->s390_sieic.ipa & 0xf;

		memcpy(&ucall, addr_gva2hva(vm, run->s.regs.gprs[reg]),
		       sizeof(ucall));

		vcpu_run_complete_io(vm, vcpu_id);
		if (uc)
			memcpy(uc, &ucall, sizeof(ucall));
	}

	return ucall.cmd;
}

const struct ucall_ops ucall_ops_diag501 = {
	.name = "diag501",
	.send_cmd = ucall_ops_diag501_send_cmd,
	.recv_cmd = ucall_ops_diag501_recv_cmd,
};

const struct ucall_ops ucall_ops_default = ucall_ops_diag501;
