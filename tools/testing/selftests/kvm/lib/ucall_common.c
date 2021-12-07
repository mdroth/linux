// SPDX-License-Identifier: GPL-2.0
/*
 * Common interfaces related to ucall support. A ucall is a hypercall to
 * userspace.
 *
 * Copyright (C) 2018, Red Hat, Inc.
 * Copyright (C) 2021, Advanced Micro Devices, Inc.
 */
#include "kvm_util_base.h"
#include "ucall_common.h"

extern const struct ucall_ops ucall_ops_default;

/* Some archs rely on a default that is available even without ucall_init(). */
#if defined(__x86_64__) || defined(__s390x__)
static const struct ucall_ops *ucall_ops = &ucall_ops_default;
#else
static const struct ucall_ops *ucall_ops;
#endif

void ucall_init_ops(struct kvm_vm *vm, void *arg, const struct ucall_ops *ops)
{
	TEST_ASSERT(ops, "ucall ops must be specified");
	ucall_ops = ops;
	sync_global_to_guest(vm, ucall_ops);

	if (ucall_ops->init)
		ucall_ops->init(vm, arg);
}

void ucall_init(struct kvm_vm *vm, void *arg)
{
	ucall_init_ops(vm, arg, &ucall_ops_default);
}

void ucall_uninit_ops(struct kvm_vm *vm)
{
	if (ucall_ops && ucall_ops->uninit)
		ucall_ops->uninit(vm);

	ucall_ops = NULL;
	sync_global_to_guest(vm, ucall_ops);
}

void ucall_uninit(struct kvm_vm *vm)
{
	ucall_uninit_ops(vm);
}

static void ucall_process_args(struct ucall *uc, uint64_t cmd, int nargs, va_list va_args)
{
	int i;

	nargs = nargs <= UCALL_MAX_ARGS ? nargs : UCALL_MAX_ARGS;
	uc->cmd = cmd;

	for (i = 0; i < nargs; ++i)
		uc->args[i] = va_arg(va_args, uint64_t);
}

/*
 * Allocate/populate a ucall buffer from the guest's stack and then generate an
 * exit to host userspace. ucall_ops->send_cmd should have some way of
 * communicating the address of the ucall buffer to the host.
 */
void ucall(uint64_t cmd, int nargs, ...)
{
	struct ucall uc;
	va_list va;

	if (!ucall_ops->send_cmd)
		return;

	va_start(va, nargs);
	ucall_process_args(&uc, cmd, nargs, va);
	va_end(va);

	ucall_ops->send_cmd(&uc);
}

/*
 * Parse the ucall buffer allocated by the guest via ucall() to determine what
 * ucall message/command was sent by the guest. If 'uc' is provided, copy the
 * contents of the guest's ucall buffer into it.
 */
uint64_t get_ucall(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc)
{
	if (!ucall_ops->recv_cmd)
		return UCALL_NOT_IMPLEMENTED;

	if (uc)
		memset(uc, 0, sizeof(*uc));

	return ucall_ops->recv_cmd(vm, vcpu_id, uc);
}
