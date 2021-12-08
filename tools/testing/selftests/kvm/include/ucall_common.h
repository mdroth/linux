/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common interfaces related to ucall support.
 *
 * A ucall is a hypercall to userspace.
 *
 * Copyright (C) 2018, Google LLC.
 * Copyright (C) 2018, Red Hat, Inc.
 * Copyright (C) 2021, Advanced Micro Devices, Inc.
 */
#ifndef SELFTEST_KVM_UCALL_COMMON_H
#define SELFTEST_KVM_UCALL_COMMON_H

/* Common ucalls */
enum {
	UCALL_NONE,
	UCALL_SYNC,
	UCALL_ABORT,
	UCALL_DONE,
	UCALL_UNHANDLED,
	UCALL_NOT_IMPLEMENTED,
};

#define UCALL_MAX_ARGS 6

struct ucall {
	uint64_t cmd;
	uint64_t args[UCALL_MAX_ARGS];
};

struct ucall_ops {
	const char *name;
	void (*init)(struct kvm_vm *vm, void *arg);
	void (*uninit)(struct kvm_vm *vm);
	void (*send_cmd)(struct ucall *uc);
	uint64_t (*recv_cmd)(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc);
	void (*send_cmd_shared)(struct ucall *uc);
	uint64_t (*recv_cmd_shared)(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc);
};

void ucall_init(struct kvm_vm *vm, void *arg);
void ucall_uninit(struct kvm_vm *vm);
void ucall_init_ops(struct kvm_vm *vm, void *arg, const struct ucall_ops *ops);
void ucall_uninit_ops(struct kvm_vm *vm);
void ucall(uint64_t cmd, int nargs, ...);
uint64_t get_ucall(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc);
vm_vaddr_t ucall_shared_alloc(struct kvm_vm *vm, int count);
void ucall_shared(struct ucall *uc, uint64_t cmd, int nargs, ...);
uint64_t get_ucall_shared(struct kvm_vm *vm, uint32_t vcpu_id, struct ucall *uc);

#define GUEST_SYNC_ARGS(stage, arg1, arg2, arg3, arg4)	\
				ucall(UCALL_SYNC, 6, "hello", stage, arg1, arg2, arg3, arg4)
#define GUEST_SYNC(stage)	ucall(UCALL_SYNC, 2, "hello", stage)
#define GUEST_DONE()		ucall(UCALL_DONE, 0)
#define __GUEST_ASSERT(_condition, _condstr, _nargs, _args...) do {    \
	if (!(_condition))                                              \
		ucall(UCALL_ABORT, 2 + _nargs,                          \
			"Failed guest assert: "                         \
			_condstr, __LINE__, _args);                     \
} while (0)

#define GUEST_ASSERT(_condition) \
	__GUEST_ASSERT(_condition, #_condition, 0, 0)

#define GUEST_ASSERT_1(_condition, arg1) \
	__GUEST_ASSERT(_condition, #_condition, 1, (arg1))

#define GUEST_ASSERT_2(_condition, arg1, arg2) \
	__GUEST_ASSERT(_condition, #_condition, 2, (arg1), (arg2))

#define GUEST_ASSERT_3(_condition, arg1, arg2, arg3) \
	__GUEST_ASSERT(_condition, #_condition, 3, (arg1), (arg2), (arg3))

#define GUEST_ASSERT_4(_condition, arg1, arg2, arg3, arg4) \
	__GUEST_ASSERT(_condition, #_condition, 4, (arg1), (arg2), (arg3), (arg4))

#define GUEST_ASSERT_EQ(a, b) __GUEST_ASSERT((a) == (b), #a " == " #b, 2, a, b)

#endif /* SELFTEST_KVM_UCALL_COMMON_H */
