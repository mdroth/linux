// SPDX-License-Identifier: GPL-2.0-only
/*
 * ucall interface/implementation tests.
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"

#define VCPU_ID			2
#define TOTAL_PAGES		512

enum uc_test_type {
	UC_TEST_WITHOUT_UCALL_INIT,
	UC_TEST_WITH_UCALL_INIT,
	UC_TEST_WITH_UCALL_INIT_OPS,
	UC_TEST_WITH_UCALL_INIT_OPS_SHARED,
	UC_TEST_MAX,
};

struct uc_test_config {
	enum uc_test_type type;
	const struct ucall_ops *ops;
};

static void test_ucall(void)
{
	GUEST_SYNC(1);
	GUEST_SYNC(2);
	GUEST_DONE();
	GUEST_ASSERT(false);
}

static void check_ucall(struct kvm_vm *vm)
{
	struct ucall uc_tmp;

	vcpu_run(vm, VCPU_ID);
	TEST_ASSERT(get_ucall(vm, VCPU_ID, &uc_tmp) == UCALL_SYNC, "sync failed");

	vcpu_run(vm, VCPU_ID);
	TEST_ASSERT(get_ucall(vm, VCPU_ID, &uc_tmp) == UCALL_SYNC, "sync failed");

	vcpu_run(vm, VCPU_ID);
	TEST_ASSERT(get_ucall(vm, VCPU_ID, &uc_tmp) == UCALL_DONE, "done failed");

	vcpu_run(vm, VCPU_ID);
	TEST_ASSERT(get_ucall(vm, VCPU_ID, &uc_tmp) == UCALL_ABORT, "abort failed");
}

static void test_ucall_shared(struct ucall *uc)
{
	GUEST_SHARED_SYNC(uc, 1);
	GUEST_SHARED_SYNC(uc, 2);
	GUEST_SHARED_DONE(uc);
	GUEST_SHARED_ASSERT(uc, false);
}

static void check_ucall_shared(struct kvm_vm *vm, struct ucall *uc)
{
	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_SYNC(vm, VCPU_ID, uc, 1);

	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_SYNC(vm, VCPU_ID, uc, 2);

	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_DONE(vm, VCPU_ID, uc);

	vcpu_run(vm, VCPU_ID);
	CHECK_SHARED_ABORT(vm, VCPU_ID, uc);
}

static void __attribute__((__flatten__))
guest_code(struct ucall *uc)
{
	if (uc)
		test_ucall_shared(uc);
	else
		test_ucall();
}

static struct kvm_vm *setup_vm(void)
{
	struct kvm_vm *vm;

	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, 0, 0, TOTAL_PAGES, 0);

	/* Set up VCPU and initial guest kernel. */
	vm_vcpu_add_default(vm, VCPU_ID, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name);

	return vm;
}

static void setup_vm_args(struct kvm_vm *vm, vm_vaddr_t uc_gva)
{
	vcpu_args_set(vm, VCPU_ID, 1, uc_gva);
}

static void run_ucall_test(const struct uc_test_config *config)
{
	struct kvm_vm *vm = setup_vm();
	const struct ucall_ops *ops = config->ops;
	bool is_default_ops = (!ops || ops == &ucall_ops_default);
	bool shared = (config->type == UC_TEST_WITH_UCALL_INIT_OPS_SHARED);

	pr_info("Testing ucall%s ops for: %s%s\n",
		shared ? "_shared" : "",
		ops ? ops->name : "unspecified",
		is_default_ops ? " (via default)" : "");

	if (config->type == UC_TEST_WITH_UCALL_INIT)
		ucall_init(vm, NULL);
	else if (config->type == UC_TEST_WITH_UCALL_INIT_OPS ||
		 config->type == UC_TEST_WITH_UCALL_INIT_OPS_SHARED)
		ucall_init_ops(vm, NULL, config->ops);

	if (shared) {
		struct ucall *uc;
		vm_vaddr_t uc_gva;

		/* Set up ucall buffer. */
		uc_gva = ucall_shared_alloc(vm, 1);
		uc = addr_gva2hva(vm, uc_gva);

		setup_vm_args(vm, uc_gva);
		check_ucall_shared(vm, uc);
	} else {
		setup_vm_args(vm, 0);
		check_ucall(vm);
	}

	if (config->type == UC_TEST_WITH_UCALL_INIT)
		ucall_uninit(vm);
	else if (config->type == UC_TEST_WITH_UCALL_INIT_OPS ||
		 config->type == UC_TEST_WITH_UCALL_INIT_OPS_SHARED)
		ucall_uninit_ops(vm);

	kvm_vm_free(vm);
}

static const struct uc_test_config test_configs[] = {
#if defined(__x86_64__)
	{ UC_TEST_WITHOUT_UCALL_INIT,		NULL },
	{ UC_TEST_WITH_UCALL_INIT,		NULL },
	{ UC_TEST_WITH_UCALL_INIT_OPS,		&ucall_ops_default },
	{ UC_TEST_WITH_UCALL_INIT_OPS,		&ucall_ops_pio },
	{ UC_TEST_WITH_UCALL_INIT_OPS_SHARED,	&ucall_ops_pio },
	{ UC_TEST_WITH_UCALL_INIT_OPS_SHARED,	&ucall_ops_halt },
#elif defined(__aarch64__)
	{ UC_TEST_WITH_UCALL_INIT,		NULL },
	{ UC_TEST_WITH_UCALL_INIT_OPS,		&ucall_ops_default },
	{ UC_TEST_WITH_UCALL_INIT_OPS,		&ucall_ops_mmio },
#elif defined(__s390x__)
	{ UC_TEST_WITHOUT_UCALL_INIT,		NULL },
	{ UC_TEST_WITH_UCALL_INIT,		NULL },
	{ UC_TEST_WITH_UCALL_INIT_OPS,		&ucall_ops_default },
	{ UC_TEST_WITH_UCALL_INIT_OPS,		&ucall_ops_diag501 },
#endif
	{ UC_TEST_MAX,				NULL },
};

int main(int argc, char *argv[])
{
	int i;

	for (i = 0; test_configs[i].type != UC_TEST_MAX; i++)
		run_ucall_test(&test_configs[i]);

	return 0;
}
