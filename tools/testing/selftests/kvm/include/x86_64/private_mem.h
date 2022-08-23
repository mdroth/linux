/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022, Google LLC.
 */

#ifndef SELFTEST_KVM_PRIVATE_MEM_H
#define SELFTEST_KVM_PRIVATE_MEM_H

#include <stdint.h>
#include <kvm_util.h>

enum mem_conversion_type {
	TO_PRIVATE,
	TO_SHARED
};

void guest_update_mem_access(enum mem_conversion_type type, uint64_t gpa,
	uint64_t size);
void guest_update_mem_map(enum mem_conversion_type type, uint64_t gpa,
	uint64_t size);

void guest_map_ucall_page_shared(void);

enum mem_op {
	ALLOCATE_MEM,
	UNBACK_MEM
};

void vm_update_private_mem(struct kvm_vm *vm, uint64_t gpa, uint64_t size,
	enum mem_op op);

typedef void (*guest_code_fn)(void);
typedef void (*io_exit_handler)(struct kvm_vm *vm, uint32_t uc_arg1);

struct test_setup_info {
	uint64_t test_area_gpa;
	uint64_t test_area_size;
	uint32_t test_area_slot;
	uint32_t test_area_mem_src;
};

struct vm_setup_info {
	enum vm_mem_backing_src_type vm_mem_src;
	uint32_t memslot0_pages;
	struct test_setup_info test_info;
	guest_code_fn guest_fn;
	io_exit_handler ioexit_cb;
};

void execute_vm_with_private_mem(struct vm_setup_info *info);

#endif /* SELFTEST_KVM_PRIVATE_MEM_H */
