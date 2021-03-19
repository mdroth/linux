// SPDX-License-Identifier: GPL-2.0-only
/*
 * Basic SEV boot test
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
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"

#define VCPU_ID			5
#define PAGE_SIZE		4096

#define SHARED_GPA		0x1000000
#define SHARED_PAGES		2
#define SHARED_MEMSLOT		16
#define SHARED_VADDR_MIN	0x1000000

#define PRIVATE_GPA		0x2000000
#define PRIVATE_PAGES		2
#define PRIVATE_MEMSLOT		17
#define PRIVATE_VADDR_MIN	0x2000000

static void __attribute__((__flatten__))
guest_code(struct sev_sync_data *sync, uint8_t *private_buf)
{
	uint32_t eax, ebx, ecx, edx, token = 0;
	uint64_t sev_status;
	int i;

	/* Check SEV enabled bit */
	sev_status = rdmsr(MSR_AMD64_SEV);
	SEV_GUEST_ASSERT(sync, token++, (sev_status & 0x1) == 1);

	cpuid(0x8000001f, 0, &eax, &ebx, &ecx, &edx);

	/* Check SEV bit */
	SEV_GUEST_ASSERT(sync, token++, eax & (1 << 1));

	/* Ensure userspace can't read encrypted data */
	for (i = 0; i < 32; i++)
		private_buf[i] = i;
	sev_guest_sync(sync, 100, 0);

	sev_guest_done(sync, 101, 0);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	struct sev_sync_data *sync;
	struct vm_memcrypt memcrypt;

	struct sev_user_data_status sev_status = {0};
	struct kvm_sev_launch_start ksev_launch_start = {0};
	struct kvm_sev_guest_status ksev_guest_status = {0};
	struct kvm_sev_launch_measure ksev_launch_measure = {0};

	int sev_fd, i;
	vm_vaddr_t shared_vaddr, private_vaddr;
	bool private_data_encrypted;
	uint8_t *shared_buf, *private_buf, *ksev_launch_measure_buf;

	/* Initialize/check SEV environment */
	sev_fd = open(SEV_DEV_PATH, O_RDWR);
	if (sev_fd < 0) {
		pr_info("Failed to open SEV device, path: %s, error: %d, skipping test.\n",
			SEV_DEV_PATH, sev_fd);
		return 0;
	}

	sev_ioctl(sev_fd, SEV_PLATFORM_STATUS, &sev_status);
	pr_info("SEV build_id: %d, api major/minor: %d/%d\n",
		sev_status.build, sev_status.api_major, sev_status.api_minor);

	/* Create SEV-ES VM and load initial guest state */

	/* We need to handle memslots after SEV_ES init, and after setting memcrypt */
	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_INIT, NULL);
	sev_memcrypt_init(&memcrypt, sev_fd);
	vm_memcrypt_set(vm, &memcrypt);

	/* Now we can set up main memslot */
	vm_userspace_mem_region_add_encrypted(vm, VM_MEM_SRC_ANONYMOUS, 0, 0,
					      DEFAULT_GUEST_PHY_PAGES, 0);

	/* Set up our VCPU */
	vm_vcpu_add_default(vm, VCPU_ID, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name, 0, 0);
#if 0
	vm_init_descriptor_tables(vm);
	vm_handle_exception(vm, 29, vc_handler);
	vcpu_init_descriptor_tables(vm, VCPU_ID);
#endif
	vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

	/* Set up additional memslot for reserved shared memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, SHARED_GPA,
				    SHARED_MEMSLOT, SHARED_PAGES, 0);
	shared_vaddr = vm_vaddr_alloc(vm, SHARED_PAGES * PAGE_SIZE,
				      SHARED_VADDR_MIN, SHARED_MEMSLOT, 0);
	shared_buf = addr_gva2hva(vm, shared_vaddr);
	memset(shared_buf, 0, SHARED_PAGES * PAGE_SIZE);

	/* Set up additional memslot for reserved private memory */
	vm_userspace_mem_region_add_encrypted(vm, VM_MEM_SRC_ANONYMOUS, PRIVATE_GPA,
					      PRIVATE_MEMSLOT, PRIVATE_PAGES, 0);
	private_vaddr = vm_vaddr_alloc(vm, PRIVATE_PAGES * PAGE_SIZE,
				       PRIVATE_VADDR_MIN, PRIVATE_MEMSLOT, 0);
	private_buf = addr_gva2hva(vm, private_vaddr);
	memset(private_buf, 0x42, PRIVATE_PAGES * PAGE_SIZE);

	/* Set up guest params */
	sync = addr_gva2hva(vm, shared_vaddr);
	vcpu_args_set(vm, VCPU_ID, 3, shared_vaddr, private_vaddr);

	/* Get ready to encrypt initial state */
	ksev_launch_start.policy = 0x1;
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_LAUNCH_START, &ksev_launch_start);
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_GUEST_STATUS, &ksev_guest_status);
	TEST_ASSERT(ksev_guest_status.policy == 0x1, "incorrect guest policy");
	TEST_ASSERT(ksev_guest_status.state == SEV_GSTATE_LUPDATE,
		    "unexpected guest state: %d", ksev_guest_status.state);

	/* Encrypt initial guest state */
	vm_memcrypt_encrypt_memslot(vm, 0);
	vm_memcrypt_encrypt_memslot(vm, PRIVATE_MEMSLOT);

#if 0
	/* TODO: why does probing measurement size fail with fw_error: 4? */
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_LAUNCH_MEASURE, &ksev_launch_measure);
	TEST_ASSERT(ksev_launch_measure.len > 0,
		    "failed to query launch measurement length");
#endif

	/* Dump the initial measurement. A test to actually verify it would be nice */
	ksev_launch_measure.len = 512;
	ksev_launch_measure_buf = calloc(ksev_launch_measure.len, 1);
	ksev_launch_measure.uaddr = (__u64)ksev_launch_measure_buf;
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_LAUNCH_MEASURE, &ksev_launch_measure);
	pr_info("measurement: \n");
	for (i = 0; i < 32; ++i) {
		pr_info("%02x", ksev_launch_measure_buf[i]);
	}
	pr_info("\n");

	/* Measurement causes a state transition, check that */
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_GUEST_STATUS, &ksev_guest_status);
	TEST_ASSERT(ksev_guest_status.state == SEV_GSTATE_LSECRET,
		    "unexpected guest state: %d", ksev_guest_status.state);

	/* Ready to run the guest now */
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_LAUNCH_FINISH, NULL);
	kvm_sev_ioctl(vm, sev_fd, KVM_SEV_GUEST_STATUS, &ksev_guest_status);
	TEST_ASSERT(ksev_guest_status.state == SEV_GSTATE_RUNNING,
		    "unexpected guest state: %d", ksev_guest_status.state);

	/* Run guest and do some sanity checks */
	run = vcpu_state(vm, VCPU_ID);

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_sync(run, sync, 100);

	/* Ensure data written by guest is encrypted */
	private_data_encrypted = false;
	for (i = 0; !private_data_encrypted && i < 32; i++) {
		if (private_buf[i] != i)
			private_data_encrypted = true;
	}
	TEST_ASSERT(private_data_encrypted, "guest memory not encrypted!");

	/* Ensure the initial memory contents were encrypted */
	private_data_encrypted = false;
	for (i = 0; !private_data_encrypted && i < 32; i++) {
		if (private_buf[PAGE_SIZE + i] != 0x42)
			private_data_encrypted = true;
	}
	TEST_ASSERT(private_data_encrypted, "guest memory not encrypted!");

	vcpu_run(vm, VCPU_ID);
	sev_check_guest_done(run, sync, 101);

	kvm_vm_free(vm);

	return 0;
}
