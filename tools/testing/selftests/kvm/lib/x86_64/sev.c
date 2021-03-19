// SPDX-License-Identifier: GPL-2.0-only
/*
 * tools/testing/selftests/kvm/lib/x86_64/sev.c
 *
 * Helpers used for SEV guests
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#include <stdint.h>
#include <stdbool.h>
#include "kvm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"

/*
 * Maybe not the most appropriate place for this, but we end up using it a lot
 * for SEV and there isn't currently a good place for x86-specific general
 * purpose helper functions.
 */
void cpuid(uint32_t fn, uint32_t subfn, uint32_t *eaxp, uint32_t *ebxp,
	   uint32_t *ecxp, uint32_t *edxp)
{
	uint32_t eax, ebx, ecx, edx;

	asm volatile("cpuid"
		     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		     : "a"(fn), "c"(subfn));

	*eaxp = eax;
	*ebxp = ebx;
	*ecxp = ecx;
	*edxp = edx;
}

/* Helpers for coordinating between guests and test harness */

void sev_guest_sync(struct sev_sync_data *sync, uint32_t token, uint64_t info)
{
	sync->token = token;
	sync->info = info;
	sync->pending = true;

	asm volatile("hlt" : : : "memory");
}

void sev_guest_done(struct sev_sync_data *sync, uint32_t token, uint64_t info)
{
	while (true) {
		sync->done = true;
		sev_guest_sync(sync, token, info);
	}
}

void sev_guest_abort(struct sev_sync_data *sync, uint32_t token, uint64_t info)
{
	while (true) {
		sync->aborted = true;
		sev_guest_sync(sync, token, info);
	}
}

void sev_check_guest_sync(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token)
{
	TEST_ASSERT(run->exit_reason == KVM_EXIT_HLT,
		    "unexpected exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));
	TEST_ASSERT(sync->token == token,
		    "unexpected guest token, expected %d, got: %d", token,
		    sync->token);
	TEST_ASSERT(sync->done == false, "unexpected guest state");
	TEST_ASSERT(sync->aborted == false, "unexpected guest state");
	sync->pending = false;
}

void sev_check_guest_done(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token)
{
	TEST_ASSERT(run->exit_reason == KVM_EXIT_HLT,
		    "unexpected exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));
	TEST_ASSERT(sync->token == token,
		    "unexpected guest token, expected %d, got: %d", token,
		    sync->token);
	TEST_ASSERT(sync->done == true, "unexpected guest state");
	TEST_ASSERT(sync->aborted == false, "unexpected guest state");
	sync->pending = false;
}

/* SEV KVM/PSP API helpers */

void sev_ioctl(int sev_fd, int cmd, void *data)
{
	int r;
	struct sev_issue_cmd arg;

	arg.cmd = cmd;
	arg.data = (unsigned long)data;
	r = ioctl(sev_fd, SEV_ISSUE_CMD, &arg);
	TEST_ASSERT(r == 0, "SEV ioctl %d failed, error: %d, fw_error: %d",
		    cmd, r, arg.error);
}

void kvm_sev_ioctl(struct kvm_vm *vm, int sev_fd, int cmd, void *data)
{
	struct kvm_sev_cmd arg = {0};
	int r;

	arg.id = cmd;
	arg.sev_fd = sev_fd;
	arg.data = (__u64)data;

	r = ioctl(vm_get_fd(vm), KVM_MEMORY_ENCRYPT_OP, &arg);
	TEST_ASSERT(r == 0, "sev vm ioctl %d failed, rc: %i errno: %i (%s), fw_error: %d",
		    cmd, r, errno, strerror(errno), arg.error);
}

/* Implementation for kvm_util memory encryption callbacks */

static void sev_memcrypt_register_user_range(struct kvm_vm *vm, uint64_t uaddr,
					     uint64_t size)
{
	struct kvm_enc_region range = {0};
	int ret;

	range.addr = uaddr;
	range.size = size;

	ret = ioctl(vm_get_fd(vm), KVM_MEMORY_ENCRYPT_REG_REGION, &range);
	TEST_ASSERT(ret == 0, "failed to register user range, errno: %i\n", errno);
}

static void sev_memcrypt_encrypt_phy_range(struct kvm_vm *vm, uint64_t paddr,
					   uint64_t size)
{
	struct kvm_sev_launch_update_data ksev_update_data = {0};
	struct vm_memcrypt *memcrypt = vm_memcrypt_get(vm);

	ksev_update_data.uaddr = (__u64)addr_gpa2hva(vm, paddr);
	ksev_update_data.len = size;

	kvm_sev_ioctl(vm, memcrypt->fd, KVM_SEV_LAUNCH_UPDATE_DATA,
		      &ksev_update_data);
}

void sev_memcrypt_init(struct vm_memcrypt *memcrypt, int sev_fd)
{
	uint32_t ebx, unused;

	cpuid(0x8000001f, 0, &unused, &ebx, &unused, &unused);

	memcrypt->encrypt_bit = ebx & 0x3F;
	memcrypt->fd = sev_fd;
	memcrypt->register_user_range = sev_memcrypt_register_user_range;
	memcrypt->encrypt_phy_range = sev_memcrypt_encrypt_phy_range;
}
