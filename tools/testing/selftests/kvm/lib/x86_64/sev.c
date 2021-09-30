// SPDX-License-Identifier: GPL-2.0-only
/*
 * Helpers used for SEV guests
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#include <stdint.h>
#include <stdbool.h>
#include "kvm_util.h"
#include "linux/psp-sev.h"
#include "processor.h"
#include "sev.h"

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)

struct sev_vm {
	struct kvm_vm *vm;
	int fd;
	int enc_bit;
	uint32_t sev_policy;
	uint64_t snp_policy;
};

/* Helpers for coordinating between guests and test harness. */

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
	TEST_ASSERT(!sync->done, "unexpected guest state");
	TEST_ASSERT(!sync->aborted, "unexpected guest state");
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
	TEST_ASSERT(sync->done, "unexpected guest state");
	TEST_ASSERT(!sync->aborted, "unexpected guest state");
	sync->pending = false;
}

/* Common SEV helpers/accessors. */

struct kvm_vm *sev_get_vm(struct sev_vm *sev)
{
	return sev->vm;
}

uint8_t sev_get_enc_bit(struct sev_vm *sev)
{
	return sev->enc_bit;
}

void sev_ioctl(int sev_fd, int cmd, void *data)
{
	int ret;
	struct sev_issue_cmd arg;

	arg.cmd = cmd;
	arg.data = (unsigned long)data;
	ret = ioctl(sev_fd, SEV_ISSUE_CMD, &arg);
	TEST_ASSERT(ret == 0,
		    "SEV ioctl %d failed, error: %d, fw_error: %d",
		    cmd, ret, arg.error);
}

void kvm_sev_ioctl(struct sev_vm *sev, int cmd, void *data)
{
	struct kvm_sev_cmd arg = {0};
	int ret;

	arg.id = cmd;
	arg.sev_fd = sev->fd;
	arg.data = (__u64)data;

	ret = ioctl(vm_get_fd(sev->vm), KVM_MEMORY_ENCRYPT_OP, &arg);
	TEST_ASSERT(ret == 0,
		    "SEV KVM ioctl %d failed, rc: %i errno: %i (%s), fw_error: %d",
		    cmd, ret, errno, strerror(errno), arg.error);
}

/* Local helpers. */

static bool sev_snp_enabled(struct sev_vm *sev)
{
	/* RSVD is always 1 for SNP guests. */
	return sev->snp_policy & SNP_POLICY_RSVD;
}

static void
sev_register_user_range(struct sev_vm *sev, void *hva, uint64_t size)
{
	struct kvm_enc_region range = {0};
	int ret;

	pr_debug("register_user_range: hva: %p, size: %lu\n", hva, size);

	range.addr = (__u64)hva;
	range.size = size;

	ret = ioctl(vm_get_fd(sev->vm), KVM_MEMORY_ENCRYPT_REG_REGION, &range);
	TEST_ASSERT(ret == 0, "failed to register user range, errno: %i\n", errno);
}

static void
sev_encrypt_phy_range(struct sev_vm *sev, vm_paddr_t gpa, uint64_t size)
{
	struct kvm_sev_launch_update_data ksev_update_data = {0};

	pr_debug("encrypt_phy_range: addr: 0x%lx, size: %lu\n", gpa, size);

	ksev_update_data.uaddr = (__u64)addr_gpa2hva(sev->vm, gpa);
	ksev_update_data.len = size;

	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_UPDATE_DATA, &ksev_update_data);
}

static void
sev_snp_encrypt_phy_range(struct sev_vm *sev, vm_paddr_t gpa, uint64_t size)
{
	struct kvm_sev_snp_launch_update update_data = {0};

	pr_debug("encrypt_phy_range: addr: 0x%lx, size: %lu\n", gpa, size);

	update_data.uaddr = (__u64)addr_gpa2hva(sev->vm, gpa);
	update_data.start_gfn = gpa >> PAGE_SHIFT;
	update_data.len = size;
	update_data.page_type = KVM_SEV_SNP_PAGE_TYPE_NORMAL;

	kvm_sev_ioctl(sev, KVM_SEV_SNP_LAUNCH_UPDATE, &update_data);
}

static void sev_encrypt(struct sev_vm *sev)
{
	struct sparsebit *enc_phy_pages;
	struct kvm_vm *vm = sev->vm;
	sparsebit_idx_t pg = 0;
	vm_paddr_t gpa_start;
	uint64_t memory_size;

	/* Only memslot 0 supported for now. */
	enc_phy_pages = vm_get_encrypted_phy_pages(sev->vm, 0, &gpa_start, &memory_size);
	TEST_ASSERT(enc_phy_pages, "Unable to retrieve encrypted pages bitmap");
	while (pg < (memory_size / vm_get_page_size(vm))) {
		sparsebit_idx_t pg_cnt;

		if (sparsebit_is_clear(enc_phy_pages, pg)) {
			pg = sparsebit_next_set(enc_phy_pages, pg);
			if (!pg)
				break;
		}

		pg_cnt = sparsebit_next_clear(enc_phy_pages, pg) - pg;
		if (pg_cnt <= 0)
			pg_cnt = 1;

		if (sev_snp_enabled(sev))
			sev_snp_encrypt_phy_range(sev,
						  gpa_start + pg * vm_get_page_size(vm),
						  pg_cnt * vm_get_page_size(vm));
		else
			sev_encrypt_phy_range(sev,
					      gpa_start + pg * vm_get_page_size(vm),
					      pg_cnt * vm_get_page_size(vm));
		pg += pg_cnt;
	}

	sparsebit_free(&enc_phy_pages);
}

/* SEV VM implementation. */

static struct sev_vm *sev_common_create(struct kvm_vm *vm)
{
	struct sev_user_data_status sev_status = {0};
	uint32_t eax, ebx, ecx, edx;
	struct sev_vm *sev;
	int sev_fd;

	sev_fd = open(SEV_DEV_PATH, O_RDWR);
	if (sev_fd < 0) {
		pr_info("Failed to open SEV device, path: %s, error: %d, skipping test.\n",
			SEV_DEV_PATH, sev_fd);
		return NULL;
	}

	sev_ioctl(sev_fd, SEV_PLATFORM_STATUS, &sev_status);

	if (!(sev_status.api_major > SEV_FW_REQ_VER_MAJOR ||
	      (sev_status.api_major == SEV_FW_REQ_VER_MAJOR &&
	       sev_status.api_minor >= SEV_FW_REQ_VER_MINOR))) {
		pr_info("SEV FW version too old. Have API %d.%d (build: %d), need %d.%d, skipping test.\n",
			sev_status.api_major, sev_status.api_minor, sev_status.build,
			SEV_FW_REQ_VER_MAJOR, SEV_FW_REQ_VER_MINOR);
		return NULL;
	}

	sev = calloc(1, sizeof(*sev));
	sev->fd = sev_fd;
	sev->vm = vm;

	/* Get encryption bit via CPUID. */
	eax = 0x8000001f;
	ecx = 0;
	cpuid(&eax, &ebx, &ecx, &edx);
	sev->enc_bit = ebx & 0x3F;

	return sev;
}

static void sev_common_free(struct sev_vm *sev)
{
	close(sev->fd);
	free(sev);
}

struct sev_vm *sev_vm_create(uint32_t policy, uint64_t npages)
{
	struct sev_vm *sev;
	struct kvm_vm *vm;

	/* Need to handle memslots after init, and after setting memcrypt. */
	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	sev = sev_common_create(vm);
	if (!sev)
		return NULL;
	sev->sev_policy = policy;

	if (sev->sev_policy & SEV_POLICY_ES)
		kvm_sev_ioctl(sev, KVM_SEV_ES_INIT, NULL);
	else
		kvm_sev_ioctl(sev, KVM_SEV_INIT, NULL);

	vm_set_memory_encryption(vm, true, true, sev->enc_bit);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, 0, 0, npages, 0);
	sev_register_user_range(sev, addr_gpa2hva(vm, 0), npages * vm_get_page_size(vm));

	pr_info("%s guest created, policy: 0x%x, size: %lu KB\n",
		(sev->sev_policy & SEV_POLICY_ES) ? "SEV-ES" : "SEV",
		sev->sev_policy, npages * vm_get_page_size(vm) / 1024);

	return sev;
}

void sev_vm_free(struct sev_vm *sev)
{
	kvm_vm_free(sev->vm);
	sev_common_free(sev);
}

void sev_vm_launch(struct sev_vm *sev)
{
	struct kvm_sev_launch_start ksev_launch_start = {0};
	struct kvm_sev_guest_status ksev_status = {0};

	/* Need to use ucall_shared for synchronization. */
	ucall_init_ops(sev_get_vm(sev), NULL, &ucall_ops_halt);

	ksev_launch_start.policy = sev->sev_policy;
	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_START, &ksev_launch_start);
	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.policy == sev->sev_policy, "Incorrect guest policy.");
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_LUPDATE,
		    "Unexpected guest state: %d", ksev_status.state);

	sev_encrypt(sev);

	if (sev->sev_policy & SEV_POLICY_ES)
		kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_UPDATE_VMSA, NULL);
}

void sev_vm_measure(struct sev_vm *sev, uint8_t *measurement)
{
	struct kvm_sev_launch_measure ksev_launch_measure = {0};
	struct kvm_sev_guest_status ksev_guest_status = {0};

	ksev_launch_measure.len = 256;
	ksev_launch_measure.uaddr = (__u64)measurement;
	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_MEASURE, &ksev_launch_measure);

	/* Measurement causes a state transition, check that. */
	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_guest_status);
	TEST_ASSERT(ksev_guest_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", ksev_guest_status.state);
}

void sev_vm_launch_finish(struct sev_vm *sev)
{
	struct kvm_sev_guest_status ksev_status = {0};

	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_LUPDATE ||
		    ksev_status.state == SEV_GSTATE_LSECRET,
		    "Unexpected guest state: %d", ksev_status.state);

	kvm_sev_ioctl(sev, KVM_SEV_LAUNCH_FINISH, NULL);

	kvm_sev_ioctl(sev, KVM_SEV_GUEST_STATUS, &ksev_status);
	TEST_ASSERT(ksev_status.state == SEV_GSTATE_RUNNING,
		    "Unexpected guest state: %d", ksev_status.state);
}

/* SEV-SNP VM implementation. */

struct sev_vm *sev_snp_vm_create(uint64_t policy, uint64_t npages)
{
	struct kvm_snp_init init = {0};
	struct sev_vm *sev;
	struct kvm_vm *vm;

	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	sev = sev_common_create(vm);
	if (!sev)
		return NULL;
	sev->snp_policy = policy | SNP_POLICY_RSVD;

	kvm_sev_ioctl(sev, KVM_SEV_SNP_INIT, &init);
	vm_set_memory_encryption(vm, true, true, sev->enc_bit);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, 0, 0, npages, 0);
	sev_register_user_range(sev, addr_gpa2hva(vm, 0), npages * vm_get_page_size(vm));

	pr_info("SEV-SNP guest created, policy: 0x%lx, size: %lu KB\n",
		sev->snp_policy, npages * vm_get_page_size(vm) / 1024);

	return sev;
}

void sev_snp_vm_free(struct sev_vm *sev)
{
	kvm_vm_free(sev->vm);
	sev_common_free(sev);
}

void sev_snp_vm_launch(struct sev_vm *sev)
{
	struct kvm_sev_snp_launch_start launch_start = {0};
	struct kvm_sev_snp_launch_update launch_finish = {0};

	launch_start.policy = sev->snp_policy;
	kvm_sev_ioctl(sev, KVM_SEV_SNP_LAUNCH_START, &launch_start);

	sev_encrypt(sev);

	kvm_sev_ioctl(sev, KVM_SEV_SNP_LAUNCH_FINISH, &launch_finish);
}
