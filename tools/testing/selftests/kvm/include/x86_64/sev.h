/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Helpers used for SEV guests
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */
#ifndef SELFTEST_KVM_SEV_H
#define SELFTEST_KVM_SEV_H

#include <stdint.h>
#include <stdbool.h>
#include "kvm_util.h"

#define SEV_DEV_PATH		"/dev/sev"
#define SEV_FW_REQ_VER_MAJOR	1
#define SEV_FW_REQ_VER_MINOR	30

#define SEV_POLICY_NO_DBG	(1UL << 0)
#define SEV_POLICY_ES		(1UL << 2)

#define SNP_POLICY_SMT		(1ULL << 16)
#define SNP_POLICY_RSVD		(1ULL << 17)
#define SNP_POLICY_DBG		(1ULL << 19)

#define SEV_GUEST_ASSERT(sync, token, _cond) do {	\
	if (!(_cond))					\
		sev_guest_abort(sync, token, 0);	\
} while (0)

enum {
	SEV_GSTATE_UNINIT = 0,
	SEV_GSTATE_LUPDATE,
	SEV_GSTATE_LSECRET,
	SEV_GSTATE_RUNNING,
};

struct sev_sync_data {
	uint32_t token;
	bool pending;
	bool done;
	bool aborted;
	uint64_t info;
};

struct sev_vm;

void sev_guest_sync(struct sev_sync_data *sync, uint32_t token, uint64_t info);
void sev_guest_done(struct sev_sync_data *sync, uint32_t token, uint64_t info);
void sev_guest_abort(struct sev_sync_data *sync, uint32_t token, uint64_t info);

void sev_check_guest_sync(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token);
void sev_check_guest_done(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token);

void kvm_sev_ioctl(struct sev_vm *sev, int cmd, void *data);
struct kvm_vm *sev_get_vm(struct sev_vm *sev);
uint8_t sev_get_enc_bit(struct sev_vm *sev);

struct sev_vm *sev_vm_create(uint32_t policy, uint64_t npages);
void sev_vm_free(struct sev_vm *sev);
void sev_vm_launch(struct sev_vm *sev);
void sev_vm_measure(struct sev_vm *sev, uint8_t *measurement);
void sev_vm_launch_finish(struct sev_vm *sev);

struct sev_vm *sev_snp_vm_create(uint64_t policy, uint64_t npages);
void sev_snp_vm_free(struct sev_vm *sev);
void sev_snp_vm_launch(struct sev_vm *sev);

#endif /* SELFTEST_KVM_SEV_H */
