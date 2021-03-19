// SPDX-License-Identifier: GPL-2.0-only
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

#define SEV_DEV_PATH "/dev/sev"

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

void sev_guest_sync(struct sev_sync_data *sync, uint32_t token, uint64_t info);
void sev_guest_done(struct sev_sync_data *sync, uint32_t token, uint64_t info);
void sev_guest_abort(struct sev_sync_data *sync, uint32_t token, uint64_t info);

void sev_check_guest_sync(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token);
void sev_check_guest_done(struct kvm_run *run, struct sev_sync_data *sync,
			  uint32_t token);

void sev_ioctl(int sev_fd, int cmd, void *data);
void kvm_sev_ioctl(struct kvm_vm *vm, int sev_fd, int cmd, void *data);

void sev_memcrypt_init(struct vm_memcrypt *memcrypt, int sev_fd);

void cpuid(uint32_t fn, uint32_t subfn, uint32_t *eaxp, uint32_t *ebxp,
	  uint32_t *ecxp, uint32_t *edxp);

#endif /* SELFTEST_KVM_SEV_H */
