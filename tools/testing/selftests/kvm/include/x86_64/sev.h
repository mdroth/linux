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

/* Makefile might set this separately for user-overrides */
#ifndef SEV_DEV_PATH
#define SEV_DEV_PATH		"/dev/sev"
#endif

#define SEV_FW_REQ_VER_MAJOR	0
#define SEV_FW_REQ_VER_MINOR	17

#define SEV_POLICY_NO_DBG	(1UL << 0)
#define SEV_POLICY_ES		(1UL << 2)

enum {
	SEV_GSTATE_UNINIT = 0,
	SEV_GSTATE_LUPDATE,
	SEV_GSTATE_LSECRET,
	SEV_GSTATE_RUNNING,
};

struct sev_vm;

void kvm_sev_ioctl(struct sev_vm *sev, int cmd, void *data);
struct kvm_vm *sev_get_vm(struct sev_vm *sev);
uint8_t sev_get_enc_bit(struct sev_vm *sev);

struct sev_vm *sev_vm_create(uint32_t policy, uint64_t npages);
void sev_vm_free(struct sev_vm *sev);
void sev_vm_launch(struct sev_vm *sev);
void sev_vm_launch_measure(struct sev_vm *sev, uint8_t *measurement);
void sev_vm_launch_finish(struct sev_vm *sev);

#endif /* SELFTEST_KVM_SEV_H */
