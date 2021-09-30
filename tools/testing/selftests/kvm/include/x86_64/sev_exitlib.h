/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VC/vmgexit/GHCB-related helpers for SEV-ES/SEV-SNP guests.
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#ifndef SELFTEST_KVM_SEV_EXITLIB_H
#define SELFTEST_KVM_SEV_EXITLIB_H

int sev_es_handle_vc(void *ghcb, u64 ghcb_gpa, struct ex_regs *regs);
void sev_es_terminate(int reason);

#endif /* SELFTEST_KVM_SEV_EXITLIB_H */
