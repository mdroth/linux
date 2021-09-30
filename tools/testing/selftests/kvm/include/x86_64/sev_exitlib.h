/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VC/vmgexit/GHCB-related helpers for SEV-ES/SEV-SNP guests.
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#ifndef SELFTEST_KVM_SEV_EXITLIB_H
#define SELFTEST_KVM_SEV_EXITLIB_H

#define PVALIDATE_NO_UPDATE 255

int sev_es_handle_vc(void *ghcb, u64 ghcb_gpa, struct ex_regs *regs);
void sev_es_terminate(int reason);
void snp_register_ghcb(u64 ghcb_gpa);
void snp_psc_set_shared(u64 gpa);
void snp_psc_set_private(u64 gpa);
int snp_pvalidate(void *ptr, bool rmp_psize, bool validate);

#endif /* SELFTEST_KVM_SEV_EXITLIB_H */
