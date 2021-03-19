// SPDX-License-Identifier: GPL-2.0-only
/*
 * VC handler and helpers used for SEV-ES/SEV-SNP guests
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */

#ifndef SELFTEST_KVM_SEV_ES_H
#define SELFTEST_KVM_SEV_ES_H

void sev_es_handle_vc(void *ghcb, struct ex_regs *regs);

#endif /* SELFTEST_KVM_SEV_ES_H */
