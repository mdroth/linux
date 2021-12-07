/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arch-specific ucall implementations.
 *
 * A ucall is a "hypercall to userspace".
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */
#ifndef SELFTEST_KVM_UCALL_H
#define SELFTEST_KVM_UCALL_H

#include "ucall_common.h"

extern const struct ucall_ops ucall_ops_pio;

extern const struct ucall_ops ucall_ops_default;

#endif /* SELFTEST_KVM_UCALL_H */
