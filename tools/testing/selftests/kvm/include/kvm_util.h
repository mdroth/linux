/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * tools/testing/selftests/kvm/include/kvm_util.h
 *
 * Copyright (C) 2018, Google LLC.
 */
#ifndef SELFTEST_KVM_UTIL_H
#define SELFTEST_KVM_UTIL_H

#include "kvm_util_base.h"
/*
 * TODO: ucall.h contains arch-specific declarations along with
 * ucall_common.h. For now only a subset of archs provide the
 * new header. Once all archs implement the new header the #include for
 * ucall_common.h can be dropped.
 */
#ifdef __x86_64__
#include "ucall.h"
#else
#include "ucall_common.h"
#endif

#endif /* SELFTEST_KVM_UTIL_H */
