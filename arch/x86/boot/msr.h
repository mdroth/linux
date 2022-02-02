/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Helpers/definitions related to MSR access.
 */

#ifndef BOOT_MSR_H
#define BOOT_MSR_H

#include <asm/shared/msr.h>

static inline void rd_msr(unsigned int msr, struct msr *m)
{
	asm volatile("rdmsr" : "=a" (m->l), "=d" (m->h) : "c" (msr));
}

static inline void wr_msr(unsigned int msr, const struct msr *m)
{
	asm volatile("wrmsr" : : "c" (msr), "a"(m->l), "d" (m->h) : "memory");
}

#endif /* BOOT_MSR_H */
