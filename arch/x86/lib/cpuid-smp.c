/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/export.h>
#include <linux/smp.h>
#include <asm/cpuid.h>

struct cpuid_info {
	u32 op;
	struct cpuid_regs regs;
};

static void __cpuid_smp(void *info)
{
	struct cpuid_info *rv = info;

	cpuid(rv->op, &rv->regs.eax, &rv->regs.ebx, &rv->regs.ecx, &rv->regs.edx);
}

int cpuid_on_cpu(unsigned int cpu, unsigned int op,
		 unsigned int *eax, unsigned int *ebx,
		 unsigned int *ecx, unsigned int *edx)
{
	struct cpuid_info rv;
	int err;

	memset(&rv, 0, sizeof(rv));

	rv.op = op;
	err = smp_call_function_single(cpu, __cpuid_smp, &rv, 1);
	*eax = rv.regs.eax;
	*ebx = rv.regs.ebx;
	*ecx = rv.regs.ecx;
	*edx = rv.regs.edx;

	return err;
}
EXPORT_SYMBOL(cpuid_on_cpu);
