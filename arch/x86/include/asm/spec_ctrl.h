/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <asm/microcode.h>

void spec_ctrl_scan_feature(struct cpuinfo_x86 *c);
void spec_ctrl_unprotected_begin(void);
void spec_ctrl_unprotected_end(void);

static inline void __disable_indirect_speculation(void)
{
	native_wrmsrl(MSR_IA32_SPEC_CTRL, SPEC_CTRL_ENABLE_IBRS);
}

static inline void __enable_indirect_speculation(void)
{
	native_wrmsrl(MSR_IA32_SPEC_CTRL, SPEC_CTRL_DISABLE_IBRS);
}

#endif /* _ASM_X86_SPEC_CTRL_H */
