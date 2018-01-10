#include <linux/string.h>

#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>

static bool ibrs_admin_enabled;
DEFINE_STATIC_KEY_FALSE(spec_ctrl_dynamic_ibrs);

void spec_ctrl_scan_feature(struct cpuinfo_x86 *c)
{
	if (boot_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		if (ibrs_admin_enabled) {
			set_cpu_cap(c, X86_FEATURE_SPEC_CTRL_IBRS);
			if (!c->cpu_index)
				static_branch_enable(&spec_ctrl_dynamic_ibrs);
		}
	}
}

static int __init check_ibrs_param(char *str)
{
	if (strcmp(str, "ibrs") == 0)
		ibrs_admin_enabled = true;

	return 0;
}
early_param("spectre_v2", check_ibrs_param);

/*
 * Interrupts must be disabled to begin unprotected speculation.
 * Otherwise interrupts could come in and start running in unprotected mode.
 */

void spec_ctrl_unprotected_begin(void)
{
	/* should use lockdep_assert_irqs_disabled() when available */
	WARN_ON_ONCE(!irqs_disabled());
	if (static_branch_unlikely(&spec_ctrl_dynamic_ibrs))
		__enable_indirect_speculation();
}
EXPORT_SYMBOL_GPL(spec_ctrl_unprotected_begin);

void spec_ctrl_unprotected_end(void)
{
	if (static_branch_unlikely(&spec_ctrl_dynamic_ibrs))
		__disable_indirect_speculation();
}
EXPORT_SYMBOL_GPL(spec_ctrl_unprotected_end);
