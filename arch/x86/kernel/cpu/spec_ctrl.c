#include <linux/string.h>

#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>

static bool ibrs_admin_enabled;

void spec_ctrl_scan_feature(struct cpuinfo_x86 *c)
{
	if (boot_cpu_has(X86_FEATURE_SPEC_CTRL)) {
		if (ibrs_admin_enabled)
			set_cpu_cap(c, X86_FEATURE_SPEC_CTRL_IBRS);
	}
}

static int __init check_ibrs_param(char *str)
{
	if (strcmp(str, "ibrs") == 0)
		ibrs_admin_enabled = true;

	return 0;
}
early_param("spectre_v2", check_ibrs_param);
