// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include "util/evsel.h"
#include "util/env.h"
#include "linux/string.h"
#include "util/pmu.h"
#include "util/debug.h"

void arch_evsel__set_sample_weight(struct evsel *evsel)
{
	evsel__set_sample_bit(evsel, WEIGHT_STRUCT);
}

void arch_evsel__fixup_new_cycles(struct perf_event_attr *attr)
{
	struct perf_env env = { .total_mem = 0, } ;

	if (!perf_env__cpuid(&env))
		return;

	/*
	 * On AMD, precise cycles event sampling internally uses IBS pmu.
	 * But IBS does not have filtering capabilities and perf by default
	 * sets exclude_guest = 1. This makes IBS pmu event init fail and
	 * thus perf ends up doing non-precise sampling. Avoid it by clearing
	 * exclude_guest.
	 */
	if (env.cpuid && strstarts(env.cpuid, "AuthenticAMD"))
		attr->exclude_guest = 0;

	free(env.cpuid);
}

void arch_evsel__warn_ambiguity(struct evsel *evsel, struct perf_event_attr *attr)
{
	struct perf_env *env = evsel__env(evsel);
	struct perf_pmu *evsel_pmu = evsel__find_pmu(evsel);
	struct perf_pmu *ibs_fetch_pmu = perf_pmu__find("ibs_fetch");
	struct perf_pmu *ibs_op_pmu = perf_pmu__find("ibs_op");
	static int warned_once;

	if (warned_once || !perf_env__cpuid(env) || !env->cpuid ||
	   !strstarts(env->cpuid, "AuthenticAMD") || !evsel_pmu)
		return;

	if (ibs_fetch_pmu && ibs_fetch_pmu->type == evsel_pmu->type) {
		if (attr->config & (1ULL << 59)) {
			pr_warning(
"WARNING: Hw internally reset sampling period when L3 Miss Filtering is enabled\n"
"and tagged operation does not cause L3 Miss. This causes sampling period skew.\n");
		}
	} else if (ibs_op_pmu && ibs_op_pmu->type == evsel_pmu->type) {
		if (attr->config & (1ULL << 16)) {
			pr_warning(
"WARNING: Hw internally reset sampling period when L3 Miss Filtering is enabled\n"
"and tagged operation does not cause L3 Miss. This causes sampling period skew.\n");
		}
	}

	warned_once = 1;
}
