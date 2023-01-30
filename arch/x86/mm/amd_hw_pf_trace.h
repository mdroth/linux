/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The functionality provided is meant to give hw developers
 * the ability to disable hardware tracing during page faults
 * and provide them with the results of page faults.
 *
 * Design doc available:
 * http://mhdcwww.amd.com/systems/projects/e64/genesis/debug/linux_AMDSoS_PF_debug_instrumentation
 */

void hw_pf_tracing_enter(void);
void hw_pf_tracing_exit(int rc);
