// SPDX-License-Identifier: GPL-2.0

/*
 * This file is written to be #include'ed by fault.c.
 *
 * The functionality provided is meant to give hw developers
 * the ability to disable hardware tracing during page faults
 * and provide them with the results of page faults.
 *
 * Design doc available:
 * http://mhdcwww.amd.com/systems/projects/e64/genesis/debug/linux_AMDSoS_PF_debug_instrumentation
 */

#include <asm/amd_nb.h>

static long hw_pf_enter_cnt;
static long hw_pf_exit_cnt;

static long hw_pf_core0_enter_cnt;
static long hw_pf_core0_exit_cnt;

static spinlock_t hw_pf_tracing_lock;

static u32 hw_pf_status;

struct hw_pf_cpu_stats {
	int	inflight;
	long	enter;
	long	exit;
};

static DEFINE_PER_CPU(struct hw_pf_cpu_stats, hw_pf_stats);

#define DECLARE_HW_PF_BIT(name, shift)					\
	u32	hw_pf_bit_##name = 1 << shift;				\
									\
	static void set_hw_pf_##name(bool enable)			\
	{								\
		if (enable)						\
			hw_pf_status |= hw_pf_bit_##name;		\
		else							\
			hw_pf_status &= ~hw_pf_bit_##name;		\
	}								\
									\
	static bool hw_pf_##name##_enabled(void)			\
	{								\
		return hw_pf_status & hw_pf_bit_##name;			\
	}

DECLARE_HW_PF_BIT(trace, 0);
DECLARE_HW_PF_BIT(thread_0, 1);
DECLARE_HW_PF_BIT(thread_1, 2);
DECLARE_HW_PF_BIT(signature_writes, 3);

DECLARE_HW_PF_BIT(drb_clk, 24);
DECLARE_HW_PF_BIT(dsm_clk, 25);

DECLARE_HW_PF_BIT(core_sr, 28);
DECLARE_HW_PF_BIT(core_dbg, 29);

DECLARE_HW_PF_BIT(sec_pol, 30);
DECLARE_HW_PF_BIT(sec_state, 31);

#define MSR_DBGU_ADDR_INDEX	0xC0011041
#define MSR_DBGU_DATA		0xC0011042
#define MSR_CORE_DBG_REG	0xC00133A0

static void get_core_pre_req_status(void *data)
{
	u32 lo, hi;
	int cpu;

	/* Only need to do this for T0 */
	cpu = smp_processor_id();
	if (topology_smt_supported() && !topology_is_primary_thread(cpu))
		return;

	rdmsr(MSR_CORE_DBG_REG, lo, hi);

	if ((lo & 0x00000002) == 0)
		set_hw_pf_core_sr(false);

	if ((lo & 0x00000001) == 0)
		set_hw_pf_core_dbg(false);
}

static void get_clk_pre_req_status(void *data)
{
	u32 saved_lo, saved_hi;
	u32 drb, dsm;
	u32 lo, hi;
	int cpu;

	/* Only need to do this for T0 */
	cpu = smp_processor_id();
	if (topology_smt_supported() && !topology_is_primary_thread(cpu))
		return;

	spin_lock(&hw_pf_tracing_lock);

	/* Check DRM/DSM Clocks */
	rdmsr(MSR_DBGU_ADDR_INDEX, saved_lo, saved_hi);

	wrmsr(MSR_DBGU_ADDR_INDEX, 0, saved_hi);
	rdmsr(MSR_DBGU_DATA, lo, hi);

	/* From design spec, OR together bits 5 and 2 */
	drb = ((lo & (1 << 5)) | (lo & (1 << 2)));
	if (drb == 0)
		set_hw_pf_drb_clk(false);

	/* From design spec, OR together bits 6 and 3 */
	dsm = ((lo & (1 << 6)) | (lo & (1 << 3)));
	if (dsm == 0)
		set_hw_pf_dsm_clk(false);

	wrmsr(MSR_DBGU_ADDR_INDEX, saved_lo, saved_hi);
	spin_unlock(&hw_pf_tracing_lock);
}

static void get_pre_req_status(void)
{
	u32 policy;

	/* Set all capabilities to false. As we progress through checking
	 * each of the pre-req's they will be manipulated to validate system
	 * status.
	 */
	set_hw_pf_core_sr(false);
	set_hw_pf_core_dbg(false);
	set_hw_pf_drb_clk(false);
	set_hw_pf_dsm_clk(false);
	set_hw_pf_sec_pol(false);

	/* There is no method to validate security state
	 * pre-req status so set to false.
	 */
	printk(KERN_INFO "hw_pf_tracing: Skipping security state validation\n");
	set_hw_pf_sec_state(false);

	printk(KERN_INFO "hw_pf_tracing: Validating security policy status\n");
	amd_smn_read(0, 0x03810A6C, &policy);
	if (policy == 0) {
		set_hw_pf_sec_pol(true);
	} else {
		printk(KERN_WARNING "hw_pf_tracing: Security Policy is active\n");
		return;
	}

	/* To validate the core and clock settings we assume they are
	 * enabled. If we find they are not enabled on any cpu, the
	 * called routine will mark them as disabled.
	 */
	set_hw_pf_core_dbg(true);
	set_hw_pf_core_sr(true);

	printk(KERN_INFO "hw_pf_tracing: Validating core debug register enablement pre-requisites\n");
	on_each_cpu(get_core_pre_req_status, NULL, 1);
	if (!hw_pf_core_dbg_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: Core Debug Register 0 not set\n");
		return;
	}

	if (!hw_pf_core_sr_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: Core Debug Register 1 not set\n");
		return;
	}

	set_hw_pf_drb_clk(true);
	set_hw_pf_dsm_clk(true);

	printk(KERN_INFO "hw_pf_tracing: Validating clock enablement pre-requisites\n");
	on_each_cpu(get_clk_pre_req_status, NULL, 1);
	if (!hw_pf_drb_clk_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: DRB Clock not enabled\n");
		return;
	}

	if (!hw_pf_dsm_clk_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: DSM Clock not enabled\n");
		return;
	}
}

static void wrmsr_sig_status(u32 status)
{
	u32 lo, hi;

	rdmsr(MSR_DBGU_DATA, lo, hi);
	wrmsr(MSR_DBGU_DATA, status, hi);
}

static void hw_pf_tracing_enter(void)
{
	struct hw_pf_cpu_stats *pf_stats;
	int thread, cpu;
	u32 addr_lo, addr_hi;
	u32 trace_acc_lo;

	if (!hw_pf_trace_enabled())
		return;

	cpu = smp_processor_id();
	if (topology_smt_supported() && !topology_is_primary_thread(cpu))
		thread = 1;
	else
		thread = 0;

	spin_lock(&hw_pf_tracing_lock);
	hw_pf_enter_cnt++;

	if (topology_core_id(cpu) == 0)
		hw_pf_core0_enter_cnt++;

	/* this_cpu_inc(hw_pf_inflight); */
	pf_stats = &per_cpu(hw_pf_stats, cpu);

	pf_stats->enter++;
	pf_stats->inflight = 1;

	/* Save MSR_DBGU_ADDR_INDEX values */
	rdmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

	/* Write MCODE2DSM register to signal DSM triggers */
	if (hw_pf_thread_0_enabled() && (thread == 0)) {
		trace_acc_lo = 0x0FA170;
		wrmsr(MSR_DBGU_ADDR_INDEX, 0x8000102F, addr_hi);
		wrmsr_sig_status(0x2000);
	}

	if (hw_pf_thread_1_enabled() && (thread == 1)) {
		trace_acc_lo = 0x0FA171;
		wrmsr(MSR_DBGU_ADDR_INDEX, 0x80001031, addr_hi);
		wrmsr_sig_status(0x2000);
	}

	if (hw_pf_signature_writes_enabled()) {
		/* Write DSM TraceAcc register for trace marker */
		wrmsr(MSR_DBGU_ADDR_INDEX, 0x8000103A, addr_hi);
		wrmsr(MSR_DBGU_DATA, trace_acc_lo, 0x00057A11);
	}

	/* Restore MSR_DBGU_ADDR_INDEX values */
	wrmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

	spin_unlock(&hw_pf_tracing_lock);
}

static void hw_pf_tracing_exit(int rc)
{
	struct hw_pf_cpu_stats *pf_stats;
	u32 sig_write_lo, sig_write_hi;
	u32 addr_lo, addr_hi;
	u32 sig_status;
	int cpu, thread;

	if (!hw_pf_trace_enabled())
		return;

	cpu = smp_processor_id();
	if (topology_smt_supported() && !topology_is_primary_thread(cpu))
		thread = 1;
	else
		thread = 0;

	spin_lock(&hw_pf_tracing_lock);

	pf_stats = &per_cpu(hw_pf_stats, cpu);

	if (pf_stats->inflight == 0) {
		spin_unlock(&hw_pf_tracing_lock);
		return;
	}

	pf_stats->exit++;
	pf_stats->inflight = 0;

	hw_pf_exit_cnt++;

	if (topology_core_id(cpu) == 0)
		hw_pf_core0_exit_cnt++;

	if (rc) {
		sig_status = 0x1000;
		sig_write_lo = 0x0FA170 + thread;
		sig_write_hi = 0xDECEA5ED;
	} else {
		sig_status = 0x4000;
		sig_write_lo = 0xFFA170 + thread;
		sig_write_hi = 0xFDE57A11;
	}

	/* Save MSR_DBGU_ADDR_INDEX values */
	rdmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

	if (hw_pf_signature_writes_enabled()) {
		/* Write trace marker */
		wrmsr(MSR_DBGU_ADDR_INDEX, 0x8000103A, addr_hi);
		wrmsr(MSR_DBGU_DATA, sig_write_lo, sig_write_hi);
	}

	if (hw_pf_thread_0_enabled() && (thread == 0)) {
		wrmsr(MSR_DBGU_ADDR_INDEX, 0x8000102F, addr_hi);
		wrmsr_sig_status(sig_status);
	}

	if (hw_pf_thread_1_enabled() && (thread == 1)) {
		wrmsr(MSR_DBGU_ADDR_INDEX, 0x80001031, addr_hi);
		wrmsr_sig_status(sig_status);
	}

	/* Restore MSR_DBGU_ADDR_INDEX values */
	wrmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

	spin_unlock(&hw_pf_tracing_lock);
}

static ssize_t hw_pf_tracing_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	int offset;

	get_pre_req_status();

	offset = sprintf(buf, "%08x\n", hw_pf_status);

	offset += sprintf(buf + offset, "Debug %sabled\n",
			  hw_pf_trace_enabled() ? "En" : "Dis");
	offset += sprintf(buf + offset, "Thread 0 %sabled\n",
			  hw_pf_thread_0_enabled() ? "En" : "Dis");
	offset += sprintf(buf + offset, "Thread 1 %sabled\n",
			  hw_pf_thread_1_enabled() ? "En" : "Dis");
	offset += sprintf(buf + offset, "Signature Writes %sabled\n\n",
			  hw_pf_signature_writes_enabled() ? "En" : "Dis");

	/* Security state check is skipped until we have a method
	 * to validate the current security state.
	 */
	offset += sprintf(buf + offset, "Security State (skipped) %s\n",
			  hw_pf_sec_state_enabled() ? "Active" : "Disabled");
	offset += sprintf(buf + offset, "Security Policy %s\n",
			  hw_pf_sec_pol_enabled() ? "Active" : "Disabled");
	offset += sprintf(buf + offset, "Core Debug Reg %sabled\n",
			  hw_pf_core_dbg_enabled() ? "En" : "Dis");
	offset += sprintf(buf + offset, "Save/Restore Flag %sabled\n",
			  hw_pf_core_sr_enabled() ? "En" : "Dis");
	offset += sprintf(buf + offset, "DSM Clock %sabled\n",
			  hw_pf_dsm_clk_enabled() ? "En" : "Dis");
	offset += sprintf(buf + offset, "DRB Clock %sabled\n\n",
			  hw_pf_drb_clk_enabled() ? "En" : "Dis");


	offset += sprintf(buf + offset, "Hit Counts: (enter/exit)\n");
	offset += sprintf(buf + offset, "    Total:  %ld/%ld\n",
			  hw_pf_enter_cnt, hw_pf_exit_cnt);
	offset += sprintf(buf + offset, "    Core 0: %ld/%ld\n",
			  hw_pf_core0_enter_cnt, hw_pf_core0_exit_cnt);

	return offset;
}

static ssize_t hw_pf_tracing_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned long trace_data;

	kstrtoul(buf, 0, &trace_data);

	printk(KERN_INFO "hw_pf_tracing: Updating capabilities (%08lx)\n",
	       trace_data);

	if (trace_data & 0x1) {
		/* Enabling tracing, check pre-reqs
		 *
		 * Gather data but do not use yet.
		 */
		get_pre_req_status();

		printk(KERN_WARNING "hw_pf_tracing: Enabling Tracing without verifying pre-requisites\n");
		set_hw_pf_trace(1);
	} else {
		printk(KERN_INFO "hw_pf_tracing: Disabling Tracing\n");
		set_hw_pf_trace(0);
	}

	/* Update any addditional tracing parameters */
	set_hw_pf_thread_0(trace_data & 0x2);
	set_hw_pf_thread_1(trace_data & 0x4);
	set_hw_pf_signature_writes(trace_data & 0x8);

	printk(KERN_INFO "hw_pf_tracing: Thread 0 %sabled\n",
	       hw_pf_thread_0_enabled() ? "En" : "Dis");
	printk(KERN_INFO "hw_pf_tracing: Thread 1 %sabled\n",
	       hw_pf_thread_1_enabled() ? "En" : "Dis");
	printk(KERN_INFO "hw_pf_tracing: Signature writes %sabled\n",
	       hw_pf_signature_writes_enabled() ? "En" : "Dis");

	return count;
}

static ssize_t hw_pf_stats_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct hw_pf_cpu_stats *pf_stats;
	int offset;
	int cpu;
	long enter, exit;

	offset = sprintf(buf, "Hit Counts: (enter/exit)\n");
	offset += sprintf(buf + offset, "    Total:  %ld/%ld\n",
			  hw_pf_enter_cnt, hw_pf_exit_cnt);

	enter = exit = 0;
	for_each_online_cpu(cpu) {
		pf_stats = &per_cpu(hw_pf_stats, cpu);

		if ((pf_stats->enter == 0) && (pf_stats->exit == 0))
			continue;

		enter += pf_stats->enter;
		exit += pf_stats->exit;

		offset += sprintf(buf + offset, "    CPU %d: %ld/%ld%c\n", cpu,
				pf_stats->enter, pf_stats->exit,
				pf_stats->enter == pf_stats->exit ? ' ' : '*');
	}

	offset += sprintf(buf + offset, "    CPU Totals: %ld%c/%ld%c\n",
			  enter, enter == hw_pf_enter_cnt ? ' ' : '*',
			  exit, exit == hw_pf_exit_cnt ? ' ' : '*');

	return offset;
}

static struct kobj_attribute tracing_attr =
	__ATTR(hw_pf_tracing, 0644, hw_pf_tracing_show, hw_pf_tracing_store);
static struct kobj_attribute tracing_stats_attr =
	__ATTR(hw_pf_stats, 0644, hw_pf_stats_show, NULL);

static int __init hw_page_fault_trace_init(void)
{
	int rc;

	spin_lock_init(&hw_pf_tracing_lock);

	hw_pf_status = 0;
	hw_pf_enter_cnt = 0;
	hw_pf_exit_cnt = 0;
	hw_pf_core0_enter_cnt = 0;
	hw_pf_core0_exit_cnt = 0;

	rc = sysfs_create_file(mm_kobj, &tracing_attr.attr);
	rc |= sysfs_create_file(mm_kobj, &tracing_stats_attr.attr);
	return rc;
}
late_initcall(hw_page_fault_trace_init);
