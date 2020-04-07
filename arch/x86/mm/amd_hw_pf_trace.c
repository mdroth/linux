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

struct hw_pf_cpu_stats {
	int	inflight;
	long	enter;
	long	exit;
};

static DEFINE_PER_CPU(struct hw_pf_cpu_stats, hw_pf_stats);

#define MSR_DBGU_ADDR_INDEX     0xC0011041
#define MSR_DBGU_DATA           0xC0011042
#define MSR_CORE_DBG_REG        0xC00133A0

static u32 hw_pf_status;
static u32 hw_pf_tested;

/* Note: We do not test security state (bit 31) so it is
 * not part of the mask. Once we have a test for this we
 * have to update the mask.
 */
#define HW_PF_PRE_REQ_MASK	0x7FFF0000
#define is_pre_req_capability(x)	((x) & HW_PF_PRE_REQ_MASK)

static void __set_hw_pf(bool enable, u32 capability)
{
	if (enable)
		hw_pf_status |= capability;
	else
		hw_pf_status &= ~capability;

	if (is_pre_req_capability(capability))
		hw_pf_tested |= capability;
}

static char *__hw_pf_to_str(u32 capability)
{
	if (is_pre_req_capability(capability)) {
		if (!(hw_pf_tested & capability))
			return "(skipped)";
	}

	if (hw_pf_status & capability)
		return "Enabled";

	return "Disabled";
}

#define DECLARE_HW_PF_BIT(name, shift)					\
	u32	hw_pf_bit_##name = 1 << shift;				\
									\
	static void set_hw_pf_##name(bool enable)			\
	{								\
		__set_hw_pf(enable, hw_pf_bit_##name);			\
	}								\
									\
	static char *hw_pf_##name##_to_str(void)			\
	{								\
		return __hw_pf_to_str(hw_pf_bit_##name);		\
	}								\
									\
	static bool hw_pf_##name##_enabled(void)			\
	{								\
		return hw_pf_bit_##name & hw_pf_status;			\
	}

/* Security pre-req'sare different in that we weant to set the bit
 * in the hw_pf_status field if the security is disabled.
 */
#define DECLARE_HW_PF_SEC_BIT(name, shift)				\
	u32	hw_pf_bit_##name = 1 << shift;				\
									\
	static void set_hw_pf_##name(bool enable)			\
	{								\
		__set_hw_pf(!enable, hw_pf_bit_##name);			\
	}								\
									\
	static char *hw_pf_##name##_to_str(void)			\
	{								\
		if (!(hw_pf_bit_##name & hw_pf_tested))			\
			return "(skipped)";				\
									\
		if (hw_pf_bit_##name & hw_pf_status)			\
			return "Inactive";				\
									\
		return "Active";					\
	}

DECLARE_HW_PF_BIT(trace, 0);
DECLARE_HW_PF_BIT(thread_0, 1);
DECLARE_HW_PF_BIT(thread_1, 2);
DECLARE_HW_PF_BIT(sig_writes, 3);

DECLARE_HW_PF_BIT(drb_clk, 24);
DECLARE_HW_PF_BIT(dsm_clk, 25);

DECLARE_HW_PF_BIT(core_sr, 28);
DECLARE_HW_PF_BIT(core_dbg, 29);

DECLARE_HW_PF_SEC_BIT(sec_pol, 30);
DECLARE_HW_PF_SEC_BIT(sec_state, 31);

static void reset_pre_req_testing(void)
{
	hw_pf_status &= ~HW_PF_PRE_REQ_MASK;
	hw_pf_tested = 0;
}

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

static int get_pre_req_status(void)
{
	int rc;
	u32 policy;

	reset_pre_req_testing();

	/* There is no method to validate security state
	 * pre-req status so set to false.
	 */
	printk(KERN_INFO "hw_pf_tracing: Skipping security state validation\n");
	set_hw_pf_sec_state(false);

	printk(KERN_INFO "hw_pf_tracing: Validating security policy status 0\n");
	rc = amd_smn_read(0, 0x03810A6C, &policy);
	if (rc) {
		/* If the SMN read fails, assume the security
		 * policy is active
		 */
		printk(KERN_WARNING "hw_pf_tracing: Security policy status check failed\n");
		set_hw_pf_sec_pol(true);
		return -1;
	}

	if (policy == 0) {
		set_hw_pf_sec_pol(false);
	} else {
		printk(KERN_WARNING "hw_pf_tracing: Security Policy is active\n");
		set_hw_pf_sec_pol(true);
		return -1;
	}

	/* To validate the core and clock settings we assume they are
	 * enabled. If we find they are not enabled on any cpu, the
	 * called routine will mark them as disabled.
	 */
	set_hw_pf_core_sr(true);
	set_hw_pf_core_dbg(true);

	printk(KERN_INFO "hw_pf_tracing: Validating core debug register enablement pre-requisites\n");
	on_each_cpu(get_core_pre_req_status, NULL, 1);

	if (!hw_pf_core_dbg_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: Core Debug Register 0 not set\n");
		return -1;
	}

	if (!hw_pf_core_sr_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: Core Debug Register 1 not set\n");
		return -1;
	}

	set_hw_pf_drb_clk(true);
	set_hw_pf_dsm_clk(true);

	printk(KERN_INFO "hw_pf_tracing: Validating clock enablement pre-requisites\n");
	on_each_cpu(get_clk_pre_req_status, NULL, 1);

	if (!hw_pf_drb_clk_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: DRB Clock not enabled\n");
		return -1;
	}

	if (!hw_pf_dsm_clk_enabled()) {
		printk(KERN_WARNING "hw_pf_tracing: DSM Clock not enabled\n");
		return -1;
	}

	return 0;
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

	if (hw_pf_sig_writes_enabled()) {
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

	if (hw_pf_sig_writes_enabled()) {
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
	int rc, offset;

	rc = get_pre_req_status();

	offset = sprintf(buf, "%08x\n", hw_pf_status);

	offset += sprintf(buf + offset, "Debug %s\n",
			  hw_pf_trace_to_str());
	offset += sprintf(buf + offset, "Thread 0 %s\n",
			  hw_pf_thread_0_to_str());
	offset += sprintf(buf + offset, "Thread 1 %s\n",
			  hw_pf_thread_1_to_str());
	offset += sprintf(buf + offset, "Signature Writes %s\n\n",
			  hw_pf_sig_writes_to_str());

	/* Security state check is skipped until we have a method
	 * to validate the current security state.
	 */
	offset += sprintf(buf + offset, "Security State (not tested) %s\n",
			  hw_pf_sec_state_to_str());
	offset += sprintf(buf + offset, "Security Policy %s\n",
			  hw_pf_sec_pol_to_str());
	offset += sprintf(buf + offset, "Core Debug Reg %s\n",
			  hw_pf_core_dbg_to_str());
	offset += sprintf(buf + offset, "Save/Restore Flag %s\n",
			  hw_pf_core_sr_to_str());
	offset += sprintf(buf + offset, "DSM Clock %s\n",
			  hw_pf_dsm_clk_to_str());
	offset += sprintf(buf + offset, "DRB Clock %s\n\n",
			  hw_pf_drb_clk_to_str());


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
	int rc;

	kstrtoul(buf, 0, &trace_data);

	printk(KERN_INFO "hw_pf_tracing: Updating capabilities (%08lx)\n",
	       trace_data);

	if (trace_data & 0x1) {
		/* Verify pre-requisites */
		rc = get_pre_req_status();
		if (rc) {
			printk(KERN_WARNING "hw_pf_tracing: Pre-req check failed, not enabling tracing\n");
			return count;
		}
	}

	set_hw_pf_trace(trace_data & 0x1);
	printk(KERN_INFO "hw_pf_tracing: Tracing %s\n",
	       hw_pf_trace_to_str());

	set_hw_pf_thread_0(trace_data & 0x2);
	printk(KERN_INFO "hw_pf_tracing: Thread 0 %s\n",
	       hw_pf_thread_0_to_str());

	set_hw_pf_thread_1(trace_data & 0x4);
	printk(KERN_INFO "hw_pf_tracing: Thread 1 %s\n",
	       hw_pf_thread_1_to_str());

	set_hw_pf_sig_writes(trace_data & 0x8);
	printk(KERN_INFO "hw_pf_tracing: Signature Writes %s\n",
	       hw_pf_sig_writes_to_str());

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
