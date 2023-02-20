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

#define HW_PF_VERSION	"1.01"

static long hw_pf_enter_cnt;
static long hw_pf_exit_cnt;

static long hw_pf_core0_enter_cnt;
static long hw_pf_core0_exit_cnt;

static spinlock_t hw_pf_tracing_lock;

static u32 hw_pf_status;

struct hw_pf_cpu_stats {
	int	thread;
	int	inflight;
	long	enter;
	long	exit;
};

static DEFINE_PER_CPU(struct hw_pf_cpu_stats, hw_pf_stats);

#define DECLARE_HW_PF_BIT(name, shift)					\
	u32	hw_pf_bit_##name = 1 << (shift);			\
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

#define DSM_TRIGGER_SIGWRITE	0x8000103A
#define DSM_TRIGGER_THREAD0	0x8000102F
#define DSM_TRIGGER_THREAD1	0x80001031

#define DSM_SIG_STATUS_ENTER	0x2000
#define DSM_SIG_LO_ENTER	0x0FA170
#define DSM_SIG_HI_ENTER	0x00057A11

#define DSM_SIG_STATUS_FAIL	0x1000
#define DSM_SIG_LO_FAIL		0x0FA170
#define DSM_SIG_HI_FAIL		0xDECEA5ED

#define DSM_SIG_STATUS_PASS	0x4000
#define DSM_SIG_LO_PASS		0xFFA170
#define DSM_SIG_HI_PASS		0xFDE57A11

static void __init get_core_debug_status(void *data)
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

static void __init get_drb_dsm_clk_status(void *data)
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

static void __init hw_pf_check_status(void)
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
	pr_info("hw_pf_tracing: Skipping security state validation\n");
	set_hw_pf_sec_state(false);

	pr_info("hw_pf_tracing: Validating security policy status\n");
	amd_smn_read(0, 0x03810A6C, &policy);
	if (policy == 0) {
		set_hw_pf_sec_pol(true);
	} else {
		pr_warn("hw_pf_tracing: Security Policy is active\n");
		return;
	}

	/* To validate the core and clock settings we assume they are
	 * enabled. If we find they are not enabled on any cpu, the
	 * called routine will mark them as disabled.
	 */
	set_hw_pf_core_dbg(true);
	set_hw_pf_core_sr(true);

	pr_info("hw_pf_tracing: Validating core debug register enablement\n");
	on_each_cpu(get_core_debug_status, NULL, 1);
	if (!hw_pf_core_dbg_enabled()) {
		pr_warn("hw_pf_tracing: Core Debug Register 0 not set\n");
		return;
	}

	if (!hw_pf_core_sr_enabled()) {
		pr_warn("hw_pf_tracing: Core Debug Register 1 not set\n");
		return;
	}

	set_hw_pf_drb_clk(true);
	set_hw_pf_dsm_clk(true);

	pr_info("hw_pf_tracing: Validating DRB/DSM clock enablement\n");
	on_each_cpu(get_drb_dsm_clk_status, NULL, 1);
	if (!hw_pf_drb_clk_enabled()) {
		pr_warn("hw_pf_tracing: DRB Clock not enabled\n");
		return;
	}

	if (!hw_pf_dsm_clk_enabled()) {
		pr_warn("hw_pf_tracing: DSM Clock not enabled\n");
		return;
	}
}

static void wrmsr_sig_status(u32 status)
{
	u32 lo, hi;

	rdmsr(MSR_DBGU_DATA, lo, hi);
	wrmsr(MSR_DBGU_DATA, status, hi);
}

static int hw_pf_tracing_enter(void)
{
	struct hw_pf_cpu_stats *pf_stats;
	u32 addr_lo, addr_hi;
	int cpu, thread;

	if (!hw_pf_trace_enabled())
		return -1;

	local_irq_disable();
	spin_lock(&hw_pf_tracing_lock);

	cpu = smp_processor_id();

	hw_pf_enter_cnt++;
	if (topology_core_id(cpu) == 0)
		hw_pf_core0_enter_cnt++;

	pf_stats = &per_cpu(hw_pf_stats, cpu);
	pf_stats->enter++;
	pf_stats->inflight++;

	/* No need to write MSRs again if tracing already disabled */
	if (pf_stats->inflight > 1)
		goto tracing_enter_exit;

	thread = pf_stats->thread;

	/* Save MSR_DBGU_ADDR_INDEX values */
	rdmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

	/* Write MCODE2DSM register to signal DSM triggers */
	if (hw_pf_thread_0_enabled() && thread == 0) {
		wrmsr(MSR_DBGU_ADDR_INDEX, DSM_TRIGGER_THREAD0, addr_hi);
		wrmsr_sig_status(DSM_SIG_STATUS_ENTER);
	}

	if (hw_pf_thread_1_enabled() && thread == 1) {
		wrmsr(MSR_DBGU_ADDR_INDEX, DSM_TRIGGER_THREAD1, addr_hi);
		wrmsr_sig_status(DSM_SIG_STATUS_ENTER);
	}

	if (hw_pf_signature_writes_enabled()) {
		/* Write DSM TraceAcc register for trace marker */
		wrmsr(MSR_DBGU_ADDR_INDEX, DSM_TRIGGER_SIGWRITE, addr_hi);
		wrmsr(MSR_DBGU_DATA, DSM_SIG_LO_ENTER + thread, DSM_SIG_HI_ENTER);
	}

	/* Restore MSR_DBGU_ADDR_INDEX values */
	wrmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

tracing_enter_exit:
	spin_unlock(&hw_pf_tracing_lock);
	local_irq_enable();

	return cpu;
}

static void hw_pf_tracing_exit(int rc, int cpu)
{
	struct hw_pf_cpu_stats *pf_stats;
	u32 sig_write_lo, sig_write_hi;
	u32 addr_lo, addr_hi;
	u32 sig_status;
	int thread;

	if (!hw_pf_trace_enabled())
		return;

	local_irq_disable();
	spin_lock(&hw_pf_tracing_lock);

	hw_pf_exit_cnt++;
	if (topology_core_id(cpu) == 0)
		hw_pf_core0_exit_cnt++;

	pf_stats = &per_cpu(hw_pf_stats, cpu);
	pf_stats->exit++;
	pf_stats->inflight--;

	if (pf_stats->inflight < 0)
		pr_err("HWPF: CPU %d inflight is %d\n", cpu, pf_stats->inflight);

	/* Keep logging disabled if page faults still in flight */
	if (pf_stats->inflight != 0)
		goto tracing_exit_exit;

	thread = pf_stats->thread;

	if (rc) {
		sig_status = DSM_SIG_STATUS_FAIL;
		sig_write_lo = DSM_SIG_LO_FAIL + thread;
		sig_write_hi = DSM_SIG_HI_FAIL;
	} else {
		sig_status = DSM_SIG_STATUS_PASS;
		sig_write_lo = DSM_SIG_LO_PASS + thread;
		sig_write_hi = DSM_SIG_HI_PASS;
	}

	/* Save MSR_DBGU_ADDR_INDEX values */
	rdmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

	if (hw_pf_signature_writes_enabled()) {
		/* Write trace marker */
		wrmsr(MSR_DBGU_ADDR_INDEX, DSM_TRIGGER_SIGWRITE, addr_hi);
		wrmsr(MSR_DBGU_DATA, sig_write_lo, sig_write_hi);
	}

	if (hw_pf_thread_0_enabled() && thread == 0) {
		wrmsr(MSR_DBGU_ADDR_INDEX, DSM_TRIGGER_THREAD0, addr_hi);
		wrmsr_sig_status(sig_status);
	}

	if (hw_pf_thread_1_enabled() && thread == 1) {
		wrmsr(MSR_DBGU_ADDR_INDEX, DSM_TRIGGER_THREAD1, addr_hi);
		wrmsr_sig_status(sig_status);
	}

	/* Restore MSR_DBGU_ADDR_INDEX values */
	wrmsr(MSR_DBGU_ADDR_INDEX, addr_lo, addr_hi);

tracing_exit_exit:
	spin_unlock(&hw_pf_tracing_lock);
	local_irq_enable();
}

static ssize_t hw_pf_tracing_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	int count;

	count = sysfs_emit(buf, "%08x\n", hw_pf_status);

	count += sysfs_emit_at(buf, count, "Debug %sabled\n",
			       hw_pf_trace_enabled() ? "En" : "Dis");
	count += sysfs_emit_at(buf, count, "Thread 0 %sabled\n",
			       hw_pf_thread_0_enabled() ? "En" : "Dis");
	count += sysfs_emit_at(buf, count, "Thread 1 %sabled\n",
			       hw_pf_thread_1_enabled() ? "En" : "Dis");
	count += sysfs_emit_at(buf, count, "Signature Writes %sabled\n\n",
			       hw_pf_signature_writes_enabled() ? "En" : "Dis");

	/* Security state check is skipped until we have a method
	 * to validate the current security state.
	 */
	count += sysfs_emit_at(buf, count, "Security State (skipped) %s\n",
			       hw_pf_sec_state_enabled() ? "Active" : "Disabled");
	count += sysfs_emit_at(buf, count, "Security Policy %s\n",
			       hw_pf_sec_pol_enabled() ? "Active" : "Disabled");
	count += sysfs_emit_at(buf, count,  "Core Debug Reg %sabled\n",
			       hw_pf_core_dbg_enabled() ? "En" : "Dis");
	count += sysfs_emit_at(buf, count,  "Save/Restore Flag %sabled\n",
			       hw_pf_core_sr_enabled() ? "En" : "Dis");
	count += sysfs_emit_at(buf, count, "DSM Clock %sabled\n",
			       hw_pf_dsm_clk_enabled() ? "En" : "Dis");
	count += sysfs_emit_at(buf, count, "DRB Clock %sabled\n\n",
			       hw_pf_drb_clk_enabled() ? "En" : "Dis");

	count += sysfs_emit_at(buf, count, "Hit Counts: (enter/exit)\n");
	count += sysfs_emit_at(buf, count, "    Total:  %ld/%ld\n",
			       hw_pf_enter_cnt, hw_pf_exit_cnt);
	count += sysfs_emit_at(buf, count, "    Core 0: %ld/%ld\n",
			       hw_pf_core0_enter_cnt, hw_pf_core0_exit_cnt);

	return count;
}

static ssize_t hw_pf_tracing_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned long trace_data;
	int rc;

	rc = kstrtoul(buf, 0, &trace_data);
	if (rc) {
		pr_err("hw_pf_tracing: Invalid capabilities \"%s\"\n", buf);
		return -EINVAL;
	}

	/* Enable/Disable Tracing */
	set_hw_pf_trace(trace_data & 0x01);

	/* Update any addditional tracing parameters */
	set_hw_pf_thread_0(trace_data & 0x2);
	set_hw_pf_thread_1(trace_data & 0x4);
	set_hw_pf_signature_writes(trace_data & 0x8);

	return count;
}

static ssize_t hw_pf_stats_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct hw_pf_cpu_stats *pf_stats;
	long enter, exit;
	int count;
	int cpu;

	count = sysfs_emit(buf, "Hit Counts: %ld/%ld (enter/exit)\n",
			   hw_pf_enter_cnt, hw_pf_exit_cnt);

	enter = 0;
	exit = 0;

	for_each_online_cpu(cpu) {
		pf_stats = &per_cpu(hw_pf_stats, cpu);

		enter += pf_stats->enter;
		exit += pf_stats->exit;

		if (enter != exit)
			count += sysfs_emit_at(buf, count, "    CPU %d: %ld/%ld\n",
					       cpu, enter, exit);
	}

	count += sysfs_emit_at(buf, count, "    CPU Totals: %ld%c/%ld%c\n",
			       enter, enter == hw_pf_enter_cnt ? ' ' : '*',
			       exit, exit == hw_pf_exit_cnt ? ' ' : '*');

	return count;
}

static ssize_t hw_pf_version_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", HW_PF_VERSION);
}

static struct kobj_attribute tracing_attr =
	__ATTR(hw_pf_tracing, 0644, hw_pf_tracing_show, hw_pf_tracing_store);
static struct kobj_attribute tracing_stats_attr =
	__ATTR(hw_pf_stats, 0644, hw_pf_stats_show, NULL);
static struct kobj_attribute version_attr =
	__ATTR(hw_pf_version, 0444, hw_pf_version_show, NULL);

static int __init hw_page_fault_trace_init(void)
{
	struct hw_pf_cpu_stats *pf_stats;
	int cpu;
	int rc;

	spin_lock_init(&hw_pf_tracing_lock);

	hw_pf_status = 0;
	hw_pf_enter_cnt = 0;
	hw_pf_exit_cnt = 0;
	hw_pf_core0_enter_cnt = 0;
	hw_pf_core0_exit_cnt = 0;

	hw_pf_check_status();

	if (topology_smt_supported()) {
		for_each_online_cpu(cpu) {
			if (!topology_is_primary_thread(cpu)) {
				pf_stats = &per_cpu(hw_pf_stats, cpu);
				pf_stats->thread = 1;
			}
		}
	}

	rc = sysfs_create_file(mm_kobj, &tracing_attr.attr);
	rc |= sysfs_create_file(mm_kobj, &tracing_stats_attr.attr);
	rc |= sysfs_create_file(mm_kobj, &version_attr.attr);

	return rc;
}
late_initcall(hw_page_fault_trace_init);
