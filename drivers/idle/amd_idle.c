/*
 * AMD Idle Driver - AMD Internal only
 */

#define pr_fmt(fmt)	"AMD IDLE: " fmt

#include <asm/cpu_device_id.h>
#include <asm/mwait.h>
#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/module.h>
#include <linux/tick.h>

#define DEBUG

#define AMD_IDLE_VERSION "0.5.0"

MODULE_LICENSE("GPL");

static struct cpuidle_driver amd_idle_driver = {
	.name = "amd_idle",
	.owner = THIS_MODULE,
};

static int max_cstate = CPUIDLE_STATE_MAX - 1;
static int c2_latency;
static int c2_residency;
static bool enabled = false;

static unsigned int mwait_substates;

#define LAPIC_TIMER_ALWAYS_RELIABLE 0xFFFFFFFF
/*
 * Reliable LAPIC Timer States, bit 1 for C1 etc.
 * Default to only C1
 */
static unsigned int lapic_timer_reliable_states = (1 << 1);

struct idle_cpu {
	struct cpuidle_state *state_table;
};

static const struct idle_cpu *icpu;
static struct cpuidle_device __percpu *amd_idle_cpuidle_devices;
static struct cpuidle_state *cpuidle_state_table __initdata;

/*
 * Set this flag for states where the HW flushes the TLB for us
 * and so we don't need cross-calls to keep it consistent.
 * If this flag is set, SW flushes the TLB, so even if the
 * HW doesn't do the flushing, this flag is safe to use.
 */
#define CPUIDLE_FLAG_TLB_FLUSHED	0x10000

/*
 * MWAIT takes an 8-bit "hint" in EAX "suggesting"
 * the C-state (top nibble) and sub-state (bottom nibble)
 * 0x00 means "MWAIT(C1)", 0x10 means "MWAIT(C2)" etc.
 *
 * We store the hint at the top of our "flags" for each state.
 */
#define flg2MWAIT(flags) (((flags) >> 24) & 0xFF)
#define MWAIT2flg(eax) ((eax & 0xFF) << 24)

/**
 * amd_idle
 * @dev: cpuidle_device
 * @drv: cpuidle driver
 * @index: index of cpuidle state
 *
 * Must be called under local_irq_disable().
 */
static __cpuidle int amd_idle(struct cpuidle_device *dev,
			      struct cpuidle_driver *drv, int index)
{
	unsigned long ecx = 1; /* break on interrupt flag */
	struct cpuidle_state *state = &drv->states[index];
	unsigned long eax = flg2MWAIT(state->flags);
	unsigned int cstate;
	int cpu = smp_processor_id();

	cstate = (((eax) >> MWAIT_SUBSTATE_SIZE) & MWAIT_CSTATE_MASK) + 1;

	/*
	 * leave_mm() to avoid costly and often unnecessary wakeups
	 * for flushing the user TLB's associated with the active mm.
	 */
	if (state->flags & CPUIDLE_FLAG_TLB_FLUSHED)
		leave_mm(cpu);

	if (!(lapic_timer_reliable_states & (1 << (cstate))))
		tick_broadcast_enter();

	mwait_idle_with_hints(eax, ecx);

	if (!(lapic_timer_reliable_states & (1 << (cstate))))
		tick_broadcast_exit();

	return index;
}

/**
 * amd_s2idle
 * @dev: cpuidle_device
 * @drv: cpuidle driver
 * @index: state index
 *
 * Simplified "enter" callback routine for suspend-to-idle.
 */
static void amd_s2idle(struct cpuidle_device *dev,
		       struct cpuidle_driver *drv, int index)
{
	unsigned long ecx = 1; /* break on interrupt flag */
	unsigned long eax = flg2MWAIT(drv->states[index].flags);

	mwait_idle_with_hints(eax, ecx);
}

/*
 * States are indexed by the cstate number,
 * which is also the index into the MWAIT hint array.
 * Thus C0 is a dummy.
 */
static struct cpuidle_state default_cstates[] = {
	{
		.name = "C1",
		.desc = "MWAIT 0x00",
		.flags = MWAIT2flg(0x00),
		.exit_latency = 1,
		.target_residency = 2,
		.enter = &amd_idle,
		.enter_s2idle = amd_s2idle, },
	{
		.name = "C2",
		.desc = "MWAIT 0x10",
		.flags = MWAIT2flg(0x10) | CPUIDLE_FLAG_TLB_FLUSHED,
		.exit_latency = 400,
		.target_residency = 800,
		.enter = &amd_idle,
		.enter_s2idle = amd_s2idle, },
	{
		.enter = NULL }
};

static void __setup_broadcast_timer(bool on)
{
	if (on)
		tick_broadcast_enable();
	else
		tick_broadcast_disable();
}

static const struct idle_cpu default_idle_cpu = {
	.state_table = default_cstates,
};

static const struct x86_cpu_id amd_idle_ids[] __initconst = {
	{
		.vendor = X86_VENDOR_AMD,
		.family = 0x17,
		.model = X86_MODEL_ANY,
		.feature = X86_FEATURE_MWAIT,
		.driver_data = (unsigned long)&default_idle_cpu
	},
	{}
};

/**
 * amd_idle_probe
 */
static int __init amd_idle_probe(void)
{
	unsigned int eax, ebx, ecx;
	const struct x86_cpu_id *id;

	id = x86_match_cpu(amd_idle_ids);
	if (!id) {
		pr_info("does not run on family %d model %d\n",
			boot_cpu_data.x86, boot_cpu_data.x86_model);
		return -ENODEV;
	}

	if (boot_cpu_data.cpuid_level < CPUID_MWAIT_LEAF)
		return -ENODEV;

	cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &mwait_substates);

	/* HACK: EDX is reserved on AMD systems */
	mwait_substates = ~0;

	if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
	    !(ecx & CPUID5_ECX_INTERRUPT_BREAK) ||
	    !mwait_substates)
		return -ENODEV;

	pr_info("MWAIT substates: 0x%x\n", mwait_substates);

	icpu = (const struct idle_cpu *)id->driver_data;
	cpuidle_state_table = icpu->state_table;

	pr_info("v" AMD_IDLE_VERSION " model 0x%X\n",
		boot_cpu_data.x86_model);

	return 0;
}

/**
 * amd_idle_cpuidle_devices_uninit
 *
 * Unregisters the cpuidle devices.
 */
static void amd_idle_cpuidle_devices_uninit(void)
{
	int i;
	struct cpuidle_device *dev;

	for_each_online_cpu(i) {
		dev = per_cpu_ptr(amd_idle_cpuidle_devices, i);
		cpuidle_unregister_device(dev);
	}
}

/**
 * update_c2_state
 * @cstate - index into cstate table
 *
 * Update any C2 state values specified via module parameters
 */
static void update_c2_state(int cstate)
{
	if (c2_latency)
		cpuidle_state_table[cstate].exit_latency = c2_latency;

	if (c2_residency)
		cpuidle_state_table[cstate].target_residency = c2_residency;
}

/**
 * amd_idle_cpuidle_driver_init
 *
 * allocate, initialize cpuidle_states
 */
static void __init amd_idle_cpuidle_driver_init(void)
{
	int cstate;
	struct cpuidle_driver *drv = &amd_idle_driver;

	cpuidle_poll_state_init(drv);

	drv->state_count = 1;

	for (cstate = 0; cstate < CPUIDLE_STATE_MAX; ++cstate) {
		int num_substates, mwait_hint, mwait_cstate;

		if ((cpuidle_state_table[cstate].enter == NULL) &&
		    (cpuidle_state_table[cstate].enter_s2idle == NULL))
			break;

		if (cstate + 1 > max_cstate) {
			pr_info("max_cstate %d reached\n", max_cstate);
			break;
		}

		mwait_hint = flg2MWAIT(cpuidle_state_table[cstate].flags);
		mwait_cstate = MWAIT_HINT2CSTATE(mwait_hint);

		/* number of sub-states for this state in CPUID.MWAIT */
		num_substates = (mwait_substates >> ((mwait_cstate + 1) * 4))
				& MWAIT_SUBSTATE_MASK;

		/* if NO sub-states for this state in CPUID, skip it */
		if (num_substates == 0)
			continue;

		/* if state marked as disabled, skip it */
		if (cpuidle_state_table[cstate].flags & CPUIDLE_FLAG_UNUSABLE) {
			pr_info("state %s is disabled",
				cpuidle_state_table[cstate].name);
			continue;
		}


		if (((mwait_cstate + 1) > 2) &&
			!boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
			mark_tsc_unstable("TSC halts in idle states deeper than C2");

		/* Update table for C2 state if needed. */
		if (!strcmp(cpuidle_state_table[cstate].name, "C2"))
			update_c2_state(cstate);

		pr_info("state %s exit_latency=%dus target_residency=%dus\n",
			cpuidle_state_table[cstate].name,
			cpuidle_state_table[cstate].exit_latency,
			cpuidle_state_table[cstate].target_residency);

		/* structure copy */
		drv->states[drv->state_count] = cpuidle_state_table[cstate];

		drv->state_count++;
	}
}


/**
 * amd_idle_cpu_init
 * @cpu: cpu/core to initialize
 *
 * allocate, initialize, register cpuidle_devices
 */
static int amd_idle_cpu_init(unsigned int cpu)
{
	struct cpuidle_device *dev;

	dev = per_cpu_ptr(amd_idle_cpuidle_devices, cpu);
	dev->cpu = cpu;

	if (cpuidle_register_device(dev)) {
		pr_info("cpuidle_register_device %d failed!\n", cpu);
		return -EIO;
	}

	return 0;
}

static int amd_idle_cpu_online(unsigned int cpu)
{
	struct cpuidle_device *dev;

	if (lapic_timer_reliable_states != LAPIC_TIMER_ALWAYS_RELIABLE)
		__setup_broadcast_timer(true);

	/*
	 * Some systems can hotplug a cpu at runtime after
	 * the kernel has booted, we have to initialize the
	 * driver in this case
	 */
	dev = per_cpu_ptr(amd_idle_cpuidle_devices, cpu);
	if (!dev->registered)
		return amd_idle_cpu_init(cpu);

	return 0;
}

static int __init amd_idle_init(void)
{
	int retval;

	/* Do not load amd_idle at all for now if idle= is passed */
	if (boot_option_idle_override != IDLE_NO_OVERRIDE)
		return -ENODEV;

	/* AMD idle driver is disabled by default, do not load unless
	 * amd_idle.enabled is set to true.
	 */
	if (!enabled) {
		pr_info("disabled\n");
		return -EPERM;
	}

	retval = amd_idle_probe();
	if (retval)
		return retval;

	amd_idle_cpuidle_devices = alloc_percpu(struct cpuidle_device);
	if (amd_idle_cpuidle_devices == NULL)
		return -ENOMEM;

	amd_idle_cpuidle_driver_init();

	retval = cpuidle_register_driver(&amd_idle_driver);
	if (retval) {
		struct cpuidle_driver *drv = cpuidle_get_driver();

		pr_err("amd_idle yielding to %s", drv ? drv->name : "none");
		goto init_driver_fail;
	}

	if (boot_cpu_has(X86_FEATURE_ARAT))	/* Always Reliable APIC Timer */
		lapic_timer_reliable_states = LAPIC_TIMER_ALWAYS_RELIABLE;

	retval = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "idle/amd:online",
				   amd_idle_cpu_online, NULL);
	if (retval < 0)
		goto hp_setup_fail;

	pr_info("lapic_timer_reliable_states 0x%x\n",
		lapic_timer_reliable_states);

	return 0;

hp_setup_fail:
	amd_idle_cpuidle_devices_uninit();
	cpuidle_unregister_driver(&amd_idle_driver);
init_driver_fail:
	free_percpu(amd_idle_cpuidle_devices);
	return retval;

}
device_initcall(amd_idle_init);

/* amd_idle.enabled enalbes the AMD idle driver, default is disabled */
module_param(enabled, bool, 0444);

/* amd_idle.max_cstate dictates the number of c-states initialized */
module_param(max_cstate, int, 0444);

/* amd_idle.c2_latency sets the exit_latency for C2 state */
module_param(c2_latency, int, 0444);

/* amd_idle.c2_residency sets the target_residency for C2 state */
module_param(c2_residency, int, 0444);
