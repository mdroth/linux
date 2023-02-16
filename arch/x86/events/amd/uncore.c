// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Advanced Micro Devices, Inc.
 *
 * Author: Jacob Shin <jacob.shin@amd.com>
 */

#include <linux/perf_event.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpufeature.h>
#include <linux/smp.h>

#include <asm/perf_event.h>
#include <asm/msr.h>

#define NUM_COUNTERS_NB		4
#define NUM_COUNTERS_DFDBG	4
#define NUM_COUNTERS_L2		4
#define NUM_COUNTERS_L3		6

#define RDPMC_BASE_NB		6
#define RDPMC_BASE_LLC		10

#define COUNTER_SHIFT		16

#define UNIT_NAME_LEN		16
#define UNIT_OWNER_NONE		-1

/*
 * The highest possible configuration as of now is a 2P system with all memory
 * controllers active. The maximum number of memory controllers in each channel
 * group is 32.
 */
#define NUM_UNITS_UMC_MAX	64

#undef pr_fmt
#define pr_fmt(fmt)	"amd_uncore: " fmt

static int pmu_version;

static HLIST_HEAD(uncore_unused_list);

struct amd_uncore_context {
	int id;
	int refcnt;
	int cpu;
	struct perf_event **events;
	struct hlist_node node;
};

struct amd_uncore_unit {
	char name[UNIT_NAME_LEN];
	struct amd_uncore_context * __percpu *ctx;
	struct pmu pmu;
	cpumask_t active_mask;
	int num_counters;
	int rdpmc_base;
	u32 msr_base;
	u32 dbg_msr_base;
	int owner;
	int (*id)(unsigned int cpu);
};

struct amd_uncore {
	struct amd_uncore_unit *units;
	int num_units;
};

enum amd_uncore_type {
	UNCORE_TYPE_NB	= 0,
	UNCORE_TYPE_DF	= UNCORE_TYPE_NB,
	UNCORE_TYPE_LLC	= 1,
	UNCORE_TYPE_L2	= UNCORE_TYPE_LLC,
	UNCORE_TYPE_L3	= UNCORE_TYPE_LLC,
	UNCORE_TYPE_UMC	= 2,

	UNCORE_TYPE_MAX
};

static struct amd_uncore uncores[UNCORE_TYPE_MAX];

static inline
struct amd_uncore_unit *event_to_uncore_unit(struct perf_event *event)
{
	return container_of(event->pmu, struct amd_uncore_unit, pmu);
}

static void amd_uncore_read(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 prev, new;
	s64 delta;

	/*
	 * since we do not enable counter overflow interrupts,
	 * we do not have to worry about prev_count changing on us
	 */

	prev = local64_read(&hwc->prev_count);

	/*
	 * Some uncore PMUs do not have RDPMC assignments. In such cases,
	 * read counts directly from the corresponding PERF_CTR.
	 */
	if (hwc->event_base_rdpmc < 0)
		rdmsrl(hwc->event_base, new);
	else
		rdpmcl(hwc->event_base_rdpmc, new);

	local64_set(&hwc->prev_count, new);
	delta = (new << COUNTER_SHIFT) - (prev << COUNTER_SHIFT);
	delta >>= COUNTER_SHIFT;
	local64_add(delta, &event->count);
}

static void amd_uncore_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	if (flags & PERF_EF_RELOAD)
		wrmsrl(hwc->event_base, (u64)local64_read(&hwc->prev_count));

	hwc->state = 0;
	wrmsrl(hwc->config_base, (hwc->config | ARCH_PERFMON_EVENTSEL_ENABLE));
	perf_event_update_userpage(event);
}

static void amd_uncore_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	wrmsrl(hwc->config_base, hwc->config);
	hwc->state |= PERF_HES_STOPPED;

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		amd_uncore_read(event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

static int amd_uncore_add(struct perf_event *event, int flags)
{
	int i;
	struct amd_uncore_unit *unit = event_to_uncore_unit(event);
	struct amd_uncore_context *ctx = *per_cpu_ptr(unit->ctx, event->cpu);
	struct hw_perf_event *hwc = &event->hw;

	/* are we already assigned? */
	if (hwc->idx != -1 && ctx->events[hwc->idx] == event)
		goto out;

	for (i = 0; i < unit->num_counters; i++) {
		if (ctx->events[i] == event) {
			hwc->idx = i;
			goto out;
		}
	}

	/* if not, take the first available counter */
	hwc->idx = -1;
	for (i = 0; i < unit->num_counters; i++) {
		if (cmpxchg(&ctx->events[i], NULL, event) == NULL) {
			hwc->idx = i;
			break;
		}
	}

out:
	if (hwc->idx == -1)
		return -EBUSY;

	hwc->config_base = unit->msr_base + (2 * hwc->idx);
	hwc->event_base = unit->msr_base + 1 + (2 * hwc->idx);
	hwc->event_base_rdpmc = unit->rdpmc_base + hwc->idx;
	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	/* Some uncore PMUs do not have RDPMC assignments */
	if (unit->rdpmc_base < 0)
		hwc->event_base_rdpmc = -1;

	if (flags & PERF_EF_START)
		event->pmu->start(event, PERF_EF_RELOAD);

	return 0;
}

static void amd_uncore_del(struct perf_event *event, int flags)
{
	int i;
	struct amd_uncore_unit *unit = event_to_uncore_unit(event);
	struct amd_uncore_context *ctx = *per_cpu_ptr(unit->ctx, event->cpu);
	struct hw_perf_event *hwc = &event->hw;

	event->pmu->stop(event, PERF_EF_UPDATE);

	for (i = 0; i < unit->num_counters; i++) {
		if (cmpxchg(&ctx->events[i], event, NULL) == event)
			break;
	}

	hwc->idx = -1;
}

static int amd_uncore_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct amd_uncore_context *ctx;
	struct amd_uncore_unit *unit;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/*
	 * NB and Last level cache counters (MSRs) are shared across all cores
	 * that share the same NB / Last level cache.  On family 16h and below,
	 * Interrupts can be directed to a single target core, however, event
	 * counts generated by processes running on other cores cannot be masked
	 * out. So we do not support sampling and per-thread events via
	 * CAP_NO_INTERRUPT, and we do not enable counter overflow interrupts:
	 */
	hwc->config = event->attr.config & AMD64_RAW_EVENT_MASK_NB;
	hwc->idx = -1;

	if (event->cpu < 0)
		return -EINVAL;

	unit = event_to_uncore_unit(event);
	ctx = *per_cpu_ptr(unit->ctx, event->cpu);
	if (!ctx)
		return -ENODEV;

	/*
	 * since request can come in to any of the shared cores, we will remap
	 * to a single common cpu.
	 */
	event->cpu = ctx->cpu;

	return 0;
}

static umode_t
amd_f17h_uncore_is_visible(struct kobject *kobj, struct attribute *attr, int i)
{
	return boot_cpu_data.x86 >= 0x17 && boot_cpu_data.x86 < 0x19 ?
	       attr->mode : 0;
}

static umode_t
amd_f19h_uncore_is_visible(struct kobject *kobj, struct attribute *attr, int i)
{
	return boot_cpu_data.x86 >= 0x19 ? attr->mode : 0;
}

static ssize_t amd_uncore_attr_show_cpumask(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct pmu *pmu = dev_get_drvdata(dev);
	struct amd_uncore_unit *unit = container_of(pmu, struct amd_uncore_unit, pmu);

	return cpumap_print_to_pagebuf(true, buf, &unit->active_mask);
}
static DEVICE_ATTR(cpumask, S_IRUGO, amd_uncore_attr_show_cpumask, NULL);

static struct attribute *amd_uncore_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group amd_uncore_attr_group = {
	.attrs = amd_uncore_attrs,
};

#define DEFINE_UNCORE_FORMAT_ATTR(_var, _name, _format)			\
static ssize_t __uncore_##_var##_show(struct device *dev,		\
				struct device_attribute *attr,		\
				char *page)				\
{									\
	BUILD_BUG_ON(sizeof(_format) >= PAGE_SIZE);			\
	return sprintf(page, _format "\n");				\
}									\
static struct device_attribute format_attr_##_var =			\
	__ATTR(_name, 0444, __uncore_##_var##_show, NULL)

DEFINE_UNCORE_FORMAT_ATTR(event12,	event,		"config:0-7,32-35");
DEFINE_UNCORE_FORMAT_ATTR(event14,	event,		"config:0-7,32-35,59-60"); /* F17h+ DF */
DEFINE_UNCORE_FORMAT_ATTR(event14v2,	event,		"config:0-7,32-37");	   /* PerfMonV2 DF */
DEFINE_UNCORE_FORMAT_ATTR(event8,	event,		"config:0-7");		   /* F17h+ L3, PerfMonV2 UMC */
DEFINE_UNCORE_FORMAT_ATTR(umask8,	umask,		"config:8-15");
DEFINE_UNCORE_FORMAT_ATTR(umask12,	umask,		"config:8-15,24-27");	   /* PerfMonV2 DF */
DEFINE_UNCORE_FORMAT_ATTR(coreid,	coreid,		"config:42-44");	   /* F19h L3 */
DEFINE_UNCORE_FORMAT_ATTR(slicemask,	slicemask,	"config:48-51");	   /* F17h L3 */
DEFINE_UNCORE_FORMAT_ATTR(threadmask8,	threadmask,	"config:56-63");	   /* F17h L3 */
DEFINE_UNCORE_FORMAT_ATTR(threadmask2,	threadmask,	"config:56-57");	   /* F19h L3 */
DEFINE_UNCORE_FORMAT_ATTR(enallslices,	enallslices,	"config:46");		   /* F19h L3 */
DEFINE_UNCORE_FORMAT_ATTR(enallcores,	enallcores,	"config:47");		   /* F19h L3 */
DEFINE_UNCORE_FORMAT_ATTR(sliceid,	sliceid,	"config:48-50");	   /* F19h L3 */
DEFINE_UNCORE_FORMAT_ATTR(rdwrmask,    rdwrmask,       "config:8-9");		   /* PerfMonV2 UMC */

/* Common DF and NB attributes */
static struct attribute *amd_uncore_df_format_attr[] = {
	&format_attr_event12.attr,	/* event */
	&format_attr_umask8.attr,	/* umask */
	NULL,
};

/* Common L2 and L3 attributes */
static struct attribute *amd_uncore_l3_format_attr[] = {
	&format_attr_event12.attr,	/* event */
	&format_attr_umask8.attr,	/* umask */
	NULL,				/* threadmask */
	NULL,
};

/* Common UMC attributes */
static struct attribute *amd_uncore_umc_format_attr[] = {
	&format_attr_event8.attr,       /* event */
	&format_attr_rdwrmask.attr,     /* rdwrmask */
	NULL,
};

/* F17h unique L3 attributes */
static struct attribute *amd_f17h_uncore_l3_format_attr[] = {
	&format_attr_slicemask.attr,	/* slicemask */
	NULL,
};

/* F19h unique L3 attributes */
static struct attribute *amd_f19h_uncore_l3_format_attr[] = {
	&format_attr_coreid.attr,	/* coreid */
	&format_attr_enallslices.attr,	/* enallslices */
	&format_attr_enallcores.attr,	/* enallcores */
	&format_attr_sliceid.attr,	/* sliceid */
	NULL,
};

static struct attribute_group amd_uncore_df_format_group = {
	.name = "format",
	.attrs = amd_uncore_df_format_attr,
};

static struct attribute_group amd_uncore_l3_format_group = {
	.name = "format",
	.attrs = amd_uncore_l3_format_attr,
};

static struct attribute_group amd_uncore_umc_format_group = {
	.name = "format",
	.attrs = amd_uncore_umc_format_attr,
};

static struct attribute_group amd_f17h_uncore_l3_format_group = {
	.name = "format",
	.attrs = amd_f17h_uncore_l3_format_attr,
	.is_visible = amd_f17h_uncore_is_visible,
};

static struct attribute_group amd_f19h_uncore_l3_format_group = {
	.name = "format",
	.attrs = amd_f19h_uncore_l3_format_attr,
	.is_visible = amd_f19h_uncore_is_visible,
};

static const struct attribute_group *amd_uncore_df_attr_groups[] = {
	&amd_uncore_attr_group,
	&amd_uncore_df_format_group,
	NULL,
};

static const struct attribute_group *amd_uncore_l3_attr_groups[] = {
	&amd_uncore_attr_group,
	&amd_uncore_l3_format_group,
	NULL,
};

static const struct attribute_group *amd_uncore_l3_attr_update[] = {
	&amd_f17h_uncore_l3_format_group,
	&amd_f19h_uncore_l3_format_group,
	NULL,
};

static const struct attribute_group *amd_uncore_umc_attr_groups[] = {
	&amd_uncore_attr_group,
	&amd_uncore_umc_format_group,
	NULL,
};

static int
uncore_context_alloc(unsigned int cpu, unsigned int type, unsigned int unit)
{
	struct amd_uncore_unit *parent = &uncores[type].units[unit];
	struct amd_uncore_context *ctx;
	int node = cpu_to_node(cpu);

	*per_cpu_ptr(parent->ctx, cpu) = NULL;
	ctx = kzalloc_node(sizeof(struct amd_uncore_context), GFP_KERNEL, node);
	if (!ctx)
		return -ENOMEM;

	ctx->cpu = cpu;
	ctx->id = -1;
	ctx->events = kzalloc_node(sizeof(struct perf_event *) * parent->num_counters,
				   GFP_KERNEL, node);
	if (!ctx->events) {
		kfree(ctx);
		return -ENOMEM;
	}

	*per_cpu_ptr(parent->ctx, cpu) = ctx;

	return 0;
}

static void
uncore_context_free(unsigned int cpu, unsigned int type, unsigned int unit)
{
	struct amd_uncore_unit *parent = &uncores[type].units[unit];
	struct amd_uncore_context *ctx = *per_cpu_ptr(parent->ctx, cpu);

	if (!ctx->refcnt) {
		kfree(ctx->events);
		kfree(ctx);
	}

	*per_cpu_ptr(parent->ctx, cpu) = NULL;
}

static int uncore_cpu_up_prepare(unsigned int cpu, unsigned int type)
{
	struct amd_uncore *uncore = &uncores[type];
	int i;

	for (i = 0; i < uncore->num_units; i++)
		if (uncore_context_alloc(cpu, type, i))
			goto fail;

	return 0;

fail:
	for (i = i - 1; i >= 0; i--)
		uncore_context_free(cpu, type, i);

	return -ENOMEM;
}

static int amd_uncore_cpu_up_prepare(unsigned int cpu)
{
	int i, j;

	for (i = 0; i < UNCORE_TYPE_MAX; i++)
		if (uncore_cpu_up_prepare(cpu, i))
			goto fail;

	return 0;

fail:
	for (i = i - 1; i >= 0; i--)
		for (j = 0; j < uncores[i].num_units; j++)
			uncore_context_free(cpu, i, j);

	return -ENOMEM;
}

static void uncore_cpu_starting(unsigned int cpu, unsigned int type)
{
	struct amd_uncore *uncore = &uncores[type];
	struct amd_uncore_context *this, *that;
	struct amd_uncore_unit *unit;
	int i, j;

	for (i = 0; i < uncore->num_units; i++) {
		unit = &uncore->units[i];
		this = *per_cpu_ptr(unit->ctx, cpu);
		this->id = unit->id(cpu);

		if (unit->owner != UNIT_OWNER_NONE && this->id != unit->owner) {
			hlist_add_head(&this->node, &uncore_unused_list);
			*per_cpu_ptr(unit->ctx, cpu) = NULL;
			continue;
		}

		/* try to find a shared sibling */
		for_each_online_cpu(j) {
			that = *per_cpu_ptr(unit->ctx, j);

			if (!that)
				continue;

			if (this == that)
				continue;

			if (this->id == that->id) {
				hlist_add_head(&this->node, &uncore_unused_list);
				this = that;
				break;
			}
		}

		this->refcnt++;
		*per_cpu_ptr(unit->ctx, cpu) = this;
	}
}

static int amd_uncore_cpu_starting(unsigned int cpu)
{
	int i;

	for (i = 0; i < UNCORE_TYPE_MAX; i++)
		uncore_cpu_starting(cpu, i);

	return 0;
}

static void uncore_clean_online(void)
{
	struct amd_uncore_context *ctx;
	struct hlist_node *n;

	hlist_for_each_entry_safe(ctx, n, &uncore_unused_list, node) {
		hlist_del(&ctx->node);
		kfree(ctx->events);
		kfree(ctx);
	}
}

static void uncore_cpu_online(unsigned int cpu, unsigned int type)
{
	struct amd_uncore *uncore = &uncores[type];
	struct amd_uncore_context *ctx;
	struct amd_uncore_unit *unit;
	int i;

	for (i = 0; i < uncore->num_units; i++) {
		unit = &uncore->units[i];
		ctx = *per_cpu_ptr(unit->ctx, cpu);

		if (unit->owner != UNIT_OWNER_NONE && !ctx)
			continue;

		if (cpu == ctx->cpu)
			cpumask_set_cpu(cpu, &unit->active_mask);
	}
}

static int amd_uncore_cpu_online(unsigned int cpu)
{
	int i;

	uncore_clean_online();
	for (i = 0; i < UNCORE_TYPE_MAX; i++)
		uncore_cpu_online(cpu, i);

	return 0;
}

static void uncore_cpu_down_prepare(unsigned int cpu, unsigned int type)
{
	struct amd_uncore *uncore = &uncores[type];
	struct amd_uncore_context *this, *that;
	struct amd_uncore_unit *unit;
	int i, j;

	for (i = 0; i < uncore->num_units; i++) {
		unit = &uncore->units[i];
		this = *per_cpu_ptr(unit->ctx, cpu);

		if (unit->owner != UNIT_OWNER_NONE && !this)
			continue;

		if (this->cpu != cpu)
			continue;

		/*
		 * this cpu is going down, migrate to a shared sibling if
		 * possible
		 */
		for_each_online_cpu(j) {
			that = *per_cpu_ptr(unit->ctx, j);

			if (cpu == j)
				continue;

			if (this == that) {
				perf_pmu_migrate_context(&unit->pmu, cpu, j);
				cpumask_clear_cpu(cpu, &unit->active_mask);
				cpumask_set_cpu(j, &unit->active_mask);
				that->cpu = j;
				break;
			}
		}
	}
}

static int amd_uncore_cpu_down_prepare(unsigned int cpu)
{
	int i;

	for (i = 0; i < UNCORE_TYPE_MAX; i++)
		uncore_cpu_down_prepare(cpu, i);

	return 0;
}

static void uncore_cpu_dead(unsigned int cpu, unsigned int type)
{
	struct amd_uncore *uncore = &uncores[type];
	struct amd_uncore_context *ctx;
	struct amd_uncore_unit *unit;
	int i;

	for (i = 0; i < uncore->num_units; i++) {
		unit = &uncore->units[i];
		ctx = *per_cpu_ptr(unit->ctx, cpu);

		if (unit->owner != UNIT_OWNER_NONE && !ctx)
			continue;

		if (cpu == ctx->cpu)
			cpumask_clear_cpu(cpu, &unit->active_mask);

		ctx->refcnt--;
		uncore_context_free(cpu, type, i);
	}
}

static int amd_uncore_cpu_dead(unsigned int cpu)
{
	int i;

	for (i = 0; i < UNCORE_TYPE_MAX; i++)
		uncore_cpu_dead(cpu, i);

	return 0;
}

static int amd_uncore_unit_init(struct amd_uncore_unit *unit)
{
	int ret = -ENOMEM;

	unit->ctx = alloc_percpu(struct amd_uncore_context *);
	if (!unit->ctx)
		goto fail;

	ret = perf_pmu_register(&unit->pmu, unit->pmu.name, -1);
	if (ret)
		goto fail;

	pr_info("%d %s %s counters detected\n", unit->num_counters,
		boot_cpu_data.x86_vendor == X86_VENDOR_HYGON ?  "HYGON" : "",
		unit->pmu.name);

	return 0;

fail:
	if (unit->pmu.type > 0)
		perf_pmu_unregister(&unit->pmu);
	if (unit->ctx)
		free_percpu(unit->ctx);

	return ret;
}

static int amd_uncore_nb_id(unsigned int cpu)
{
	/*
	 * Return the corresponding Socket ID. This is available from CPUID
	 * leaf 0x8000001e ECX bits 7:0 and represent the Node ID.
	 */
	return topology_die_id(cpu);
}

static int amd_uncore_nb_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int ret = amd_uncore_event_init(event);

	if (ret || pmu_version < 2)
		return ret;

	hwc->config = event->attr.config & AMD64_PERFMON_V2_RAW_EVENT_MASK_NB;

	return 0;
}

static int amd_uncore_nb_add(struct perf_event *event, int flags)
{
	struct amd_uncore_unit *unit = event_to_uncore_unit(event);
	int ret = amd_uncore_add(event, flags & ~PERF_EF_START);
	struct hw_perf_event *hwc = &event->hw;

	if (ret)
		return ret;

	/*
	 * The first four DF counters are accessible via RDPMC index 6 to 9
	 * followed by the L3 counters from index 10 to 15. For processors
	 * with more than four DF counters, the DF RDPMC assignments become
	 * discontiguous as the additional counters are accessible starting
	 * from index 16.
	 */
	if (hwc->idx >= NUM_COUNTERS_NB)
		hwc->event_base_rdpmc += NUM_COUNTERS_L3;

	if (unit->dbg_msr_base &&
	    unit->num_counters <= (NUM_COUNTERS_NB + NUM_COUNTERS_DFDBG) &&
	    hwc->idx >= (unit->num_counters - NUM_COUNTERS_DFDBG)) {
		hwc->config_base = unit->dbg_msr_base + (2 * (hwc->idx -
				   (unit->num_counters - NUM_COUNTERS_DFDBG)));
		hwc->event_base = unit->dbg_msr_base + (2 * (hwc->idx -
				  (unit->num_counters - NUM_COUNTERS_DFDBG))) + 1;
		/* debug MSRs don't have rdpmc assignments */
		hwc->event_base_rdpmc = -1;
	}

	/* Delayed start after rdpmc base update */
	if (flags & PERF_EF_START)
		amd_uncore_start(event, PERF_EF_RELOAD);

	return 0;
}

static int amd_uncore_nb_init(void)
{
	struct amd_uncore *uncore = &uncores[UNCORE_TYPE_NB];
	struct attribute **attr = amd_uncore_df_format_attr;
	union cpuid_0x80000022_ebx ebx;
	struct amd_uncore_unit *unit;
	int ret = -ENOMEM;

	/* If not found, allow other PMUs to be discovered and initialized */
	if (!boot_cpu_has(X86_FEATURE_PERFCTR_NB))
		return 0;

	uncore->num_units = 1;
	uncore->units = kcalloc(uncore->num_units,
				sizeof(struct amd_uncore_unit), GFP_KERNEL);
	if (!uncore->units)
		return ret;

	ebx.full = cpuid_ebx(EXT_PERFMON_DEBUG_FEATURES);
	if (pmu_version >= 2) {
		*attr++ = &format_attr_event14v2.attr;
		*attr++ = &format_attr_umask12.attr;
	} else if (boot_cpu_data.x86 >= 0x17) {
		*attr = &format_attr_event14.attr;
	}

	unit = &uncore->units[0];
	strncpy(unit->name, "amd_nb", sizeof(unit->name));
	unit->num_counters = NUM_COUNTERS_NB + NUM_COUNTERS_DFDBG;
	unit->msr_base = MSR_F15H_NB_PERF_CTL;
	unit->dbg_msr_base = MSR_DFDBG_PERF_CTL;
	unit->rdpmc_base = RDPMC_BASE_NB;
	unit->pmu = (struct pmu) {
		.task_ctx_nr	= perf_invalid_context,
		.attr_groups	= amd_uncore_df_attr_groups,
		.name		= unit->name,
		.event_init	= amd_uncore_nb_event_init,
		.add		= amd_uncore_nb_add,
		.del		= amd_uncore_del,
		.start		= amd_uncore_start,
		.stop		= amd_uncore_stop,
		.read		= amd_uncore_read,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE | PERF_PMU_CAP_NO_INTERRUPT,
		.module		= THIS_MODULE,
	};

	/*
	 * Family 17h+ repurposes the Northbridge (NB) counters as
	 * Data Fabric (DF) counters. The PMU is exported based on
	 * family as either NB or DF.
	 */
	if (boot_cpu_data.x86 >= 0x17)
		strncpy(unit->name, "amd_df", sizeof(unit->name));

	if (pmu_version >= 2)
		unit->num_counters = ebx.split.num_df_pmc;

	unit->owner = UNIT_OWNER_NONE;
	unit->id = amd_uncore_nb_id;
	ret = amd_uncore_unit_init(unit);
	if (ret)
		goto fail;

	return 0;

fail:
	kfree(uncore->units);
	uncore->num_units = 0;

	return ret;
}

static int amd_uncore_llc_id(unsigned int cpu)
{
	/* Return the corresponding CCX ID. This is available from CPUID leaf
	 * 0x00000001 EBX bits 31:28 and represent the upper nibble of the
	 * Local APIC ID.
	 */
	return get_llc_id(cpu);
}

static int amd_uncore_llc_event_init(struct perf_event *event)
{
	int ret = amd_uncore_event_init(event);
	struct hw_perf_event *hwc = &event->hw;
	u64 config = event->attr.config;
	u64 mask;

	/*
	 * SliceMask and ThreadMask need to be set for certain L3 events.
	 * For other events, the two fields do not affect the count.
	 */
	if (ret || boot_cpu_data.x86 < 0x17)
		return ret;

	mask = config & (AMD64_L3_F19H_THREAD_MASK | AMD64_L3_SLICEID_MASK |
			AMD64_L3_EN_ALL_CORES | AMD64_L3_EN_ALL_SLICES |
			AMD64_L3_COREID_MASK);

	if (boot_cpu_data.x86 <= 0x18)
		mask = ((config & AMD64_L3_SLICE_MASK) ? : AMD64_L3_SLICE_MASK) |
			((config & AMD64_L3_THREAD_MASK) ? : AMD64_L3_THREAD_MASK);

	/*
	 * If the user doesn't specify a ThreadMask, they're not trying to
	 * count core 0, so we enable all cores & threads.
	 * We'll also assume that they want to count slice 0 if they specify
	 * a ThreadMask and leave SliceId and EnAllSlices unpopulated.
	 */
	else if (!(config & AMD64_L3_F19H_THREAD_MASK))
		mask = AMD64_L3_F19H_THREAD_MASK | AMD64_L3_EN_ALL_SLICES |
			AMD64_L3_EN_ALL_CORES;

	hwc->config |= mask;

	return 0;
}

static int amd_uncore_llc_init(void)
{
	struct amd_uncore *uncore = &uncores[UNCORE_TYPE_LLC];
	struct attribute **attr = amd_uncore_l3_format_attr;
	struct amd_uncore_unit *unit;
	int ret = -ENOMEM;

	/* If not found, allow other PMUs to be discovered and initialized */
	if (!boot_cpu_has(X86_FEATURE_PERFCTR_LLC))
		return 0;

	uncore->num_units = 1;
	uncore->units = kcalloc(uncore->num_units,
				sizeof(struct amd_uncore_unit), GFP_KERNEL);
	if (!uncore->units)
		return ret;

	if (boot_cpu_data.x86 >= 0x19) {
		*attr++ = &format_attr_event8.attr;
		*attr++ = &format_attr_umask8.attr;
		*attr++ = &format_attr_threadmask2.attr;
	} else if (boot_cpu_data.x86 >= 0x17) {
		*attr++ = &format_attr_event8.attr;
		*attr++ = &format_attr_umask8.attr;
		*attr++ = &format_attr_threadmask8.attr;
	}

	unit = &uncore->units[0];
	strncpy(unit->name, "amd_l2", sizeof(unit->name));
	unit->num_counters = NUM_COUNTERS_L2;
	unit->msr_base = MSR_F16H_L2I_PERF_CTL;
	unit->rdpmc_base = RDPMC_BASE_LLC;
	unit->pmu = (struct pmu) {
		.task_ctx_nr	= perf_invalid_context,
		.attr_groups	= amd_uncore_l3_attr_groups,
		.attr_update	= amd_uncore_l3_attr_update,
		.name		= unit->name,
		.event_init	= amd_uncore_llc_event_init,
		.add		= amd_uncore_add,
		.del		= amd_uncore_del,
		.start		= amd_uncore_start,
		.stop		= amd_uncore_stop,
		.read		= amd_uncore_read,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE | PERF_PMU_CAP_NO_INTERRUPT,
		.module		= THIS_MODULE,
	};

	/*
	 * Family 17h+ supports L3 counters instead of L2. The PMU is exported
	 * based on family as either L2 or L3.
	 */
	if (boot_cpu_data.x86 >= 0x17) {
		unit->num_counters = NUM_COUNTERS_L3;
		strncpy(unit->name, "amd_l3", sizeof(unit->name));
	}

	unit->owner = UNIT_OWNER_NONE;
	unit->id = amd_uncore_llc_id;
	ret = amd_uncore_unit_init(unit);
	if (ret)
		goto fail;

	return 0;

fail:
	kfree(uncore->units);
	uncore->num_units = 0;

	return ret;
}

static int amd_uncore_umc_id(unsigned int cpu)
{
	/*
	 * Return the corresponding Socket ID. This is available from CPUID
	 * leaf 0x8000001e ECX bits 7:0 and represent the Node ID.
	 */
	return topology_die_id(cpu);
}

static int amd_uncore_umc_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int ret = amd_uncore_event_init(event);

	if (ret)
		return ret;

	/* FIXME */
	hwc->config = event->attr.config & GENMASK_ULL(9, 0);

	return 0;
}

static void amd_uncore_umc_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;

	if (flags & PERF_EF_RELOAD)
		wrmsrl(hwc->event_base, (u64)local64_read(&hwc->prev_count));

	/* FIXME */
	hwc->state = 0;
	wrmsrl(hwc->config_base, (hwc->config | BIT_ULL(31)));
	perf_event_update_userpage(event);
}

static int amd_uncore_umc_init(void)
{
	struct amd_uncore *uncore = &uncores[UNCORE_TYPE_UMC];
	union cpuid_0x80000022_ebx ebx;
	struct amd_uncore_unit *unit;
	unsigned int eax, ecx, edx;
	int id, ret = -ENOMEM;
	u64 groupmask = 0;
	int i, j = 0, k, l;

	/* If not found, allow other PMUs to be discovered and initialized */
	if (pmu_version < 2)
		return 0;

	/*
	 * Since the memory controllers are yet to be discovered, assume the
	 * highest possible configuration. Unused slots can be freed up later.
	 */
	uncore->units = kcalloc(NUM_UNITS_UMC_MAX,
				sizeof(struct amd_uncore_unit), GFP_KERNEL);
	if (!uncore->units)
		return -ENOMEM;

	/*
	 * Each group of memory controllers can have an unique configuration
	 * based on the DIMM population scheme. If all CPUs associated with a
	 * group of memory channels are offline, then the corresponding memory
	 * controllers will not be discoverable as this relies on CPUID.
	 */
	for_each_online_cpu(i) {
		id = amd_uncore_umc_id(i);
		if (groupmask & BIT_ULL(id))
			continue;

		groupmask |= BIT_ULL(id);
		ret = cpuid_on_cpu(i, EXT_PERFMON_DEBUG_FEATURES,
				   &eax, &ebx.full, &ecx, &edx);
		if (ret)
			goto fail;

		for (k = 0, l = 0; j < NUM_UNITS_UMC_MAX && k < 32; k++) {
			if (!(ecx & BIT(k)))
				continue;

			unit = &uncore->units[j];
			snprintf(unit->name, sizeof(unit->name), "amd_umc_%d", j);
			unit->num_counters = ebx.split.num_umc_pmc / hweight32(ecx);
			unit->msr_base = MSR_F19H_UMC_PERF_CTL + l * unit->num_counters * 2;
			unit->rdpmc_base = -1;
			unit->pmu = (struct pmu) {
				.type		= -1,
				.task_ctx_nr	= perf_invalid_context,
				.attr_groups	= amd_uncore_umc_attr_groups,
				.name		= unit->name,
				.event_init	= amd_uncore_umc_event_init,
				.add		= amd_uncore_add,
				.del		= amd_uncore_del,
				.start		= amd_uncore_umc_start,
				.stop		= amd_uncore_stop,
				.read		= amd_uncore_read,
				.capabilities	= PERF_PMU_CAP_NO_EXCLUDE | PERF_PMU_CAP_NO_INTERRUPT,
				.module		= THIS_MODULE,
			};

			unit->owner = id;
			unit->id = amd_uncore_umc_id;
			ret = amd_uncore_unit_init(unit);
			if (ret)
				goto fail;

			j++;
			l++;
		}
	}

	/* Update the number of units and free unused memory */
	uncore->num_units = j;
	uncore->units = krealloc_array(uncore->units, uncore->num_units,
				       sizeof(struct amd_uncore_unit),
				       GFP_KERNEL);
	if (!uncore->units)
		goto fail;

	return 0;

fail:
	for (; j >= 0; j--) {
		unit = &uncore->units[j];
		if (unit->pmu.type > 0)
			perf_pmu_unregister(&unit->pmu);
		if (unit->ctx)
			free_percpu(unit->ctx);
	}

	kfree(uncore->units);
	uncore->num_units = 0;

	return ret;
}

static void amd_uncore_free(void)
{
	struct amd_uncore_unit *unit;
	struct amd_uncore *uncore;
	int i, j;

	for (i = 0; i < UNCORE_TYPE_MAX; i++) {
		uncore = &uncores[i];

		for (j = 0; j < uncore->num_units; j++) {
			unit = &uncore->units[j];
			if (unit->pmu.type > 0)
				perf_pmu_unregister(&unit->pmu);
			if (unit->ctx)
				free_percpu(unit->ctx);
		}

		kfree(uncore->units);
	}
}

static int __init amd_uncore_init(void)
{
	int ret = -ENODEV;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return -ENODEV;

	if (!boot_cpu_has(X86_FEATURE_TOPOEXT))
		return -ENODEV;

	if (boot_cpu_has(X86_FEATURE_PERFMON_V2))
		pmu_version = 2;

	if (amd_uncore_nb_init())
		goto fail;

	if (amd_uncore_llc_init())
		goto fail;

	if (amd_uncore_umc_init())
		goto fail;

	/*
	 * Install callbacks. Core will call them for each online cpu.
	 */
	if (cpuhp_setup_state(CPUHP_PERF_X86_AMD_UNCORE_PREP,
			      "perf/x86/amd/uncore:prepare",
			      amd_uncore_cpu_up_prepare, amd_uncore_cpu_dead))
		goto fail;

	if (cpuhp_setup_state(CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING,
			      "perf/x86/amd/uncore:starting",
			      amd_uncore_cpu_starting, NULL))
		goto fail_prep;
	if (cpuhp_setup_state(CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE,
			      "perf/x86/amd/uncore:online",
			      amd_uncore_cpu_online,
			      amd_uncore_cpu_down_prepare))
		goto fail_start;
	return 0;

fail_start:
	cpuhp_remove_state(CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING);
fail_prep:
	cpuhp_remove_state(CPUHP_PERF_X86_AMD_UNCORE_PREP);
fail:
	amd_uncore_free();

	return ret;
}

static void __exit amd_uncore_exit(void)
{
	cpuhp_remove_state(CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE);
	cpuhp_remove_state(CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING);
	cpuhp_remove_state(CPUHP_PERF_X86_AMD_UNCORE_PREP);
	amd_uncore_free();
}

module_init(amd_uncore_init);
module_exit(amd_uncore_exit);

MODULE_DESCRIPTION("AMD Uncore Driver");
MODULE_LICENSE("GPL v2");
