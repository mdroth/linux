// SPDX-License-Identifier: GPL-2.0-only
/*
 * Basic SEV boot tests.
 *
 * Copyright (C) 2021 Advanced Micro Devices
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include "linux/psp-sev.h"
#include "sev.h"

#define VCPU_ID			2
#define PAGE_STRIDE		32

#define SHARED_PAGES		8192
#define SHARED_VADDR_MIN	0x1000000

#define PRIVATE_PAGES		2048
#define PRIVATE_VADDR_MIN	(SHARED_VADDR_MIN + SHARED_PAGES * PAGE_SIZE)

#define TOTAL_PAGES		(512 + SHARED_PAGES + PRIVATE_PAGES)

#define NR_SYNCS 1

static void guest_run_loop(struct kvm_vcpu *vcpu)
{
	struct ucall uc;
	int i;

	for (i = 0; i <= NR_SYNCS; ++i) {
		vcpu_run(vcpu);
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			continue;
		case UCALL_DONE:
			return;
		case UCALL_ABORT:
			TEST_ASSERT(false, "%s at %s:%ld\n\tvalues: %#lx, %#lx",
				    (const char *)uc.args[0], __FILE__,
				    uc.args[1], uc.args[2], uc.args[3]);
		default:
			TEST_ASSERT(
				false, "Unexpected exit: %s",
				exit_reason_str(vcpu->run->exit_reason));
		}
	}
}

static void __attribute__((__flatten__)) guest_sev_code(void)
{
	uint32_t eax, ebx, ecx, edx;
	uint64_t sev_status;

	GUEST_SYNC(1);

	eax = CPUID_MEM_ENC_LEAF;
	cpuid(eax, &eax, &ebx, &ecx, &edx);
	GUEST_ASSERT(eax & (1 << 1));

	sev_status = rdmsr(MSR_AMD64_SEV);
	GUEST_ASSERT((sev_status & 0x1) == 1);

	GUEST_DONE();
}

static struct sev_vm *setup_test_common(void *guest_code, uint64_t policy,
					struct kvm_vcpu **vcpu)
{
	uint8_t measurement[512];
	struct sev_vm *sev;
	struct kvm_vm *vm;
	int i;

	sev = sev_vm_create(policy, TOTAL_PAGES);
	if (!sev)
		return NULL;
	vm = sev_get_vm(sev);

	/* Set up VCPU and initial guest kernel. */
	*vcpu = vm_vcpu_add(vm, VCPU_ID, guest_code);
	kvm_vm_elf_load(vm, program_invocation_name);

	/* Allocations/setup done. Encrypt initial guest payload. */
	sev_vm_launch(sev);

	/* Dump the initial measurement. A test to actually verify it would be nice. */
	sev_vm_launch_measure(sev, measurement);
	pr_info("guest measurement: ");
	for (i = 0; i < 32; ++i)
		pr_info("%02x", measurement[i]);
	pr_info("\n");

	sev_vm_launch_finish(sev);

	return sev;
}

static void test_sev(void *guest_code, uint64_t policy)
{
	struct sev_vm *sev;
	struct kvm_vcpu *vcpu;

	sev = setup_test_common(guest_code, policy, &vcpu);
	if (!sev)
		return;

	/* Guest is ready to run. Do the tests. */
	guest_run_loop(vcpu);

	pr_info("guest ran successfully\n");

	sev_vm_free(sev);
}

int main(int argc, char *argv[])
{
	/* SEV tests */
	test_sev(guest_sev_code, SEV_POLICY_NO_DBG);
	test_sev(guest_sev_code, 0);

	return 0;
}
