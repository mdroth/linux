// SPDX-License-Identifier: GPL-2.0-only
#include "kvm_util.h"
#include "linux/types.h"
#include "linux/bitmap.h"
#include "linux/atomic.h"

struct ucall_header {
	DECLARE_BITMAP(in_use, KVM_MAX_VCPUS);
	struct ucall ucalls[KVM_MAX_VCPUS];
};

static bool use_ucall_pool;
static struct ucall_header *ucall_pool;

void ucall_init(struct kvm_vm *vm, void *arg)
{
	struct ucall *uc;
	struct ucall_header *hdr;
	vm_vaddr_t vaddr;
	int i;

	use_ucall_pool = vm->use_ucall_pool;
	sync_global_to_guest(vm, use_ucall_pool);
	if (!use_ucall_pool)
		goto out;

	TEST_ASSERT(!ucall_pool, "Only a single encrypted guest at a time for ucalls.");
	vaddr = vm_vaddr_alloc_shared(vm, sizeof(*hdr), vm->page_size);
	hdr = (struct ucall_header *)addr_gva2hva(vm, vaddr);
	memset(hdr, 0, sizeof(*hdr));

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		uc = &hdr->ucalls[i];
		uc->hva = uc;
	}

	ucall_pool = (struct ucall_header *)vaddr;
	sync_global_to_guest(vm, ucall_pool);

out:
	ucall_arch_init(vm, arg);
}

void ucall_uninit(struct kvm_vm *vm)
{
	use_ucall_pool = false;
	ucall_pool = NULL;

	if (!vm->memcrypt.encrypted) {
		sync_global_to_guest(vm, use_ucall_pool);
		sync_global_to_guest(vm, ucall_pool);
	}

	ucall_arch_uninit(vm);
}

static struct ucall *ucall_alloc(void)
{
	struct ucall *uc = NULL;
	int i;

	if (!use_ucall_pool)
		goto out;

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (!atomic_test_and_set_bit(i, ucall_pool->in_use)) {
			uc = &ucall_pool->ucalls[i];
			memset(uc->args, 0, sizeof(uc->args));
			break;
		}
	}
out:
	return uc;
}

static inline size_t uc_pool_idx(struct ucall *uc)
{
	return uc - ucall_pool->ucalls;
}

static void ucall_free(struct ucall *uc)
{
	if (!use_ucall_pool)
		return;

	clear_bit(uc_pool_idx(uc), ucall_pool->in_use);
}

void ucall(uint64_t cmd, int nargs, ...)
{
	struct ucall *uc;
	struct ucall tmp;
	va_list va;
	int i;

	uc = ucall_alloc();
	if (!uc)
		uc = &tmp;

	WRITE_ONCE(uc->cmd, cmd);

	nargs = min(nargs, UCALL_MAX_ARGS);

	va_start(va, nargs);
	for (i = 0; i < nargs; ++i)
		WRITE_ONCE(uc->args[i], va_arg(va, uint64_t));
	va_end(va);

	/*
	 * When using the ucall pool implementation the @hva member of the ucall
	 * structs in the pool has been initialized to the hva of the ucall
	 * object.
	 */
	if (use_ucall_pool)
		ucall_arch_do_ucall((vm_vaddr_t)uc->hva);
	else
		ucall_arch_do_ucall((vm_vaddr_t)uc);

	ucall_free(uc);
}

uint64_t get_ucall(struct kvm_vcpu *vcpu, struct ucall *uc)
{
	struct ucall ucall;
	void *addr;

	if (!uc)
		uc = &ucall;

	addr = ucall_arch_get_ucall(vcpu);
	if (addr) {
		memcpy(uc, addr, sizeof(*uc));
		vcpu_run_complete_io(vcpu);
	} else {
		memset(uc, 0, sizeof(*uc));
	}

	return uc->cmd;
}
