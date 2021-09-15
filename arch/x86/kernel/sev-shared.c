// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases.
 */

#ifndef __BOOT_COMPRESSED
#define error(v)	pr_err(v)
#define has_cpuflag(f)	boot_cpu_has(f)
#endif

/*
 * Individual entries of the SEV-SNP CPUID table, as defined by the SEV-SNP
 * Firmware ABI, Revision 0.9, Section 7.1, Table 14. Note that the XCR0_IN
 * and XSS_IN are denoted here as __unused/__unused2, since they are not
 * needed for the current guest implementation, where the size of the buffers
 * needed to store enabled XSAVE-saved features are calculated rather than
 * encoded in the CPUID table for each possible combination of XCR0_IN/XSS_IN
 * to save space.
 */
struct snp_cpuid_fn {
	u32 eax_in;
	u32 ecx_in;
	u64 __unused;
	u64 __unused2;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
	u64 __reserved;
} __packed;

/*
 * SEV-SNP CPUID table header, as defined by the SEV-SNP Firmware ABI,
 * Revision 0.9, Section 8.14.2.6. Also noted there is the SEV-SNP
 * firmware-enforced limit of 64 entries per CPUID table.
 */
#define SNP_CPUID_COUNT_MAX 64

struct snp_cpuid_info {
	u32 count;
	u32 __reserved1;
	u64 __reserved2;
	struct snp_cpuid_fn fn[SNP_CPUID_COUNT_MAX];
} __packed;

/*
 * Since feature negotiation related variables are set early in the boot
 * process they must reside in the .data section so as not to be zeroed
 * out when the .bss section is later cleared.
 *
 * GHCB protocol version negotiated with the hypervisor.
 */
static u16 __ro_after_init ghcb_version;

/* Bitmap of SEV features supported by the hypervisor */
static u64 __ro_after_init sev_hv_features;

/*
 * These are stored in .data section to avoid the need to re-parse boot_params
 * and regenerate the CPUID table/pointer when .bss is cleared.
 */

/* Copy of the SNP firmware's CPUID page. */
static struct snp_cpuid_info cpuid_info_copy __ro_after_init;

/*
 * The CPUID info can't always be referenced directly due to the need for
 * pointer fixups during initial startup phase of kernel proper, so access must
 * be done through this pointer, which will be fixed up as-needed during boot.
 */
static const struct snp_cpuid_info *cpuid_info __ro_after_init;

/*
 * These will be initialized based on CPUID table so that non-present
 * all-zero leaves (for sparse tables) can be differentiated from
 * invalid/out-of-range leaves. This is needed since all-zero leaves
 * still need to be post-processed.
 */
u32 cpuid_std_range_max __ro_after_init;
u32 cpuid_hyp_range_max __ro_after_init;
u32 cpuid_ext_range_max __ro_after_init;

static bool __init sev_es_check_cpu_features(void)
{
	if (!has_cpuflag(X86_FEATURE_RDRAND)) {
		error("RDRAND instruction not supported - no trusted source of randomness available\n");
		return false;
	}

	return true;
}

static void __noreturn sev_es_terminate(unsigned int set, unsigned int reason)
{
	u64 val = GHCB_MSR_TERM_REQ;

	/* Tell the hypervisor what went wrong. */
	val |= GHCB_SEV_TERM_REASON(set, reason);

	/* Request Guest Termination from Hypvervisor */
	sev_es_wr_ghcb_msr(val);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n" : : : "memory");
}

/*
 * The hypervisor features are available from GHCB version 2 onward.
 */
static bool get_hv_features(void)
{
	u64 val;

	sev_hv_features = 0;

	if (ghcb_version < 2)
		return false;

	sev_es_wr_ghcb_msr(GHCB_MSR_HV_FT_REQ);
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();
	if (GHCB_RESP_CODE(val) != GHCB_MSR_HV_FT_RESP)
		return false;

	sev_hv_features = GHCB_MSR_HV_FT_RESP_VAL(val);

	return true;
}

static void snp_register_ghcb_early(unsigned long paddr)
{
	unsigned long pfn = paddr >> PAGE_SHIFT;
	u64 val;

	sev_es_wr_ghcb_msr(GHCB_MSR_REG_GPA_REQ_VAL(pfn));
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();

	/* If the response GPA is not ours then abort the guest */
	if ((GHCB_RESP_CODE(val) != GHCB_MSR_REG_GPA_RESP) ||
	    (GHCB_MSR_REG_GPA_RESP_VAL(val) != pfn))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_REGISTER);
}

static bool sev_es_negotiate_protocol(void)
{
	u64 val;

	/* Do the GHCB protocol version negotiation */
	sev_es_wr_ghcb_msr(GHCB_MSR_SEV_INFO_REQ);
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();

	if (GHCB_MSR_INFO(val) != GHCB_MSR_SEV_INFO_RESP)
		return false;

	if (GHCB_MSR_PROTO_MAX(val) < GHCB_PROTOCOL_MIN ||
	    GHCB_MSR_PROTO_MIN(val) > GHCB_PROTOCOL_MAX)
		return false;

	ghcb_version = min_t(size_t, GHCB_MSR_PROTO_MAX(val), GHCB_PROTOCOL_MAX);

	if (!get_hv_features())
		return false;

	return true;
}

static __always_inline void vc_ghcb_invalidate(struct ghcb *ghcb)
{
	ghcb->save.sw_exit_code = 0;
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static bool vc_decoding_needed(unsigned long exit_code)
{
	/* Exceptions don't require to decode the instruction */
	return !(exit_code >= SVM_EXIT_EXCP_BASE &&
		 exit_code <= SVM_EXIT_LAST_EXCP);
}

static enum es_result vc_init_em_ctxt(struct es_em_ctxt *ctxt,
				      struct pt_regs *regs,
				      unsigned long exit_code)
{
	enum es_result ret = ES_OK;

	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->regs = regs;

	if (vc_decoding_needed(exit_code))
		ret = vc_decode_insn(ctxt);

	return ret;
}

static void vc_finish_insn(struct es_em_ctxt *ctxt)
{
	ctxt->regs->ip += ctxt->insn.length;
}

static enum es_result sev_es_ghcb_hv_call(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt,
					  u64 exit_code, u64 exit_info_1,
					  u64 exit_info_2)
{
	enum es_result ret;

	/* Fill in protocol and format specifiers */
	ghcb->protocol_version = ghcb_version;
	ghcb->ghcb_usage       = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if ((ghcb->save.sw_exit_info_1 & 0xffffffff) == 1) {
		u64 info = ghcb->save.sw_exit_info_2;
		unsigned long v;

		info = ghcb->save.sw_exit_info_2;
		v = info & SVM_EVTINJ_VEC_MASK;

		/* Check if exception information from hypervisor is sane. */
		if ((info & SVM_EVTINJ_VALID) &&
		    ((v == X86_TRAP_GP) || (v == X86_TRAP_UD)) &&
		    ((info & SVM_EVTINJ_TYPE_MASK) == SVM_EVTINJ_TYPE_EXEPT)) {
			ctxt->fi.vector = v;
			if (info & SVM_EVTINJ_VALID_ERR)
				ctxt->fi.error_code = info >> 32;
			ret = ES_EXCEPTION;
		} else {
			ret = ES_VMM_ERROR;
		}
	} else {
		ret = ES_OK;
	}

	return ret;
}

static int sev_cpuid_hv(u32 func, u32 subfunc, u32 *eax, u32 *ebx,
			u32 *ecx, u32 *edx)
{
	u64 val;

	if (eax) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_EAX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*eax = (val >> 32);
	}

	if (ebx) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_EBX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*ebx = (val >> 32);
	}

	if (ecx) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_ECX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*ecx = (val >> 32);
	}

	if (edx) {
		sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(func, GHCB_CPUID_REQ_EDX));
		VMGEXIT();
		val = sev_es_rd_ghcb_msr();

		if (GHCB_RESP_CODE(val) != GHCB_MSR_CPUID_RESP)
			return -EIO;

		*edx = (val >> 32);
	}

	return 0;
}

static inline bool snp_cpuid_active(void)
{
	return !!cpuid_info;
}

static int snp_cpuid_calc_xsave_size(u64 xfeatures_en, u32 base_size,
				     u32 *xsave_size, bool compacted)
{
	u32 xsave_size_total = base_size;
	u64 xfeatures_found = 0;
	int i;

	for (i = 0; i < cpuid_info->count; i++) {
		const struct snp_cpuid_fn *fn = &cpuid_info->fn[i];

		if (!(fn->eax_in == 0xD && fn->ecx_in > 1 && fn->ecx_in < 64))
			continue;
		if (!(xfeatures_en & (BIT_ULL(fn->ecx_in))))
			continue;
		if (xfeatures_found & (BIT_ULL(fn->ecx_in)))
			continue;

		xfeatures_found |= (BIT_ULL(fn->ecx_in));

		if (compacted)
			xsave_size_total += fn->eax;
		else
			xsave_size_total = max(xsave_size_total,
					       fn->eax + fn->ebx);
	}

	/*
	 * Either the guest set unsupported XCR0/XSS bits, or the corresponding
	 * entries in the CPUID table were not present. This is not a valid
	 * state to be in.
	 */
	if (xfeatures_found != (xfeatures_en & GENMASK_ULL(63, 2)))
		return -EINVAL;

	*xsave_size = xsave_size_total;

	return 0;
}

static void snp_cpuid_hv(u32 func, u32 subfunc, u32 *eax, u32 *ebx, u32 *ecx,
			 u32 *edx)
{
	/*
	 * MSR protocol does not support fetching indexed subfunction, but is
	 * sufficient to handle current fallback cases. Should that change,
	 * make sure to terminate rather than ignoring the index and grabbing
	 * random values. If this issue arises in the future, handling can be
	 * added here to use GHCB-page protocol for cases that occur late
	 * enough in boot that GHCB page is available.
	 */
	if (cpuid_function_is_indexed(func) && subfunc)
		sev_es_terminate(1, GHCB_TERM_CPUID_HV);

	if (sev_cpuid_hv(func, 0, eax, ebx, ecx, edx))
		sev_es_terminate(1, GHCB_TERM_CPUID_HV);
}

static bool
snp_cpuid_find_validated_func(u32 func, u32 subfunc, u32 *eax, u32 *ebx,
			      u32 *ecx, u32 *edx)
{
	int i;

	for (i = 0; i < cpuid_info->count; i++) {
		const struct snp_cpuid_fn *fn = &cpuid_info->fn[i];

		if (fn->eax_in != func)
			continue;

		if (cpuid_function_is_indexed(func) && fn->ecx_in != subfunc)
			continue;

		*eax = fn->eax;
		*ebx = fn->ebx;
		*ecx = fn->ecx;
		*edx = fn->edx;

		return true;
	}

	return false;
}

static void __init snp_cpuid_set_ranges(void)
{
	int i;

	for (i = 0; i < cpuid_info->count; i++) {
		const struct snp_cpuid_fn *fn = &cpuid_info->fn[i];

		if (fn->eax_in == 0x0)
			cpuid_std_range_max = fn->eax;
		else if (fn->eax_in == 0x40000000)
			cpuid_hyp_range_max = fn->eax;
		else if (fn->eax_in == 0x80000000)
			cpuid_ext_range_max = fn->eax;
	}
}

static bool snp_cpuid_check_range(u32 func)
{
	if (func <= cpuid_std_range_max ||
	    (func >= 0x40000000 && func <= cpuid_hyp_range_max) ||
	    (func >= 0x80000000 && func <= cpuid_ext_range_max))
		return true;

	return false;
}

static int snp_cpuid_postprocess(u32 func, u32 subfunc, u32 *eax, u32 *ebx,
				 u32 *ecx, u32 *edx)
{
	u32 ebx2, ecx2, edx2;

	switch (func) {
	case 0x1:
		snp_cpuid_hv(func, subfunc, NULL, &ebx2, NULL, &edx2);

		/* initial APIC ID */
		*ebx = (ebx2 & GENMASK(31, 24)) | (*ebx & GENMASK(23, 0));
		/* APIC enabled bit */
		*edx = (edx2 & BIT(9)) | (*edx & ~BIT(9));

		/* OSXSAVE enabled bit */
		if (native_read_cr4() & X86_CR4_OSXSAVE)
			*ecx |= BIT(27);
		break;
	case 0x7:
		/* OSPKE enabled bit */
		*ecx &= ~BIT(4);
		if (native_read_cr4() & X86_CR4_PKE)
			*ecx |= BIT(4);
		break;
	case 0xB:
		/* extended APIC ID */
		snp_cpuid_hv(func, 0, NULL, NULL, NULL, edx);
		break;
	case 0xD: {
		bool compacted = false;
		u64 xcr0 = 1, xss = 0;
		u32 xsave_size;

		if (subfunc != 0 && subfunc != 1)
			return 0;

		if (native_read_cr4() & X86_CR4_OSXSAVE)
			xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
		if (subfunc == 1) {
			/* Get XSS value if XSAVES is enabled. */
			if (*eax & BIT(3)) {
				unsigned long lo, hi;

				asm volatile("rdmsr" : "=a" (lo), "=d" (hi)
						     : "c" (MSR_IA32_XSS));
				xss = (hi << 32) | lo;
			}

			/*
			 * The PPR and APM aren't clear on what size should be
			 * encoded in 0xD:0x1:EBX when compaction is not enabled
			 * by either XSAVEC (feature bit 1) or XSAVES (feature
			 * bit 3) since SNP-capable hardware has these feature
			 * bits fixed as 1. KVM sets it to 0 in this case, but
			 * to avoid this becoming an issue it's safer to simply
			 * treat this as unsupported for SEV-SNP guests.
			 */
			if (!(*eax & (BIT(1) | BIT(3))))
				return -EINVAL;

			compacted = true;
		}

		if (snp_cpuid_calc_xsave_size(xcr0 | xss, *ebx, &xsave_size,
					      compacted))
			return -EINVAL;

		*ebx = xsave_size;
		}
		break;
	case 0x8000001E:
		/* extended APIC ID */
		snp_cpuid_hv(func, subfunc, eax, &ebx2, &ecx2, NULL);
		/* compute ID */
		*ebx = (*ebx & GENMASK(31, 8)) | (ebx2 & GENMASK(7, 0));
		/* node ID */
		*ecx = (*ecx & GENMASK(31, 8)) | (ecx2 & GENMASK(7, 0));
		break;
	default:
		/* No fix-ups needed, use values as-is. */
		break;
	}

	return 0;
}

/*
 * Returns -EOPNOTSUPP if feature not enabled. Any other return value should be
 * treated as fatal by caller.
 */
static int snp_cpuid(u32 func, u32 subfunc, u32 *eax, u32 *ebx, u32 *ecx,
		     u32 *edx)
{
	if (!snp_cpuid_active())
		return -EOPNOTSUPP;

	if (!snp_cpuid_find_validated_func(func, subfunc, eax, ebx, ecx, edx)) {
		/*
		 * Some hypervisors will avoid keeping track of CPUID entries
		 * where all values are zero, since they can be handled the
		 * same as out-of-range values (all-zero). This is useful here
		 * as well as it allows virtually all guest configurations to
		 * work using a single SEV-SNP CPUID table.
		 *
		 * To allow for this, there is a need to distinguish between
		 * out-of-range entries and in-range zero entries, since the
		 * CPUID table entries are only a template that may need to be
		 * augmented with additional values for things like
		 * CPU-specific information during post-processing. So if it's
		 * not in the table, but is still in the valid range, proceed
		 * with the post-processing. Otherwise, just return zeros.
		 */
		*eax = *ebx = *ecx = *edx = 0;
		if (!snp_cpuid_check_range(func))
			return 0;
	}

	return snp_cpuid_postprocess(func, subfunc, eax, ebx, ecx, edx);
}

/*
 * Boot VC Handler - This is the first VC handler during boot, there is no GHCB
 * page yet, so it only supports the MSR based communication with the
 * hypervisor and only the CPUID exit-code.
 */
void __init do_vc_no_ghcb(struct pt_regs *regs, unsigned long exit_code)
{
	unsigned int subfn = lower_bits(regs->cx, 32);
	unsigned int fn = lower_bits(regs->ax, 32);
	u32 eax, ebx, ecx, edx;
	int ret;

	/* Only CPUID is supported via MSR protocol */
	if (exit_code != SVM_EXIT_CPUID)
		goto fail;

	/*
	 * A #VC implies that either SEV-ES or SEV-SNP are enabled, so the SEV
	 * MSR is also available. Go ahead and initialize sev_status here to
	 * allow SEV features to be checked without relying solely on the SEV
	 * cpuid bit to indicate whether it is safe to do so.
	 */
	if (!sev_status) {
		unsigned long lo, hi;

		asm volatile("rdmsr" : "=a" (lo), "=d" (hi)
				     : "c" (MSR_AMD64_SEV));
		sev_status = (hi << 32) | lo;
	}

	ret = snp_cpuid(fn, subfn, &eax, &ebx, &ecx, &edx);
	if (ret == 0)
		goto cpuid_done;

	if (ret != -EOPNOTSUPP)
		goto fail;

	if (sev_cpuid_hv(fn, 0, &eax, &ebx, &ecx, &edx))
		goto fail;

cpuid_done:
	regs->ax = eax;
	regs->bx = ebx;
	regs->cx = ecx;
	regs->dx = edx;

	/*
	 * This is a VC handler and the #VC is only raised when SEV-ES is
	 * active, which means SEV must be active too. Do sanity checks on the
	 * CPUID results to make sure the hypervisor does not trick the kernel
	 * into the no-sev path. This could map sensitive data unencrypted and
	 * make it accessible to the hypervisor.
	 *
	 * In particular, check for:
	 *	- Availability of CPUID leaf 0x8000001f
	 *	- SEV CPUID bit.
	 *
	 * The hypervisor might still report the wrong C-bit position, but this
	 * can't be checked here.
	 */

	if (fn == 0x80000000 && (regs->ax < 0x8000001f))
		/* SEV leaf check */
		goto fail;
	else if ((fn == 0x8000001f && !(regs->ax & BIT(1))))
		/* SEV bit */
		goto fail;

	/* Skip over the CPUID two-byte opcode */
	regs->ip += 2;

	return;

fail:
	/* Terminate the guest */
	sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);
}

static enum es_result vc_insn_string_read(struct es_em_ctxt *ctxt,
					  void *src, char *buf,
					  unsigned int data_size,
					  unsigned int count,
					  bool backwards)
{
	int i, b = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *s = src + (i * data_size * b);
		char *d = buf + (i * data_size);

		ret = vc_read_mem(ctxt, s, d, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

static enum es_result vc_insn_string_write(struct es_em_ctxt *ctxt,
					   void *dst, char *buf,
					   unsigned int data_size,
					   unsigned int count,
					   bool backwards)
{
	int i, s = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *d = dst + (i * data_size * s);
		char *b = buf + (i * data_size);

		ret = vc_write_mem(ctxt, d, b, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

#define IOIO_TYPE_STR  BIT(2)
#define IOIO_TYPE_IN   1
#define IOIO_TYPE_INS  (IOIO_TYPE_IN | IOIO_TYPE_STR)
#define IOIO_TYPE_OUT  0
#define IOIO_TYPE_OUTS (IOIO_TYPE_OUT | IOIO_TYPE_STR)

#define IOIO_REP       BIT(3)

#define IOIO_ADDR_64   BIT(9)
#define IOIO_ADDR_32   BIT(8)
#define IOIO_ADDR_16   BIT(7)

#define IOIO_DATA_32   BIT(6)
#define IOIO_DATA_16   BIT(5)
#define IOIO_DATA_8    BIT(4)

#define IOIO_SEG_ES    (0 << 10)
#define IOIO_SEG_DS    (3 << 10)

static enum es_result vc_ioio_exitinfo(struct es_em_ctxt *ctxt, u64 *exitinfo)
{
	struct insn *insn = &ctxt->insn;
	*exitinfo = 0;

	switch (insn->opcode.bytes[0]) {
	/* INS opcodes */
	case 0x6c:
	case 0x6d:
		*exitinfo |= IOIO_TYPE_INS;
		*exitinfo |= IOIO_SEG_ES;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* OUTS opcodes */
	case 0x6e:
	case 0x6f:
		*exitinfo |= IOIO_TYPE_OUTS;
		*exitinfo |= IOIO_SEG_DS;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* IN immediate opcodes */
	case 0xe4:
	case 0xe5:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (u8)insn->immediate.value << 16;
		break;

	/* OUT immediate opcodes */
	case 0xe6:
	case 0xe7:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (u8)insn->immediate.value << 16;
		break;

	/* IN register opcodes */
	case 0xec:
	case 0xed:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* OUT register opcodes */
	case 0xee:
	case 0xef:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	default:
		return ES_DECODE_FAILED;
	}

	switch (insn->opcode.bytes[0]) {
	case 0x6c:
	case 0x6e:
	case 0xe4:
	case 0xe6:
	case 0xec:
	case 0xee:
		/* Single byte opcodes */
		*exitinfo |= IOIO_DATA_8;
		break;
	default:
		/* Length determined by instruction parsing */
		*exitinfo |= (insn->opnd_bytes == 2) ? IOIO_DATA_16
						     : IOIO_DATA_32;
	}
	switch (insn->addr_bytes) {
	case 2:
		*exitinfo |= IOIO_ADDR_16;
		break;
	case 4:
		*exitinfo |= IOIO_ADDR_32;
		break;
	case 8:
		*exitinfo |= IOIO_ADDR_64;
		break;
	}

	if (insn_has_rep_prefix(insn))
		*exitinfo |= IOIO_REP;

	return ES_OK;
}

static enum es_result vc_handle_ioio(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	u64 exit_info_1, exit_info_2;
	enum es_result ret;

	ret = vc_ioio_exitinfo(ctxt, &exit_info_1);
	if (ret != ES_OK)
		return ret;

	if (exit_info_1 & IOIO_TYPE_STR) {

		/* (REP) INS/OUTS */

		bool df = ((regs->flags & X86_EFLAGS_DF) == X86_EFLAGS_DF);
		unsigned int io_bytes, exit_bytes;
		unsigned int ghcb_count, op_count;
		unsigned long es_base;
		u64 sw_scratch;

		/*
		 * For the string variants with rep prefix the amount of in/out
		 * operations per #VC exception is limited so that the kernel
		 * has a chance to take interrupts and re-schedule while the
		 * instruction is emulated.
		 */
		io_bytes   = (exit_info_1 >> 4) & 0x7;
		ghcb_count = sizeof(ghcb->shared_buffer) / io_bytes;

		op_count    = (exit_info_1 & IOIO_REP) ? regs->cx : 1;
		exit_info_2 = min(op_count, ghcb_count);
		exit_bytes  = exit_info_2 * io_bytes;

		es_base = insn_get_seg_base(ctxt->regs, INAT_SEG_REG_ES);

		/* Read bytes of OUTS into the shared buffer */
		if (!(exit_info_1 & IOIO_TYPE_IN)) {
			ret = vc_insn_string_read(ctxt,
					       (void *)(es_base + regs->si),
					       ghcb->shared_buffer, io_bytes,
					       exit_info_2, df);
			if (ret)
				return ret;
		}

		/*
		 * Issue an VMGEXIT to the HV to consume the bytes from the
		 * shared buffer or to have it write them into the shared buffer
		 * depending on the instruction: OUTS or INS.
		 */
		sw_scratch = __pa(ghcb) + offsetof(struct ghcb, shared_buffer);
		ghcb_set_sw_scratch(ghcb, sw_scratch);
		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO,
					  exit_info_1, exit_info_2);
		if (ret != ES_OK)
			return ret;

		/* Read bytes from shared buffer into the guest's destination. */
		if (exit_info_1 & IOIO_TYPE_IN) {
			ret = vc_insn_string_write(ctxt,
						   (void *)(es_base + regs->di),
						   ghcb->shared_buffer, io_bytes,
						   exit_info_2, df);
			if (ret)
				return ret;

			if (df)
				regs->di -= exit_bytes;
			else
				regs->di += exit_bytes;
		} else {
			if (df)
				regs->si -= exit_bytes;
			else
				regs->si += exit_bytes;
		}

		if (exit_info_1 & IOIO_REP)
			regs->cx -= exit_info_2;

		ret = regs->cx ? ES_RETRY : ES_OK;

	} else {

		/* IN/OUT into/from rAX */

		int bits = (exit_info_1 & 0x70) >> 1;
		u64 rax = 0;

		if (!(exit_info_1 & IOIO_TYPE_IN))
			rax = lower_bits(regs->ax, bits);

		ghcb_set_rax(ghcb, rax);

		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO, exit_info_1, 0);
		if (ret != ES_OK)
			return ret;

		if (exit_info_1 & IOIO_TYPE_IN) {
			if (!ghcb_rax_is_valid(ghcb))
				return ES_VMM_ERROR;
			regs->ax = lower_bits(ghcb->save.rax, bits);
		}
	}

	return ret;
}

static int vc_handle_cpuid_snp(struct pt_regs *regs)
{
	u32 eax, ebx, ecx, edx;
	int ret;

	ret = snp_cpuid(regs->ax, regs->cx, &eax, &ebx, &ecx, &edx);
	if (ret == 0) {
		regs->ax = eax;
		regs->bx = ebx;
		regs->cx = ecx;
		regs->dx = edx;
	}

	return ret;
}

static enum es_result vc_handle_cpuid(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	u32 cr4 = native_read_cr4();
	enum es_result ret;
	int snp_cpuid_ret;

	snp_cpuid_ret = vc_handle_cpuid_snp(regs);
	if (snp_cpuid_ret == 0)
		return ES_OK;
	if (snp_cpuid_ret != -EOPNOTSUPP)
		return ES_VMM_ERROR;

	ghcb_set_rax(ghcb, regs->ax);
	ghcb_set_rcx(ghcb, regs->cx);

	if (cr4 & X86_CR4_OSXSAVE)
		/* Safe to read xcr0 */
		ghcb_set_xcr0(ghcb, xgetbv(XCR_XFEATURE_ENABLED_MASK));
	else
		/* xgetbv will cause #GP - use reset value for xcr0 */
		ghcb_set_xcr0(ghcb, 1);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_CPUID, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) &&
	      ghcb_rbx_is_valid(ghcb) &&
	      ghcb_rcx_is_valid(ghcb) &&
	      ghcb_rdx_is_valid(ghcb)))
		return ES_VMM_ERROR;

	regs->ax = ghcb->save.rax;
	regs->bx = ghcb->save.rbx;
	regs->cx = ghcb->save.rcx;
	regs->dx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_rdtsc(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt,
				      unsigned long exit_code)
{
	bool rdtscp = (exit_code == SVM_EXIT_RDTSCP);
	enum es_result ret;

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) && ghcb_rdx_is_valid(ghcb) &&
	     (!rdtscp || ghcb_rcx_is_valid(ghcb))))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;
	if (rdtscp)
		ctxt->regs->cx = ghcb->save.rcx;

	return ES_OK;
}

struct cc_setup_data {
	struct setup_data header;
	u32 cc_blob_address;
};

static struct cc_setup_data *get_cc_setup_data(struct boot_params *bp)
{
	struct setup_data *hdr = (struct setup_data *)bp->hdr.setup_data;

	while (hdr) {
		if (hdr->type == SETUP_CC_BLOB)
			return (struct cc_setup_data *)hdr;
		hdr = (struct setup_data *)hdr->next;
	}

	return NULL;
}

/*
 * Search for a Confidential Computing blob passed in as a setup_data entry
 * via the Linux Boot Protocol.
 */
struct cc_blob_sev_info *
snp_find_cc_blob_setup_data(struct boot_params *bp)
{
	struct cc_setup_data *sd;

	sd = get_cc_setup_data(bp);
	if (!sd)
		return NULL;

	return (struct cc_blob_sev_info *)(unsigned long)sd->cc_blob_address;
}

/*
 * Initialize the kernel's copy of the SEV-SNP CPUID table, and set up the
 * pointer that will be used to access it.
 *
 * Maintaining a direct mapping of the SEV-SNP CPUID table used by firmware
 * would be possible as an alternative, but the approach is brittle since the
 * mapping needs to be updated in sync with all the changes to virtual memory
 * layout and related mapping facilities throughout the boot process.
 */
void __init snp_cpuid_info_create(const struct cc_blob_sev_info *cc_info)
{
	const struct snp_cpuid_info *cpuid_info_fw;

	if (!cc_info || !cc_info->cpuid_phys || cc_info->cpuid_len < PAGE_SIZE)
		sev_es_terminate(1, GHCB_TERM_CPUID);

	cpuid_info_fw = (const struct snp_cpuid_info *)cc_info->cpuid_phys;
	if (!cpuid_info_fw->count || cpuid_info_fw->count > SNP_CPUID_COUNT_MAX)
		sev_es_terminate(1, GHCB_TERM_CPUID);

	cpuid_info = &cpuid_info_copy;
	memcpy((void *)cpuid_info, cpuid_info_fw, sizeof(*cpuid_info));
	snp_cpuid_set_ranges();
}
