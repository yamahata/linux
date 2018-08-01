/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MSHYPER_H
#define _ASM_X86_MSHYPER_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/nmi.h>
#include <asm/io.h>
#include <asm/hyperv-tlfs.h>
#include <asm/nospec-branch.h>

#define VP_INVAL	U32_MAX

struct ms_hyperv_info {
	u32 features;
	u32 misc_features;
	u32 hints;
	u32 nested_features;
	u32 max_vp_index;
	u32 max_lp_index;
};

extern struct ms_hyperv_info ms_hyperv;

/*
 * Generate the guest ID.
 */

static inline  __u64 generate_guest_id(__u64 d_info1, __u64 kernel_version,
				       __u64 d_info2)
{
	__u64 guest_id = 0;

	guest_id = (((__u64)HV_LINUX_VENDOR_ID) << 48);
	guest_id |= (d_info1 << 48);
	guest_id |= (kernel_version << 16);
	guest_id |= d_info2;

	return guest_id;
}


/* Free the message slot and signal end-of-message if required */
static inline void vmbus_signal_eom(struct hv_message *msg, u32 old_msg_type)
{
	/*
	 * On crash we're reading some other CPU's message page and we need
	 * to be careful: this other CPU may already had cleared the header
	 * and the host may already had delivered some other message there.
	 * In case we blindly write msg->header.message_type we're going
	 * to lose it. We can still lose a message of the same type but
	 * we count on the fact that there can only be one
	 * CHANNELMSG_UNLOAD_RESPONSE and we don't care about other messages
	 * on crash.
	 */
	if (cmpxchg(&msg->header.message_type, old_msg_type,
		    HVMSG_NONE) != old_msg_type)
		return;

	/*
	 * Make sure the write to MessageType (ie set to
	 * HVMSG_NONE) happens before we read the
	 * MessagePending and EOMing. Otherwise, the EOMing
	 * will not deliver any more messages since there is
	 * no empty slot
	 */
	mb();

	if (msg->header.message_flags.msg_pending) {
		/*
		 * This will cause message queue rescan to
		 * possibly deliver another msg from the
		 * hypervisor
		 */
		wrmsrl(HV_X64_MSR_EOM, 0);
	}
}

#define hv_init_timer(timer, tick) wrmsrl(timer, tick)
#define hv_init_timer_config(config, val) wrmsrl(config, val)

#define hv_get_simp(val) rdmsrl(HV_X64_MSR_SIMP, val)
#define hv_set_simp(val) wrmsrl(HV_X64_MSR_SIMP, val)

#define hv_get_siefp(val) rdmsrl(HV_X64_MSR_SIEFP, val)
#define hv_set_siefp(val) wrmsrl(HV_X64_MSR_SIEFP, val)

#define hv_get_synic_state(val) rdmsrl(HV_X64_MSR_SCONTROL, val)
#define hv_set_synic_state(val) wrmsrl(HV_X64_MSR_SCONTROL, val)

#define hv_get_vp_index(index) rdmsrl(HV_X64_MSR_VP_INDEX, index)

#define hv_get_synint_state(int_num, val) rdmsrl(int_num, val)
#define hv_set_synint_state(int_num, val) wrmsrl(int_num, val)

void hyperv_callback_vector(void);
void hyperv_reenlightenment_vector(void);
#ifdef CONFIG_TRACING
#define trace_hyperv_callback_vector hyperv_callback_vector
#endif
void hyperv_vector_handler(struct pt_regs *regs);
void hv_setup_vmbus_irq(void (*handler)(void));
void hv_remove_vmbus_irq(void);

void hv_setup_kexec_handler(void (*handler)(void));
void hv_remove_kexec_handler(void);
void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs));
void hv_remove_crash_handler(void);

/*
 * Routines for stimer0 Direct Mode handling.
 * On x86/x64, there are no percpu actions to take.
 */
void hv_stimer0_vector_handler(struct pt_regs *regs);
void hv_stimer0_callback_vector(void);
int hv_setup_stimer0_irq(int *irq, int *vector, void (*handler)(void));
void hv_remove_stimer0_irq(int irq);

static inline void hv_enable_stimer0_percpu_irq(int irq) {}
static inline void hv_disable_stimer0_percpu_irq(int irq) {}


#if IS_ENABLED(CONFIG_HYPERV)
extern struct clocksource *hyperv_cs;
extern void *hv_hypercall_pg;
extern void  __percpu  **hyperv_pcpu_input_arg;

static inline u64 __hv_do_hypercall(u64 control, void *input, void *output)
{
	u64 input_address = input ? virt_to_phys(input) : 0;
	u64 output_address = output ? virt_to_phys(output) : 0;
	u64 hv_status;

#ifdef CONFIG_X86_64
	__asm__ __volatile__("mov %4, %%r8\n"
			     CALL_NOSPEC
			     : "=a" (hv_status), ASM_CALL_CONSTRAINT,
			       "+c" (control), "+d" (input_address)
			     :  "r" (output_address),
				THUNK_TARGET(hv_hypercall_pg)
			     : "cc", "memory", "r8", "r9", "r10", "r11");
#else
	u32 input_address_hi = upper_32_bits(input_address);
	u32 input_address_lo = lower_32_bits(input_address);
	u32 output_address_hi = upper_32_bits(output_address);
	u32 output_address_lo = lower_32_bits(output_address);

	__asm__ __volatile__(CALL_NOSPEC
			     : "=A" (hv_status),
			       "+c" (input_address_lo), ASM_CALL_CONSTRAINT
			     : "A" (control),
			       "b" (input_address_hi),
			       "D"(output_address_hi), "S"(output_address_lo),
			       THUNK_TARGET(hv_hypercall_pg)
			     : "cc", "memory");
#endif /* !x86_64 */
	return hv_status;
}

/* Fast hypercall with 8 bytes of input and no output */
static inline u64 hv_do_fast_hypercall8(u16 code, u64 input1)
{
	u64 hv_status, control = (u64)code | HV_HYPERCALL_FAST_BIT;

#ifdef CONFIG_X86_64
	{
		__asm__ __volatile__(CALL_NOSPEC
				     : "=a" (hv_status), ASM_CALL_CONSTRAINT,
				       "+c" (control), "+d" (input1)
				     : THUNK_TARGET(hv_hypercall_pg)
				     : "cc", "r8", "r9", "r10", "r11");
	}
#else
	{
		u32 input1_hi = upper_32_bits(input1);
		u32 input1_lo = lower_32_bits(input1);

		__asm__ __volatile__ (CALL_NOSPEC
				      : "=A"(hv_status),
					"+c"(input1_lo),
					ASM_CALL_CONSTRAINT
				      :	"A" (control),
					"b" (input1_hi),
					THUNK_TARGET(hv_hypercall_pg)
				      : "cc", "edi", "esi");
	}
#endif
		return hv_status;
}

/* Fast hypercall with 16 bytes of input */
static inline u64 hv_do_fast_hypercall16(u16 code, u64 input1, u64 input2)
{
	u64 hv_status, control = (u64)code | HV_HYPERCALL_FAST_BIT;

#ifdef CONFIG_X86_64
	{
		__asm__ __volatile__("mov %4, %%r8\n"
				     CALL_NOSPEC
				     : "=a" (hv_status), ASM_CALL_CONSTRAINT,
				       "+c" (control), "+d" (input1)
				     : "r" (input2),
				       THUNK_TARGET(hv_hypercall_pg)
				     : "cc", "r8", "r9", "r10", "r11");
	}
#else
	{
		u32 input1_hi = upper_32_bits(input1);
		u32 input1_lo = lower_32_bits(input1);
		u32 input2_hi = upper_32_bits(input2);
		u32 input2_lo = lower_32_bits(input2);

		__asm__ __volatile__ (CALL_NOSPEC
				      : "=A"(hv_status),
					"+c"(input1_lo), ASM_CALL_CONSTRAINT
				      :	"A" (control), "b" (input1_hi),
					"D"(input2_hi), "S"(input2_lo),
					THUNK_TARGET(hv_hypercall_pg)
				      : "cc");
	}
#endif
		return hv_status;
}

/*
 * Rep hypercalls. Callers of this functions are supposed to ensure that
 * rep_count and varhead_size comply with Hyper-V hypercall definition.
 */
static inline u64 hv_do_rep_hypercall(u16 code, u16 rep_count, u16 varhead_size,
				      void *input, void *output)
{
	u64 control = code;
	u64 status;
	u16 rep_comp;

	if (unlikely(!hv_hypercall_pg))
		return U64_MAX;

	control |= (u64)varhead_size << HV_HYPERCALL_VARHEAD_OFFSET;
	control |= (u64)rep_count << HV_HYPERCALL_REP_COMP_OFFSET;

	do {
		status = __hv_do_hypercall(control, input, output);
		if ((status & HV_HYPERCALL_RESULT_MASK) != HV_STATUS_SUCCESS)
			return status;

		/* Bits 32-43 of status have 'Reps completed' data. */
		rep_comp = (status & HV_HYPERCALL_REP_COMP_MASK) >>
			HV_HYPERCALL_REP_COMP_OFFSET;

		control &= ~HV_HYPERCALL_REP_START_MASK;
		control |= (u64)rep_comp << HV_HYPERCALL_REP_START_OFFSET;

		touch_nmi_watchdog();
	} while (rep_comp < rep_count);

	return status;
}

/* ibytes = fixed header size + var header size + data size in bytes */
static inline u64 hv_do_xmm_fast_hypercall(
	u32 varhead_code, void *input, size_t ibytes,
	void *output, size_t obytes)
{
	u64 control = (u64)varhead_code | HV_HYPERCALL_FAST_BIT;
	u64 hv_status;
	u64 input1;
	u64 input2;
	size_t i_end = roundup(ibytes, 16);
	size_t o_end = i_end + roundup(obytes, 16);
	u64 *ixmm = (u64 *)input + 2;
	u64 tmp[(o_end - 16) / 8] __aligned((16));

	BUG_ON(i_end <= 16);
	BUG_ON(o_end > HV_XMM_BYTE_MAX);
	BUG_ON(!IS_ALIGNED((unsigned long)input, 16));
	BUG_ON(!IS_ALIGNED((unsigned long)output, 16));

	/* it's assumed that there are at least two inputs */
	input1 = ((u64 *)input)[0];
	input2 = ((u64 *)input)[1];

	preempt_disable();
	if (o_end > 2 * 8)
		__asm__ __volatile__("movdqa %%xmm0, %0" : : "m" (tmp[0]));
	if (o_end > 4 * 8)
		__asm__ __volatile__("movdqa %%xmm1, %0" : : "m" (tmp[2]));
	if (o_end > 6 * 8)
		__asm__ __volatile__("movdqa %%xmm2, %0" : : "m" (tmp[4]));
	if (o_end > 8 * 8)
		__asm__ __volatile__("movdqa %%xmm3, %0" : : "m" (tmp[6]));
	if (o_end > 10 * 8)
		__asm__ __volatile__("movdqa %%xmm4, %0" : : "m" (tmp[8]));
	if (o_end > 12 * 8)
		__asm__ __volatile__("movdqa %%xmm5, %0" : : "m" (tmp[10]));
	if (ibytes > 2 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm0" : : "m" (ixmm[0]));
	if (ibytes > 4 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm1" : : "m" (ixmm[2]));
	if (ibytes > 6 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm2" : : "m" (ixmm[4]));
	if (ibytes > 8 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm3" : : "m" (ixmm[6]));
	if (ibytes > 10 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm4" : : "m" (ixmm[8]));
	if (ibytes > 12 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm5" : : "m" (ixmm[10]));

#ifdef CONFIG_X86_64
	__asm__ __volatile__("mov %4, %%r8\n"
			     CALL_NOSPEC
			     : "=a" (hv_status), ASM_CALL_CONSTRAINT,
			       "+c" (control), "+d" (input1)
			     : "r" (input2),
			       THUNK_TARGET(hv_hypercall_pg)
			     : "cc", "memory", "r8", "r9", "r10", "r11");
#else
	{
		u32 input1_hi = upper_32_bits(input1);
		u32 input1_lo = lower_32_bits(input1);
		u32 input2_hi = upper_32_bits(input2);
		u32 input2_lo = lower_32_bits(input2);

		__asm__ __volatile__ (CALL_NOSPEC
				      : "=A"(hv_status),
					"+c"(input1_lo), ASM_CALL_CONSTRAINT
				      :	"A" (control), "b" (input1_hi),
					"D"(input2_hi), "S"(input2_lo),
					THUNK_TARGET(hv_hypercall_pg)
				      : "cc", "memory");
	}
#endif
	if (output) {
		u64 *oxmm = (u64 *)output;
		if (i_end <= 2 * 8 && 2 * 8 < o_end) {
			__asm__ __volatile__(
				"movdqa %%xmm0, %0" : "=m" (oxmm[0]));
			oxmm += 2;
		}
		if (i_end <= 4 * 8 && 4 * 8 < o_end) {
			__asm__ __volatile__(
				"movdqa %%xmm1, %0" : "=m" (oxmm[0]));
			oxmm += 2;
		}
		if (i_end <= 6 * 8 && 6 * 8 < o_end) {
			__asm__ __volatile__(
				"movdqa %%xmm2, %0" : "=m" (oxmm[0]));
			oxmm += 2;
		}
		if (i_end <= 8 * 8 && 8 * 8 < o_end) {
			__asm__ __volatile__(
				"movdqa %%xmm3, %0" : "=m" (oxmm[0]));
			oxmm += 2;
		}
		if (i_end <= 10 * 8 && 10 * 8 < o_end) {
			__asm__ __volatile__(
				"movdqa %%xmm4, %0" : "=m" (oxmm[0]));
			oxmm += 2;
		}
		if (i_end <= 12 * 8 && 12 * 8 < o_end) {
			__asm__ __volatile__(
				"movdqa %%xmm5, %0" : "=m" (oxmm[0]));
			oxmm += 2;
		}
	}
	if (o_end > 2 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm0" : : "m" (tmp[0]));
	if (o_end > 4 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm1" : : "m" (tmp[2]));
	if (o_end > 6 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm2" : : "m" (tmp[4]));
	if (o_end > 8 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm3" : : "m" (tmp[6]));
	if (o_end > 10 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm4" : : "m" (tmp[8]));
	if (o_end > 12 * 8)
		__asm__ __volatile__("movdqa %0, %%xmm5" : : "m" (tmp[10]));
	preempt_enable();

	return hv_status;
}

static inline u64 hv_do_hypercall(
	u32 varhead_code,
	void *input, size_t ibytes, void *output, size_t obytes)
{
	if (unlikely(!hv_hypercall_pg))
		return U64_MAX;

	/* fast hypercall */
	if (output == NULL && ibytes <= 16) {
		u64 *i = (u64*)input;

		WARN_ON((varhead_code & HV_HYPERCALL_VARHEAD_MASK) != 0);
		if (ibytes <= 8)
			return hv_do_fast_hypercall8((u16)varhead_code, i[0]);

		return hv_do_fast_hypercall16((u16)varhead_code, i[0], i[1]);
	}

	/* xmm fast hypercall */
	if (static_cpu_has(X86_FEATURE_XMM) &&
	    ms_hyperv.features & HV_X64_HYPERCALL_PARAMS_XMM_AVAILABLE &&
	    roundup(ibytes, 16) + obytes <= HV_XMM_BYTE_MAX) {
		if (output) {
			if (ms_hyperv.features &
			    HV_X64_HYPERCALL_OUTPUT_XMM_AVAILABLE)
				return hv_do_xmm_fast_hypercall(
					varhead_code, input, ibytes,
					output, obytes);
		} else {
			WARN_ON(obytes > 0);
			return hv_do_xmm_fast_hypercall(
				varhead_code, input, ibytes, NULL, 0);
		}
	}

	return __hv_do_hypercall((u64)varhead_code, input, output);
}

/*
 * Hypervisor's notion of virtual processor ID is different from
 * Linux' notion of CPU ID. This information can only be retrieved
 * in the context of the calling CPU. Setup a map for easy access
 * to this information.
 */
extern u32 *hv_vp_index;
extern u32 hv_max_vp_index;
extern struct hv_vp_assist_page **hv_vp_assist_page;

static inline struct hv_vp_assist_page *hv_get_vp_assist_page(unsigned int cpu)
{
	if (!hv_vp_assist_page)
		return NULL;

	return hv_vp_assist_page[cpu];
}

/**
 * hv_cpu_number_to_vp_number() - Map CPU to VP.
 * @cpu_number: CPU number in Linux terms
 *
 * This function returns the mapping between the Linux processor
 * number and the hypervisor's virtual processor number, useful
 * in making hypercalls and such that talk about specific
 * processors.
 *
 * Return: Virtual processor number in Hyper-V terms
 */
static inline int hv_cpu_number_to_vp_number(int cpu_number)
{
	return hv_vp_index[cpu_number];
}

static inline int cpumask_to_vpset(struct hv_vpset *vpset,
				    const struct cpumask *cpus)
{
	int cpu, vcpu, vcpu_bank, vcpu_offset, nr_bank = 1;

	/* valid_bank_mask can represent up to 64 banks */
	if (hv_max_vp_index / 64 >= 64)
		return 0;

	/*
	 * Clear all banks up to the maximum possible bank as hv_tlb_flush_ex
	 * structs are not cleared between calls, we risk flushing unneeded
	 * vCPUs otherwise.
	 */
	for (vcpu_bank = 0; vcpu_bank <= hv_max_vp_index / 64; vcpu_bank++)
		vpset->bank_contents[vcpu_bank] = 0;

	/*
	 * Some banks may end up being empty but this is acceptable.
	 */
	for_each_cpu(cpu, cpus) {
		vcpu = hv_cpu_number_to_vp_number(cpu);
		if (vcpu == VP_INVAL)
			return -1;
		vcpu_bank = vcpu / 64;
		vcpu_offset = vcpu % 64;
		__set_bit(vcpu_offset, (unsigned long *)
			  &vpset->bank_contents[vcpu_bank]);
		if (vcpu_bank >= nr_bank)
			nr_bank = vcpu_bank + 1;
	}
	vpset->valid_bank_mask = GENMASK_ULL(nr_bank - 1, 0);
	return nr_bank;
}

void __init hyperv_init(void);
void hyperv_setup_mmu_ops(void);
void hyperv_report_panic(struct pt_regs *regs, long err);
bool hv_is_hyperv_initialized(void);
void hyperv_cleanup(void);

void hyperv_reenlightenment_intr(struct pt_regs *regs);
void set_hv_tscchange_cb(void (*cb)(void));
void clear_hv_tscchange_cb(void);
void hyperv_stop_tsc_emulation(void);

#ifdef CONFIG_X86_64
void hv_apic_init(void);
#else
static inline void hv_apic_init(void) {}
#endif

#else /* CONFIG_HYPERV */
static inline void hyperv_init(void) {}
static inline bool hv_is_hyperv_initialized(void) { return false; }
static inline void hyperv_cleanup(void) {}
static inline void hyperv_setup_mmu_ops(void) {}
static inline void set_hv_tscchange_cb(void (*cb)(void)) {}
static inline void clear_hv_tscchange_cb(void) {}
static inline void hyperv_stop_tsc_emulation(void) {};
static inline struct hv_vp_assist_page *hv_get_vp_assist_page(unsigned int cpu)
{
	return NULL;
}
#endif /* CONFIG_HYPERV */

#ifdef CONFIG_HYPERV_TSCPAGE
struct ms_hyperv_tsc_page *hv_get_tsc_page(void);
static inline u64 hv_read_tsc_page_tsc(const struct ms_hyperv_tsc_page *tsc_pg,
				       u64 *cur_tsc)
{
	u64 scale, offset;
	u32 sequence;

	/*
	 * The protocol for reading Hyper-V TSC page is specified in Hypervisor
	 * Top-Level Functional Specification ver. 3.0 and above. To get the
	 * reference time we must do the following:
	 * - READ ReferenceTscSequence
	 *   A special '0' value indicates the time source is unreliable and we
	 *   need to use something else. The currently published specification
	 *   versions (up to 4.0b) contain a mistake and wrongly claim '-1'
	 *   instead of '0' as the special value, see commit c35b82ef0294.
	 * - ReferenceTime =
	 *        ((RDTSC() * ReferenceTscScale) >> 64) + ReferenceTscOffset
	 * - READ ReferenceTscSequence again. In case its value has changed
	 *   since our first reading we need to discard ReferenceTime and repeat
	 *   the whole sequence as the hypervisor was updating the page in
	 *   between.
	 */
	do {
		sequence = READ_ONCE(tsc_pg->tsc_sequence);
		if (!sequence)
			return U64_MAX;
		/*
		 * Make sure we read sequence before we read other values from
		 * TSC page.
		 */
		smp_rmb();

		scale = READ_ONCE(tsc_pg->tsc_scale);
		offset = READ_ONCE(tsc_pg->tsc_offset);
		*cur_tsc = rdtsc_ordered();

		/*
		 * Make sure we read sequence after we read all other values
		 * from TSC page.
		 */
		smp_rmb();

	} while (READ_ONCE(tsc_pg->tsc_sequence) != sequence);

	return mul_u64_u64_shr(*cur_tsc, scale, 64) + offset;
}

static inline u64 hv_read_tsc_page(const struct ms_hyperv_tsc_page *tsc_pg)
{
	u64 cur_tsc;

	return hv_read_tsc_page_tsc(tsc_pg, &cur_tsc);
}

#else
static inline struct ms_hyperv_tsc_page *hv_get_tsc_page(void)
{
	return NULL;
}

static inline u64 hv_read_tsc_page_tsc(const struct ms_hyperv_tsc_page *tsc_pg,
				       u64 *cur_tsc)
{
	BUG();
	return U64_MAX;
}
#endif
#endif
