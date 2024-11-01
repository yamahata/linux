// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm.h>
#include <stdint.h>

#include "processor.h"

#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"

#define TDX_TSC_TEST_PRIVATE_GVA	(0x80000000)
#define TDX_TSC_TEST_VADDR_SHARED_MASK BIT_ULL(30)
#define TDX_TSC_TEST_SHARED_GVA			\
	(TDX_TSC_TEST_PRIVATE_GVA |		\
	 TDX_TSC_TEST_VADDR_SHARED_MASK)

static uint64_t test_tsc_private_gpa;
static uint64_t test_tsc_shared_gpa;

static void print_data(struct kvm_shared_tsc_data *tscdata)
{
	int i;

	for(i=0; i< KVM_TSC_MAX_ENTRIES; i++) {
		pr_info("vmeh [%d].r = %lld .c = %lld .o = %lld guestr = %lld"
			" delta=%lld\n", i,
			tscdata->vme[i].r,
			tscdata->vme[i].c,
			tscdata->vme[i].o,
			tscdata->gr[i],
			tscdata->gr[i] -
			(tscdata->vme[i].c + tscdata->vme[i].o));
		if (tscdata->vme[i].r && tscdata->vme[i].c && tscdata->vme[i].o)
			TEST_ASSERT(tscdata->gr[i] >
				    (tscdata->vme[i].c + tscdata->vme[i].o),
				    "guest > scaled host enter");

		pr_info("vmex [%d].r = %lld .c = %lld .o = %lld guestr = %lld"
			" delta=%lld\n", i,
			tscdata->vmex[i].r,
			tscdata->vmex[i].c,
			tscdata->vmex[i].o,
			tscdata->gr[i],
			(tscdata->vmex[i].c + tscdata->vmex[i].o) -
			tscdata->gr[i]);
		if (tscdata->vmex[i].r && tscdata->vmex[i].c && tscdata->vmex[i].o)
			TEST_ASSERT((tscdata->vmex[i].c + tscdata->vmex[i].o) >
				    tscdata->gr[i],
				    "scaled host exit > guest");
	}
}

void guest_tsc(void)
{
	struct kvm_shared_tsc_data *tscdata =
		(struct kvm_shared_tsc_data *)TDX_TSC_TEST_SHARED_GVA;
	uint64_t placeholder;
	uint64_t ret;
	int i;

	/* Map gpa as shared */
	ret = tdg_vp_vmcall_map_gpa(test_tsc_shared_gpa, PAGE_SIZE,
				    &placeholder);
	if (ret)
		tdx_test_fatal_with_data(ret, __LINE__);

	tdg_vp_vmcall_instruction_wrmsr(MSR_KVM_DEBUG_TDXTSC, test_tsc_private_gpa | 0x1);
	for (i = 0; i < KVM_TSC_MAX_ENTRIES; i++) {
		tscdata->gr[tscdata->i] = rdtsc(); /* lfence;rdtsc;lfence */
		tdg_vp_vmcall_instruction_wrmsr(MSR_KVM_DEBUG_TDXTSC, test_tsc_private_gpa);
	}
	tdg_vp_vmcall_instruction_wrmsr(MSR_KVM_DEBUG_TDXTSC, 0);

	tdx_test_success();
}

void tdx_vcpu_run(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	int64_t gpa;

	for (;;) {
		vcpu_run(vcpu);

		if (!(vcpu->run->exit_reason == KVM_EXIT_HYPERCALL &&
		      vcpu->run->hypercall.nr == KVM_HC_MAP_GPA_RANGE))
			break;

		gpa = vcpu->run->hypercall.args[0];
		handle_memory_conversion(vm, gpa,
					 vcpu->run->hypercall.args[1] << PAGE_SHIFT,
					 vcpu->run->hypercall.args[2] & KVM_MAP_GPA_RANGE_ENCRYPTED);
		vcpu->run->hypercall.ret = 0;
	}
}

int verify_tsc_offset(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	vm_vaddr_t test_tsc_private_gva;
	struct kvm_shared_tsc_data *tscdata_hva;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	vcpu = td_vcpu_add(vm, 0, guest_tsc);
	TEST_ASSERT(vcpu, "td_vcpu_add()");

	/* Set up shared memory page for recording tsc */
	test_tsc_private_gva = vm_vaddr_alloc(vm, vm->page_size,
					      TDX_TSC_TEST_PRIVATE_GVA);
	TEST_ASSERT_EQ(test_tsc_private_gva, TDX_TSC_TEST_PRIVATE_GVA);

	tscdata_hva = addr_gva2hva(vm, test_tsc_private_gva);
	TEST_ASSERT(tscdata_hva != NULL,
		    "Guest address not found in guest memory regions\n");
	memset(tscdata_hva, 0, vm->page_size);

	test_tsc_private_gpa = addr_gva2gpa(vm, test_tsc_private_gva);
	virt_pg_map_shared(vm, TDX_TSC_TEST_SHARED_GVA,
			   test_tsc_private_gpa);

	test_tsc_shared_gpa = test_tsc_private_gpa | BIT_ULL(vm->pa_bits - 1);
	sync_global_to_guest(vm, test_tsc_private_gpa);
	sync_global_to_guest(vm, test_tsc_shared_gpa);

	td_finalize(vm);
	vm_enable_cap(vm, KVM_CAP_EXIT_HYPERCALL, BIT_ULL(KVM_HC_MAP_GPA_RANGE));

	printf("Verifying TSC offset for TDX\n");

	tdx_vcpu_run(vm, vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	print_data(tscdata_hva);

	printf("\t ... PASSED\n");
	kvm_vm_free(vm);

	return 0;
}

static void help(const char *prog_name)
{
	printf("usage: %s [-c <pCPU>]\n"
	       "-c: Pin tasks to physical CPUs.     (default: no pinning)\n"
	       "\n",
	       prog_name);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	uint32_t pcpu = -1;
	int opt;

	if (!is_tdx_enabled()) {
		printf("TDX is not supported by the KVM\n"
		       "Skipping the TDX tests.\n");
		return 0;
	}

	while ((opt = getopt(argc, argv, "c:")) != -1) {
		switch (opt) {
		case 'c':
			pcpu = atoi_non_negative("pCPU number", optarg);
			break;
		case 'h':
		default:
			help(argv[0]);
			break;
		}
	}

	if (pcpu != -1)
		kvm_pin_this_task_to_pcpu(pcpu);

	return verify_tsc_offset();
}
