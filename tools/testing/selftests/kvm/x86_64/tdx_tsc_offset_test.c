// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm.h>
#include <stdint.h>

#include "tdx/tdx_util.h"
#include "tdx/test_util.h"

void guest(void)
{
	tdx_test_success();
}

int verify_tsc_offset(void)
{
	uint64_t vmcs_tsc_offset, tsc_offset, tsc_offset_after;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	vcpu = td_vcpu_add(vm, 0, guest);
	TEST_ASSERT(vcpu, "td_vcpu_add()");

	td_finalize(vm);

	printf("Verifying TSC offset for TDX\n");

#define MD_TD_VMCS_TSC_OFFSET	0x0024000300002010ULL
	vcpu_device_attr_get(vcpu, KVM_VCPU_TDX_MD_CTRL, MD_TD_VMCS_TSC_OFFSET,
			     &vmcs_tsc_offset);

	vcpu_device_attr_get(vcpu, KVM_VCPU_TSC_CTRL,
			     KVM_VCPU_TSC_OFFSET, &tsc_offset);
	TEST_ASSERT(tsc_offset == vmcs_tsc_offset,
		    "tsc_offset doesn't match");

	td_vcpu_run(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);
	vcpu_device_attr_get(vcpu, KVM_VCPU_TSC_CTRL,
			     KVM_VCPU_TSC_OFFSET, &tsc_offset_after);
	TEST_ASSERT(tsc_offset_after == vmcs_tsc_offset,
		    "tsc_offset doesn't match");

	printf("\t ... PASSED\n");

	kvm_vm_free(vm);

	return 0;
}

int main(int argc, char **argv)
{
	if (!is_tdx_enabled()) {
		printf("TDX is not supported by the KVM\n"
		       "Skipping the TDX tests.\n");
		return 0;
	}

	return verify_tsc_offset();
}
