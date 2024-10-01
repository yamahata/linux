// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm.h>
#include <stdint.h>

#include "tdx/tdx_util.h"
#include "tdx/test_util.h"

void guest(void)
{
	/* nothing */
}

/*
 * TODO: Get TD_TDCS_EXEC_TSC_OFFSET td metadata.
 * We should check if the vCPU TSC offset matches with the one the TDX module
 * has for the vCPU.  But it's difficult to get the value in the TDX module.
 *
 * KVM maintains TSC offset per vCPU.  By relying on it and tsc=unstable,
 * check if TSC offset for two vCPU are same instead.
 */
int verify_tsc_offset(void)
{
	uint64_t tsc_offset[2], tsc_offset_after[2];
	struct kvm_vcpu *vcpu[2];
	struct kvm_vm *vm;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);

	vcpu[0] = td_vcpu_add(vm, 0, NULL);
	TEST_ASSERT(vcpu[0], "td_vcpu_add()");
	vcpu[1] = td_vcpu_add(vm, 1, NULL);
	TEST_ASSERT(vcpu[1], "td_vcpu_add()");

	td_finalize(vm);

	printf("Verifying TSC offset for TDX\n");

	vcpu_device_attr_get(vcpu[0], KVM_VCPU_TSC_CTRL,
			     KVM_VCPU_TSC_OFFSET, &tsc_offset[0]);
	vcpu_device_attr_get(vcpu[0], KVM_VCPU_TSC_CTRL,
			     KVM_VCPU_TSC_OFFSET, &tsc_offset[1]);
	TEST_ASSERT(tsc_offset[0] == tsc_offset[1], "tsc offset doesn't match");
	/*
	 * TEST_ASSERT(tsc_offset[0] == TD_TDCS_EXEC_TSC_OFFSET td metadata,
	 *             "tsc offset doesn't match");
	 */

	td_vcpu_run(vcpu[0]);
	td_vcpu_run(vcpu[1]);


	vcpu_device_attr_get(vcpu[0], KVM_VCPU_TSC_CTRL,
			     KVM_VCPU_TSC_OFFSET, &tsc_offset_after[0]);
	vcpu_device_attr_get(vcpu[1], KVM_VCPU_TSC_CTRL,
			     KVM_VCPU_TSC_OFFSET, &tsc_offset_after[1]);

	TEST_ASSERT(tsc_offset_after[0] == tsc_offset[0],
		    "tsc_offset doesn't match");
	TEST_ASSERT(tsc_offset_after[1] == tsc_offset[1],
		    "tsc_offset doesn't match");

	printf("\t ... PASSED\n");

	kvm_vm_free(vm);

	return 0;
}

int main(int argc, char **argv)
{
	char cmdline[4096];
	ssize_t ret;
	int fd;

	if (!is_tdx_enabled()) {
		printf("TDX is not supported by the KVM\n"
		       "Skipping the TDX tests.\n");
		return 0;
	}

	/*
	 * this should be removed once we can retrieve TD_TDCS_EXEC_TSC_OFFSET
	 * metadata.
	 *
	 * This is for two vCPU can have different TSC OFFSET when KVM
	 * calculates tsc offset per-vCPU.
	 */
	fd = open_path_or_exit("/proc/cmdline", O_RDONLY);
	ret = read(fd, cmdline, sizeof(cmdline));
	TEST_ASSERT(ret > 0, "failed to read /proc/cmdline");
	TEST_REQUIRE(strstr(cmdline, "tsc=unstable"));
	close(fd);

	return verify_tsc_offset();
}
