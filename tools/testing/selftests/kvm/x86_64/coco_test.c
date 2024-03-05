// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Intel, Inc
 *
 * Author:
 * Isaku Yamahata <isaku.yamahata at gmail.com>
 */
#include <linux/sizes.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

static void guest_code(uint64_t base_gpa)
{
}

static void test_update_coco(unsigned long vm_type, uint32_t nr_vcpus)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = vm_type,
	};
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
	struct kvm_coco update;
	struct kvm_vm *vm;
	uint32_t i;
	int r;

	vm = __vm_create_with_vcpus(shape, nr_vcpus, 0, guest_code, vcpus);
	TEST_REQUIRE(vm_check_cap(vm, KVM_CAP_COCO));

	update = (struct kvm_coco) {
		.cmd = KVM_COCO_INIT,
	};
	vm_ioctl(vm, KVM_UPDATE_COCO, &update);

	for (i = 0; i < nr_vcpus; i++) {
		update = (struct kvm_coco) {
			.cmd = KVM_COCO_INIT,
		};
		vcpu_ioctl(vcpus[i], KVM_UPDATE_COCO, &update);
	}

	update = (struct kvm_coco) {
		.cmd = KVM_COCO_MEMORY,
	};
	vm_ioctl(vm, KVM_UPDATE_COCO, &update);

	update = (struct kvm_coco) {
		.cmd = KVM_COCO_FIN,
	};
	vm_ioctl(vm, KVM_UPDATE_COCO, &update);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) &
		     BIT(KVM_X86_SW_PROTECTED_VM));

	test_update_coco(KVM_X86_SW_PROTECTED_VM, 1);
	test_update_coco(KVM_X86_SW_PROTECTED_VM, 256);

	return 0;
}
