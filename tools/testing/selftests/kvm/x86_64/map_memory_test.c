// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 202r, Intel, Inc
 *
 * Author:
 * Isaku Yamahata <isaku.yamahata at gmail.com>
 */
#include <linux/sizes.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

/* Arbitrarily chosen value. Pick 3G */
#define TEST_GVA		0xc0000000
#define TEST_GPA		TEST_GVA
#define TEST_SIZE		(SZ_2M + PAGE_SIZE)
#define TEST_NPAGES		(TEST_SIZE / PAGE_SIZE)
#define TEST_SLOT		10

static void guest_code(uint64_t base_gpa)
{
	volatile uint64_t val __used;
	int i;

	for (i = 0; i < TEST_NPAGES; i++) {
		uint64_t *src = (uint64_t *)(base_gpa + i * PAGE_SIZE);

		val = *src;
	}

	GUEST_DONE();
}

static void map_memory(struct kvm_vcpu *vcpu, u64 base_address, u64 size,
		       bool should_success)
{
	struct kvm_memory_mapping mapping = {
		.base_address = base_address,
		.size = size,
		.flags = 0,
	};
	int ret;

	do {
		ret = __vcpu_ioctl(vcpu, KVM_MAP_MEMORY, &mapping);
	} while (ret && (errno == EAGAIN || errno == EINTR));

	if (should_success) {
		__TEST_ASSERT_VM_VCPU_IOCTL(!ret, "KVM_MAP_MEMORY", ret, vcpu->vm);
	} else {
		/* No memory slot causes RET_PF_EMULATE. it results in -EINVAL. */
		__TEST_ASSERT_VM_VCPU_IOCTL(ret && errno == EINVAL,
					    "KVM_MAP_MEMORY", ret, vcpu->vm);
	}
}

static void __test_map_memory(unsigned long vm_type, bool private)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = vm_type,
	};
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_vm *vm;
	struct ucall uc;

	vm = vm_create_shape_with_one_vcpu(shape, &vcpu, guest_code);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_SLOT, TEST_NPAGES,
				    private ? KVM_MEM_GUEST_MEMFD : 0);
	virt_map(vm, TEST_GVA, TEST_GPA, TEST_NPAGES);

	if (private)
		vm_mem_set_private(vm, TEST_GPA, TEST_SIZE);

	map_memory(vcpu, TEST_GPA, SZ_2M, true);
	map_memory(vcpu, TEST_GPA + SZ_2M, PAGE_SIZE, true);
	map_memory(vcpu, TEST_GPA + TEST_SIZE, PAGE_SIZE, false);

	vcpu_args_set(vcpu, 1, TEST_GVA);
	vcpu_run(vcpu);

	run = vcpu->run;
	TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
		    "Wanted KVM_EXIT_IO, got exit reason: %u (%s)",
		    run->exit_reason, exit_reason_str(run->exit_reason));

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unknown ucall 0x%lx.", uc.cmd);
		break;
	}

	kvm_vm_free(vm);
}

static void test_map_memory(unsigned long vm_type)
{
	if (!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(vm_type))) {
		pr_info("Skipping tests for vm_type 0x%lx\n", vm_type);
		return;
	}

	__test_map_memory(vm_type, false);
	__test_map_memory(vm_type, true);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_MAP_MEMORY));

	__test_map_memory(KVM_X86_DEFAULT_VM, false);
	test_map_memory(KVM_X86_SW_PROTECTED_VM);
	return 0;
}
