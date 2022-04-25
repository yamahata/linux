/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#ifdef CONFIG_INTEL_TDX_HOST

struct kvm_tdx {
	struct kvm kvm;

	unsigned long tdr_pa;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	unsigned long tdvpr_pa;
};

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static __always_inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tdx, kvm);
}

static __always_inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

/*
 * C wrapper functions depend on struct kvm_tdx, struct vcpu_tdx, to_kvm_tdx(),
 * and to_tdx().
 */
#include "tdx_ops.h"

#else
struct kvm_tdx {
	struct kvm kvm;
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;
};

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_H */
