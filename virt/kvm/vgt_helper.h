#ifndef _VGT_HELPER_H_
#define _VGT_HELPER_H_

#include <linux/kvm_host.h>

struct kvm *kvm_find_by_domid(int domid);
void kvmgt_init(struct kvm *kvm);
void kvm_record_cf8(struct kvm_vcpu *vcpu, unsigned long qualification, unsigned long rax);
bool kvmgt_pio_is_igd_cfg(struct kvm_vcpu *vcpu);
bool kvmgt_pio_igd_cfg(struct kvm_vcpu *vcpu);
void *kvmgt_vmem_gpa_2_va(struct vgt_device *vgt, unsigned long gpa);
void kvmgt_inject_msi(struct kvm *kvm, struct kvm_msi *info);
void kvmgt_put_vgt(struct kvm *kvm);
bool kvmgt_add_apt_slot(struct vgt_device *vgt, pfn_t p1, gfn_t g1, int nr_mfns, u64 hva);
bool kvmgt_add_opreg_slot(struct vgt_device *vgt, int nr_pages);


static inline int kvmgt_read_hva(struct vgt_device *vgt, void *hva, int len, int atomic)
{
	int data = 0, rc;

#if 1
	if (len != sizeof(data))
		JDPRINT("FIXME!\n");
#endif

	pagefault_disable();
	rc = atomic ? __copy_from_user_inatomic(&data, hva, len) :
		__copy_from_user(&data, hva, len);
	pagefault_enable();

	if (rc != 0)
		JDPRINT("copy_from_user failed: rc == %d, len == %d\n", rc, len);

	return data;
}

static inline int kvmgt_write_hva(struct vgt_device *vgt, void *hva, void *data, int len, int atomic)
{
	int r;

	pagefault_disable();
	if (atomic)
		r = __copy_to_user_inatomic((void __user *)hva, data, len);
	else
		r = __copy_to_user((void __user *)hva, data, len);
	pagefault_enable();

	if (r) {
		JERROR("__copy_to_user failed: %d\n", r);
	}

	return r;
}

#endif /* _VGT_HELPER_H_ */
