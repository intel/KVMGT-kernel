#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <asm/page.h>
#include <asm/vmx.h>

/* drivers/xen/vgt/vgt.h */
#include "vgt.h"

static int kvm_vm_getdomid(void)
{
	/* 0 is reserved for Host */
	static int domid = 1;
	return domid++;
}

struct kvm *kvm_find_by_domid(int domid)
{
	struct kvm *kvm = NULL;

	if (unlikely(domid <= 0)) {
		JERROR("FIXME!\n");
		return NULL;
	}

	spin_lock(&kvm_lock);
	list_for_each_entry(kvm,  &vm_list, vm_list) {
		if (kvm->domid == domid) {
			spin_unlock(&kvm_lock);
			goto found;
		}
	}
	spin_unlock(&kvm_lock);
	return NULL;

found:
	return kvm;
}

void kvmgt_init(struct kvm *kvm)
{
	kvm->domid = kvm_vm_getdomid();
	kvm->vgt_enabled = false;
	kvm->vgt = NULL;

	kvm->opregion_gpa = 0;
	kvm->opregion_hva = 0;
	kvm->aperture_hpa = 0;
}

void kvm_record_cf8(struct kvm_vcpu *vcpu, unsigned long qualification, unsigned long rax)
{
	bool write;
	u16 port;

	write = !(qualification & 8);
	port = qualification >> 16;

	if (port == 0xcf8)
		vcpu->arch.last_cfg_addr = (u32)rax;
}

bool kvmgt_pio_is_igd_cfg(struct kvm_vcpu *vcpu)
{
	unsigned int b, d, f, r;
	u32 addr = vcpu->arch.last_cfg_addr;

	switch (vcpu->arch.pio.port) {
	case 0xcfc ... 0xcff:
		break;
	default:
		return false;
	}

	b = (addr >> 16) & 0xff;
	d = (addr >> 11) & 0x1f;
	f = (addr >> 8) & 0x7;
	r = (addr & 0xff);

	if (b == 0 && d == 2 && f == 0) {
		return true;
	}

	return false;
}

bool kvmgt_pio_igd_cfg(struct kvm_vcpu *vcpu)
{
	bool ret = false;
	vcpu->kvm->vgt->last_cf8 = vcpu->arch.last_cfg_addr;

	if (vcpu->arch.pio.in) {
		ret = vgt_hvm_read_cf8_cfc(vcpu->kvm->vgt,
				vcpu->arch.pio.port,
				vcpu->arch.pio.size,
				vcpu->arch.pio_data);
	} else {
		ret = vgt_hvm_write_cf8_cfc(vcpu->kvm->vgt,
				vcpu->arch.pio.port,
				vcpu->arch.pio.size,
				*(unsigned long *)vcpu->arch.pio_data);
	}

	return ret;
}

static int vgt_guest_mmio_in_range(struct kvm_trap_info *info, gpa_t addr)
{
	return ((addr >= info->base_addr) &&
		(addr < info->base_addr + info->len));
}

static int vgt_guest_mmio_read(struct kvm_io_device *this, gpa_t addr, int len,
		void *val)
{
	struct kvm_trap_info *info = container_of(this, struct kvm_trap_info, iodev);
	struct vgt_device *vgt = container_of(info, struct vgt_device, trap_mmio);
	u64 result = 0;

	if (!vgt_guest_mmio_in_range(info, addr))
		return -EOPNOTSUPP;

	if (!vgt_emulate_read(vgt, addr, &result, len)) {
		JERROR("vgt_emulate_read failed!\n");
		return -EFAULT;
	}

	switch (len) {
	case 8:
		*(u64 *)val = result;
		break;
	case 1:
	case 2:
	case 4:
		memcpy(val, (char *)&result, len);
		break;
	default:
		JERROR("FIXME! len is %d\n", len);
		return -EFAULT;
	}

	return 0;
}

static int vgt_guest_mmio_write(struct kvm_io_device *this, gpa_t addr, int len,
		const void *val)
{
	struct kvm_trap_info *info = container_of(this, struct kvm_trap_info, iodev);
	struct vgt_device *vgt = container_of(info, struct vgt_device, trap_mmio);

	if (!vgt_guest_mmio_in_range(info, addr))
		return -EOPNOTSUPP;

	if (!vgt_emulate_write(vgt, addr, (void *)val, len)) {
		JERROR("vgt_emulate_write failed\n");
		return 0;
	}

	return 0;
}

const struct kvm_io_device_ops trap_mmio_ops = {
	.read	= vgt_guest_mmio_read,
	.write	= vgt_guest_mmio_write,
};

void *kvmgt_vmem_gpa_2_va(struct vgt_device *vgt, unsigned long gpa)
{
	unsigned long hva;

	gfn_t gfn = gpa_to_gfn(gpa);
	ASSERT(vgt->vm_id);
	hva = gfn_to_hva(vgt->kvm, gfn) + offset_in_page(gpa);
	return (void *)hva;
}

void kvmgt_inject_msi(struct kvm *kvm, struct kvm_msi *info)
{
	kvm_send_userspace_msi(kvm, info);
}

void kvmgt_put_vgt(struct kvm *kvm)
{
	vgt_params_t vp;

	if (!kvm->vgt_enabled || !kvm->vgt)
		return;

	JDPRINT("release vgt resource for KVM!\n");
	vp.vm_id = -kvm->domid;
	vgt_del_state_sysfs(vp);

	kvm->vgt_enabled = false;
}

bool kvmgt_add_apt_slot(struct vgt_device *vgt, pfn_t p1, gfn_t g1, int nr_mfns, u64 hva)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;
	struct kvm *kvm = vgt->kvm;
	bool unlock = false;

	JDPRINT("hi, vgt-%d, p1: 0x%lx, g1: 0x%lx, nr_mfns: %d, hva: 0x%lx\n", vgt->vm_id,
			(unsigned long)p1, (unsigned long)g1, nr_mfns, (unsigned long)hva);
	JDPRINT("hi, vgt-%d, aperture_offset: 0x%lx\n", vgt->vm_id, (unsigned long)vgt->aperture_offset);

	kvm_userspace_mem.slot = VGT_APERTURE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr = g1 << PAGE_SHIFT;
	kvm_userspace_mem.memory_size = nr_mfns * PAGE_SIZE;

	kvm->aperture_hpa = p1 << PAGE_SHIFT;

	if (!mutex_is_locked(&kvm->slots_lock)) {
		mutex_lock(&kvm->slots_lock);
		unlock = true;
	}
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem);
	if (r) {
		JERROR("__kvm_set_memory_region failed: %d\n", r);
		if (unlock)
			mutex_unlock(&kvm->slots_lock);
		return false;
	}
	if (unlock)
		mutex_unlock(&kvm->slots_lock);

	return true;
}

bool kvmgt_add_opreg_slot(struct vgt_device *vgt, int nr_pages)
{
	struct kvm *kvm = vgt->kvm;
	struct kvm_userspace_memory_region kvm_userspace_mem;
	bool unlock = false;
	int r = 0;

	kvm_userspace_mem.slot = VGT_OPREGION_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr = kvm->opregion_gpa & PAGE_MASK;
	kvm_userspace_mem.memory_size = nr_pages * PAGE_SIZE;

	if (!mutex_is_locked(&kvm->slots_lock)) {
		mutex_lock(&kvm->slots_lock);
		unlock = true;
	}
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem);
	if (r) {
		JERROR("__kvm_set_memory_region failed: %d\n", r);
		if (unlock)
			mutex_unlock(&kvm->slots_lock);
		return false;
	}
	if (unlock)
		mutex_unlock(&kvm->slots_lock);

	return true;
}
