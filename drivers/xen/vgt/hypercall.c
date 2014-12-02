/*
 * Interfaces coupled to Xen
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef CONFIG_XEN
#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <xen/xen-ops.h>
#include <xen/interface/memory.h>
#include <xen/interface/hvm/params.h>
#endif

#include "vgt.h"


/* Translate from VM's guest pfn to machine pfn
 * WARN: Be careful! there are 3 conditions: XEN dom0, native and KVM
 */
unsigned long g2m_pfn(struct vgt_device *vgt, unsigned long g_pfn)
{
	struct xen_get_mfn_from_pfn pfn_arg;
	int rc;
	unsigned long pfn_list[1];

	if (vgt_in_xen) {
		pfn_list[0] = g_pfn;

		set_xen_guest_handle(pfn_arg.pfn_list, pfn_list);
		pfn_arg.nr_pfns = 1;
		pfn_arg.domid = vgt->vm_id;

		rc = HYPERVISOR_memory_op(XENMEM_get_mfn_from_pfn, &pfn_arg);
		if(rc < 0){
			vgt_err("failed to get mfn for gpfn(0x%lx)\n, errno=%d\n", g_pfn,rc);
			return INVALID_MFN;
		}

		return pfn_list[0];
	} else {
		pfn_t pfn;

		if (!vgt->vm_id) {
			pfn = g_pfn;
		} else {
			pfn = gfn_to_pfn_atomic(vgt->kvm, g_pfn);
			if (is_error_pfn(pfn)) {
				vgt_err("gfn_to_pfn failed for VM%d, gfn: 0x%lx\n", vgt->vm_id, g_pfn);
				pfn = INVALID_MFN;
			}
		}
		return pfn;
	}
}

int vgt_get_hvm_max_gpfn(int vm_id)
{
	domid_t dom_id = vm_id;
	int max_gpfn = 0;

	if (vgt_in_xen) {
		max_gpfn = HYPERVISOR_memory_op(XENMEM_maximum_gpfn, &dom_id);
		BUG_ON(max_gpfn < 0);
	}

	return max_gpfn;
}

int vgt_hvm_enable(struct vgt_device *vgt)
{
	struct kvm *kvm;

	if (vgt_in_xen)
		return 0;

	kvm = kvm_find_by_domid(vgt->vm_id);
	if (kvm == NULL) {
		vgt_err("kvm_find_by_domid by %d failed\n", vgt->vm_id);
		return -ENOSPC;
	}

	kvm->vgt = vgt;
	kvm->vgt_enabled = true;
	vgt->kvm = kvm;

	return 0;
}

int vgt_pause_domain(struct vgt_device *vgt)
{
	struct xen_domctl domctl;
	int rc = 0;

	if (vgt_in_xen) {
		domctl.domain = (domid_t)vgt->vm_id;
		domctl.cmd = XEN_DOMCTL_pausedomain;
		domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

		rc = HYPERVISOR_domctl(&domctl);
		if (rc != 0)
			vgt_err("HYPERVISOR_domctl pausedomain fail with %d!\n", rc);

	} else {
		vgt_err("FIXME!\n");
	}

	return rc;
}

void vgt_shutdown_domain(struct vgt_device *vgt)
{
	struct sched_remote_shutdown r;
	int rc;

	if (!vgt_in_xen)
		return;

	r.reason = SHUTDOWN_crash;
	r.domain_id = vgt->vm_id;
	rc = HYPERVISOR_sched_op(SCHEDOP_remote_shutdown, &r);
	if (rc != 0)
		vgt_err("failed to HYPERVISOR_sched_op\n");
}

static int vgt_hvm_memory_mapping(int vm_id, uint64_t first_gfn, uint64_t first_mfn,
                                  uint32_t nr_mfns, uint32_t add_mapping)
{
	struct xen_domctl arg;
	int rc;

	arg.domain = vm_id;
	arg.cmd = XEN_DOMCTL_memory_mapping;
	arg.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	arg.u.memory_mapping.first_gfn = first_gfn;
	arg.u.memory_mapping.first_mfn = first_mfn;
	arg.u.memory_mapping.nr_mfns = nr_mfns;
	arg.u.memory_mapping.add_mapping = add_mapping;

	rc = HYPERVISOR_domctl(&arg);
	if (rc<0){
		printk(KERN_ERR "HYPERVISOR_domctl fail ret=%d\n",rc);
		/* assume it is UP */
		return 1;
	}

	return 0;
}

int vgt_hvm_opregion_map(struct vgt_device *vgt, int map)
{
	int i;
	void *opregion;
	struct xen_hvm_vgt_map_mmio memmap;
	int rc;

	if (vgt_in_xen) {
		opregion = vgt->state.opregion_va;

		memset(&memmap, 0, sizeof(memmap));
		for (i = 0; i < VGT_OPREGION_PAGES; i++) {
/*
			memmap.first_gfn = vgt->state.opregion_gfn[i];
			memmap.first_mfn = vgt_virt_to_mfn(opregion + i*PAGE_SIZE);
			memmap.nr_mfns = 1;
			memmap.map = map;
			memmap.domid = vgt->vm_id;
			rc = HYPERVISOR_hvm_op(HVMOP_vgt_map_mmio, &memmap);
*/
			rc = vgt_hvm_memory_mapping(vgt->vm_id, vgt->state.opregion_gfn[i],
					vgt_virt_to_mfn(opregion + i*PAGE_SIZE),
					1, map ? DPCI_ADD_MAPPING : DPCI_REMOVE_MAPPING);
			if (rc != 0)
				vgt_err("vgt_hvm_map_opregion fail with %d!\n", rc);
		}

		return rc;
	} else {
		/* For KVM, the mapping is already done */
		if (!map) {
			vunmap(vgt->state.opregion_va);
			for (i = 0; i < VGT_OPREGION_PAGES; i++)
				put_page(vgt->state.opregion_pages[i]);
		}
		return 0;
	}
}

/*
 * Map the aperture space (BAR1) of vGT device for direct access.
 */
static int kvm_map_aperture(struct vgt_device *vgt, int map)
{
	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t bar_s;
	int r;
	gfn_t first_gfn;
	pfn_t first_pfn;
	uint32_t nr_mfns;

	if (!vgt_pci_mmio_is_enabled(vgt))
		return 0;

	/* guarantee the sequence of map -> unmap -> map -> unmap */
	if (map == vgt->state.bar_mapped[1])
		return 0;

	cfg_space += VGT_REG_CFG_SPACE_BAR1;	/* APERTUR */
	if (VGT_GET_BITS(*cfg_space, 2, 1) == 2){
		/* 64 bits MMIO bar */
		bar_s = * (uint64_t *) cfg_space;
	} else {
		/* 32 bits MMIO bar */
		bar_s = * (uint32_t*) cfg_space;
	}
	first_gfn = (bar_s + vgt_aperture_offset(vgt)) >> PAGE_SHIFT;
	first_pfn = vgt_aperture_base(vgt) >> PAGE_SHIFT;
	if (!vgt->ballooning) {
		nr_mfns = vgt->state.bar_size[1] >> PAGE_SHIFT;
	} else
		nr_mfns = vgt_aperture_sz(vgt) >> PAGE_SHIFT;


	if (!map) {
		return 0;
	}

	r = kvmgt_add_apt_slot(vgt, first_pfn, first_gfn, nr_mfns, (u64)vgt_aperture_vbase(vgt));
	vgt->state.bar_mapped[1] = 1;

	return r;
}

int vgt_hvm_map_aperture(struct vgt_device *vgt, int map)
{
	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t bar_s;
	int r;
	struct xen_hvm_vgt_map_mmio memmap;

	if (!vgt_in_xen)
		return kvm_map_aperture(vgt, map);

	if (!vgt_pci_mmio_is_enabled(vgt))
		return 0;

	/* guarantee the sequence of map -> unmap -> map -> unmap */
	if (map == vgt->state.bar_mapped[1])
		return 0;

	cfg_space += VGT_REG_CFG_SPACE_BAR1;	/* APERTUR */
	if (VGT_GET_BITS(*cfg_space, 2, 1) == 2){
		/* 64 bits MMIO bar */
		bar_s = * (uint64_t *) cfg_space;
	} else {
		/* 32 bits MMIO bar */
		bar_s = * (uint32_t*) cfg_space;
	}

	memmap.first_gfn = (bar_s + vgt_aperture_offset(vgt)) >> PAGE_SHIFT;
	memmap.first_mfn = vgt_aperture_base(vgt) >> PAGE_SHIFT;
	if (!vgt->ballooning)
		memmap.nr_mfns = vgt->state.bar_size[1] >> PAGE_SHIFT;
	else
		memmap.nr_mfns = vgt_aperture_sz(vgt) >> PAGE_SHIFT;

	memmap.map = map;
	memmap.domid = vgt->vm_id;

	printk("%s: domid=%d gfn_s=0x%llx mfn_s=0x%llx nr_mfns=0x%x\n", map==0? "remove_map":"add_map",
			vgt->vm_id, memmap.first_gfn, memmap.first_mfn, memmap.nr_mfns);

	//r = HYPERVISOR_hvm_op(HVMOP_vgt_map_mmio, &memmap);
	r = vgt_hvm_memory_mapping(vgt->vm_id, memmap.first_gfn, memmap.first_mfn,
			memmap.nr_mfns, map ? DPCI_ADD_MAPPING : DPCI_REMOVE_MAPPING);

	if (r != 0)
		printk(KERN_ERR "vgt_hvm_map_aperture fail with %d!\n", r);
	else
		vgt->state.bar_mapped[1] = map;

	return r;
}

#ifdef CONFIG_XENGT
int vgt_io_trap(struct xen_domctl *ctl)
{
	int r;

	ctl->cmd = XEN_DOMCTL_vgt_io_trap;
	ctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	r = HYPERVISOR_domctl(ctl);
	if (r) {
		printk(KERN_ERR "%s(): HYPERVISOR_domctl fail: %d\n", __func__, r);
		return r;
	}

	return 0;
}
#endif

/*
 * Zap the GTTMMIO bar area for vGT trap and emulation.
 */
static int kvm_set_trap_area(struct vgt_device *vgt)
{
	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t bar_s;
	int len;
	int r;
	struct kvm *kvm;
	bool unlock = false;

	if (!vgt_pci_mmio_is_enabled(vgt))
		return 0;

	cfg_space += VGT_REG_CFG_SPACE_BAR0;
	if (VGT_GET_BITS(*cfg_space, 2, 1) == 2) {
		/* 64 bits MMIO bar */
		bar_s = * (uint64_t *) cfg_space;
	} else {
		/* 32 bits MMIO bar */
		bar_s = * (uint32_t*) cfg_space;
	}

	bar_s &= ~0xF; /* clear the LSB 4 bits */
	len = vgt->state.bar_size[0];

	if (vgt->trap_mmio.set)
		return 0;

	kvm = kvm_find_by_domid(vgt->vm_id);
	if (kvm == NULL) {
		vgt_err("unable to find KVM guest: %d\n", vgt->vm_id);
		return 0;
	}

	vgt->trap_mmio.base_addr = bar_s;
	vgt->trap_mmio.len = len;

	kvm_iodevice_init(&vgt->trap_mmio.iodev, &trap_mmio_ops);
	if (!mutex_is_locked(&kvm->slots_lock)) {
		unlock = true;
		mutex_lock(&kvm->slots_lock);
	}
	r = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, vgt->trap_mmio.base_addr,
			len, &vgt->trap_mmio.iodev);
	if (unlock)
		mutex_unlock(&kvm->slots_lock);
	if (r < 0) {
		vgt_err("kvm_io_bus_register_dev failed: %d\n", r);
		return 0;
	}

	vgt->trap_mmio.set = true;

	return 0;
}

int vgt_hvm_set_trap_area(struct vgt_device *vgt)
{
	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t bar_s, bar_e;

	int r;

	if (!vgt_pci_mmio_is_enabled(vgt))
		return 0;

	if (!vgt_in_xen)
		return kvm_set_trap_area(vgt);

	cfg_space += VGT_REG_CFG_SPACE_BAR0;
	if (VGT_GET_BITS(*cfg_space, 2, 1) == 2) {
		/* 64 bits MMIO bar */
		bar_s = * (uint64_t *) cfg_space;
	} else {
		/* 32 bits MMIO bar */
		bar_s = * (uint32_t*) cfg_space;
	}

	bar_s &= ~0xF; /* clear the LSB 4 bits */
	bar_e = bar_s + vgt->state.bar_size[0] - 1;

	r = hvm_map_io_range_to_ioreq_server(vgt, 1, bar_s, bar_e);
	if (r < 0) {
		printk(KERN_ERR "VGT: %s(): fail to trap area: %d.\n", __func__, r);
		return r;
	}

	return r;
}

#ifdef CONFIG_XENGT
int xen_get_nr_vcpu(int vm_id)
{
	struct xen_domctl arg;
	int rc;

	arg.domain = vm_id;
	arg.cmd = XEN_DOMCTL_getdomaininfo;
	arg.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	rc = HYPERVISOR_domctl(&arg);
	if (rc<0){
		printk(KERN_ERR "HYPERVISOR_domctl fail ret=%d\n",rc);
		/* assume it is UP */
		return 1;
	}

	return arg.u.getdomaininfo.max_vcpu_id + 1;
}
#endif

#ifdef CONFIG_XENGT
static int hvm_create_iorequest_server(struct vgt_device *vgt)
{
	struct xen_hvm_create_ioreq_server arg;
	int r;

	arg.domid = vgt->vm_id;
	arg.handle_bufioreq = 0;
	r = HYPERVISOR_hvm_op(HVMOP_create_ioreq_server, &arg);
	if (r < 0) {
		printk(KERN_ERR "Cannot create io-requset server: %d!\n", r);
		return r;
	}
	vgt->iosrv_id = arg.id;

	return r;
}

int hvm_enable_iorequest_server(struct vgt_device *vgt, bool enable)
{
	struct xen_hvm_set_ioreq_server_state arg;
	int r;

	arg.domid = vgt->vm_id;
	arg.id = vgt->iosrv_id;
	arg.enabled = enable;
	r = HYPERVISOR_hvm_op(HVMOP_set_ioreq_server_state, &arg);
	if (r < 0) {
		printk(KERN_ERR "Cannot %s io-request server: %d!\n",
			enable ? "enable" : "disbale",  r);
		return r;
	}

	return r;
}

static int hvm_get_ioreq_pfn(struct vgt_device *vgt, uint64_t *value)
{
	struct xen_hvm_get_ioreq_server_info arg;
	int r;

	arg.domid = vgt->vm_id;
	arg.id = vgt->iosrv_id;
	r = HYPERVISOR_hvm_op(HVMOP_get_ioreq_server_info, &arg);
	if (r < 0) {
		printk(KERN_ERR "Cannot get ioreq pfn: %d!\n", r);
		return r;
	}
	*value = arg.ioreq_pfn;

	return r;
}

int hvm_destroy_iorequest_server(struct vgt_device *vgt)
{
	struct xen_hvm_destroy_ioreq_server arg;
	int r;

	arg.domid = vgt->vm_id;
	arg.id = vgt->iosrv_id;
	r = HYPERVISOR_hvm_op(HVMOP_destroy_ioreq_server, &arg);
	if (r < 0) {
		printk(KERN_ERR "Cannot destroy io-request server(%d): %d!\n",
			vgt->iosrv_id, r);
		return r;
	}
	vgt->iosrv_id = 0;

	return r;
}

int hvm_map_io_range_to_ioreq_server(struct vgt_device *vgt,
	int is_mmio, uint64_t start, uint64_t end)
{
	xen_hvm_io_range_t arg;
	int rc;

	arg.domid = vgt->vm_id;
	arg.id = vgt->iosrv_id;
	arg.type = is_mmio ? HVMOP_IO_RANGE_MEMORY : HVMOP_IO_RANGE_PORT;
	arg.start = start;
	arg.end = end;
	rc = HYPERVISOR_hvm_op(HVMOP_map_io_range_to_ioreq_server, &arg);
	if (rc < 0) {
		printk(KERN_ERR "Cannot map io range to ioreq_server: %d!\n", rc);
		return rc;
	}

	return rc;
}

int hvm_map_pcidev_to_ioreq_server(struct vgt_device *vgt, uint64_t sbdf)
{
	xen_hvm_io_range_t arg;
	int rc;

	arg.domid = vgt->vm_id;
	arg.id = vgt->iosrv_id;
	arg.type = HVMOP_IO_RANGE_PCI;
	arg.start = arg.end = sbdf;
	rc = HYPERVISOR_hvm_op(HVMOP_map_io_range_to_ioreq_server, &arg);
	if (rc < 0) {
		printk(KERN_ERR "Cannot map pci_dev to ioreq_server: %d!\n", rc);
		return rc;
	}

	return rc;
}

int hvm_wp_pages_to_ioreq_server(struct vgt_device *vgt, int nr, unsigned long *pages,
					int set)
{
	xen_hvm_wp_pages_to_ioreq_server_t arg;
	int i, rc;

	arg.domid = vgt->vm_id;
	arg.id = vgt->iosrv_id;
	arg.set = set;
	arg.nr_pages = nr;

	for (i = 0; i < nr; i++)
		arg.wp_pages[i] = pages[i];

	rc = HYPERVISOR_hvm_op(HVMOP_wp_pages_to_ioreq_server, &arg);
	if (rc < 0) {
		printk(KERN_ERR "Cannot %s page to ioreq_server: %d!\n",
			set ? "set":"unset", rc);
		return rc;
	}

	return rc;
}

#endif

#ifdef CONFIG_XENGT
struct vm_struct *map_hvm_iopage(struct vgt_device *vgt)
{
	uint64_t ioreq_pfn;
	int rc;

	rc = hvm_create_iorequest_server(vgt);
	if (rc < 0)
		return NULL;
	rc = hvm_get_ioreq_pfn(vgt, &ioreq_pfn);
	if (rc < 0)
		return NULL; 

	return xen_remap_domain_mfn_range_in_kernel(ioreq_pfn, 1, vgt->vm_id);
}
#endif

int vgt_hvm_vmem_init(struct vgt_device *vgt)
{
	unsigned long i, j, gpfn, count;
	unsigned long nr_low_1mb_bkt, nr_high_bkt, nr_high_4k_bkt;

	if (!vgt_in_xen)
		return 0;

	/* Dom0 already has mapping for itself */
	ASSERT(vgt->vm_id != 0)

	ASSERT(vgt->vmem_vma == NULL && vgt->vmem_vma_low_1mb == NULL);

	vgt->vmem_sz = vgt_get_hvm_max_gpfn(vgt->vm_id) + 1;
	vgt->vmem_sz <<= PAGE_SHIFT;

	/* warn on non-1MB-aligned memory layout of HVM */
	if (vgt->vmem_sz & ~VMEM_BUCK_MASK)
		vgt_warn("VM%d: vmem_sz=0x%llx!\n", vgt->vm_id, vgt->vmem_sz);

	nr_low_1mb_bkt = VMEM_1MB >> PAGE_SHIFT;
	nr_high_bkt = (vgt->vmem_sz >> VMEM_BUCK_SHIFT);
	nr_high_4k_bkt = (vgt->vmem_sz >> PAGE_SHIFT);

	vgt->vmem_vma_low_1mb =
		kmalloc(sizeof(*vgt->vmem_vma) * nr_low_1mb_bkt, GFP_KERNEL);
	vgt->vmem_vma =
		kmalloc(sizeof(*vgt->vmem_vma) * nr_high_bkt, GFP_KERNEL);
	vgt->vmem_vma_4k =
		vzalloc(sizeof(*vgt->vmem_vma) * nr_high_4k_bkt);

	if (vgt->vmem_vma_low_1mb == NULL || vgt->vmem_vma == NULL ||
		vgt->vmem_vma_4k == NULL) {
		vgt_err("Insufficient memory for vmem_vma, vmem_sz=0x%llx\n",
				vgt->vmem_sz );
		goto err;
	}

	/* map the low 1MB memory */
	for (i = 0; i < nr_low_1mb_bkt; i++) {
		vgt->vmem_vma_low_1mb[i] =
			xen_remap_domain_mfn_range_in_kernel(i, 1, vgt->vm_id);

		if (vgt->vmem_vma[i] != NULL)
			continue;

		/* Don't warn on [0xa0000, 0x100000): a known non-RAM hole */
		if (i < (0xa0000 >> PAGE_SHIFT))
			vgt_dbg(VGT_DBG_GENERIC, "vGT: VM%d: can't map GPFN %ld!\n",
				vgt->vm_id, i);
	}

	printk("start vmem_map\n");
	count = 0;
	/* map the >1MB memory */
	for (i = 1; i < nr_high_bkt; i++) {
		gpfn = i << (VMEM_BUCK_SHIFT - PAGE_SHIFT);
		vgt->vmem_vma[i] = xen_remap_domain_mfn_range_in_kernel(
				gpfn,
				VMEM_BUCK_SIZE >> PAGE_SHIFT,
				vgt->vm_id);

		if (vgt->vmem_vma[i] != NULL)
			continue;


		/* for <4G GPFNs: skip the hole after low_mem_max_gpfn */
		if (gpfn < (1 << (32 - PAGE_SHIFT)) &&
			vgt->low_mem_max_gpfn != 0 &&
			gpfn > vgt->low_mem_max_gpfn)
			continue;

		for (j = gpfn;
		     j < ((i + 1) << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
		     j++) {
			vgt->vmem_vma_4k[j] =
				xen_remap_domain_mfn_range_in_kernel(
					j, 1, vgt->vm_id);

			if (vgt->vmem_vma_4k[j]) {
				count++;
				vgt_dbg(VGT_DBG_GENERIC, "map 4k gpa (%lx)\n", j << PAGE_SHIFT);
			}
		}

		/* To reduce the number of err messages(some of them, due to
		 * the MMIO hole, are spurious and harmless) we only print a
		 * message if it's at every 64MB boundary or >4GB memory.
		 */
		if ((i % 64 == 0) || (i >= (1ULL << (32 - VMEM_BUCK_SHIFT))))
			vgt_dbg(VGT_DBG_GENERIC, "vGT: VM%d: can't map %ldKB\n",
				vgt->vm_id, i);
	}
	printk("end vmem_map (%ld 4k mappings)\n", count);

	return 0;
err:
	kfree(vgt->vmem_vma);
	kfree(vgt->vmem_vma_low_1mb);
	vfree(vgt->vmem_vma_4k);
	vgt->vmem_vma = vgt->vmem_vma_low_1mb = vgt->vmem_vma_4k = NULL;
	return -ENOMEM;
}

void vgt_vmem_destroy(struct vgt_device *vgt)
{
	int i, j;
	unsigned long nr_low_1mb_bkt, nr_high_bkt, nr_high_bkt_4k;

	if (!vgt->vm_id || !vgt_in_xen)
		return;

	/*
	 * Maybe the VM hasn't accessed GEN MMIO(e.g., still in the legacy VGA
	 * mode), so no mapping is created yet.
	 */
	if (vgt->vmem_vma == NULL && vgt->vmem_vma_low_1mb == NULL)
		return;

	ASSERT(vgt->vmem_vma != NULL && vgt->vmem_vma_low_1mb != NULL);

	nr_low_1mb_bkt = VMEM_1MB >> PAGE_SHIFT;
	nr_high_bkt = (vgt->vmem_sz >> VMEM_BUCK_SHIFT);
	nr_high_bkt_4k = (vgt->vmem_sz >> PAGE_SHIFT);

	for (i = 0; i < nr_low_1mb_bkt; i++) {
		if (vgt->vmem_vma_low_1mb[i] == NULL)
			continue;
		xen_unmap_domain_mfn_range_in_kernel(
			vgt->vmem_vma_low_1mb[i], 1, vgt->vm_id);
	}

	for (i = 1; i < nr_high_bkt; i++) {
		if (vgt->vmem_vma[i] == NULL) {
			for (j = (i << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
			     j < ((i + 1) << (VMEM_BUCK_SHIFT - PAGE_SHIFT));
			     j++) {
				if (vgt->vmem_vma_4k[j] == NULL)
					continue;
				xen_unmap_domain_mfn_range_in_kernel(
					vgt->vmem_vma_4k[j], 1, vgt->vm_id);
			}
			continue;
		}
		xen_unmap_domain_mfn_range_in_kernel(
			vgt->vmem_vma[i], VMEM_BUCK_SIZE >> PAGE_SHIFT,
			vgt->vm_id);
	}

	kfree(vgt->vmem_vma);
	kfree(vgt->vmem_vma_low_1mb);
	vfree(vgt->vmem_vma_4k);
}

void* vgt_vmem_gpa_2_va(struct vgt_device *vgt, unsigned long gpa)
{
	unsigned long buck_index, buck_4k_index;

	/* for host */
	if (!vgt->vm_id)
		return (char*)vgt_mfn_to_virt(gpa>>PAGE_SHIFT) + (gpa & (PAGE_SIZE-1));

	/* kvm guest */
	if (!vgt_in_xen)
		return kvmgt_vmem_gpa_2_va(vgt, gpa);

	/*
	 * Xen guest:
	 * At the beginning of _hvm_mmio_emulation(), we already initialize
	 * vgt->vmem_vma and vgt->vmem_vma_low_1mb.
	 */
	ASSERT(vgt->vmem_vma != NULL && vgt->vmem_vma_low_1mb != NULL);

	/* handle the low 1MB memory */
	if (gpa < VMEM_1MB) {
		buck_index = gpa >> PAGE_SHIFT;
		if (!vgt->vmem_vma_low_1mb[buck_index])
			return NULL;

		return (char*)(vgt->vmem_vma_low_1mb[buck_index]->addr) +
			(gpa & ~PAGE_MASK);

	}

	/* handle the >1MB memory */
	buck_index = gpa >> VMEM_BUCK_SHIFT;

	if (!vgt->vmem_vma[buck_index]) {
		buck_4k_index = gpa >> PAGE_SHIFT;
		if (!vgt->vmem_vma_4k[buck_4k_index]) {
			if (buck_4k_index > vgt->low_mem_max_gpfn)
				vgt_err("vGT failed to map gpa=0x%lx?\n", gpa);
			return NULL;
		}

		return (char*)(vgt->vmem_vma_4k[buck_4k_index]->addr) +
			(gpa & ~PAGE_MASK);
	}

	return (char*)(vgt->vmem_vma[buck_index]->addr) +
		(gpa & (VMEM_BUCK_SIZE -1));
}

