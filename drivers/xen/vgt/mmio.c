/*
 * MMIO virtualization framework
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/acpi.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#ifdef CONFIG_XEN
#include <xen/events.h>
#include <xen/xen-ops.h>
#endif

#include "vgt.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

DEFINE_HASHTABLE(vgt_mmio_table, VGT_HASH_BITS);

void vgt_add_mmio_entry(struct vgt_mmio_entry *e)
{
	hash_add(vgt_mmio_table, &e->hlist, e->base);
}

struct vgt_mmio_entry * vgt_find_mmio_entry(unsigned int base)
{
	struct vgt_mmio_entry *e;

	hash_for_each_possible(vgt_mmio_table, e, hlist, base) {
		if (base == e->base)
			return e;
	}
	return NULL;
}

void vgt_del_mmio_entry(unsigned int base)
{
	struct vgt_mmio_entry *e;

	if ((e = vgt_find_mmio_entry(base))) {
		hash_del(&e->hlist);
		kfree(e);
	}
}

void vgt_clear_mmio_table(void)
{
	int i;
	struct hlist_node *tmp;
	struct vgt_mmio_entry *e;

	hash_for_each_safe(vgt_mmio_table, i, tmp, e, hlist)
		kfree(e);

	hash_init(vgt_mmio_table);
}

void vgt_add_wp_page_entry(struct vgt_device *vgt, struct vgt_wp_page_entry *e)
{
	hash_add((vgt->wp_table), &e->hlist, e->pfn);
}

struct vgt_wp_page_entry * vgt_find_wp_page_entry(struct vgt_device *vgt, unsigned int pfn)
{
	struct vgt_wp_page_entry *e;

	hash_for_each_possible((vgt->wp_table), e, hlist, pfn) {
		if (pfn == e->pfn)
			return e;
	}
	return NULL;
}

void vgt_del_wp_page_entry(struct vgt_device *vgt, unsigned int pfn)
{
	struct vgt_wp_page_entry *e;

	if ((e = vgt_find_wp_page_entry(vgt, pfn))) {
		hash_del(&e->hlist);
		kfree(e);
	}
}

void vgt_clear_wp_table(struct vgt_device *vgt)
{
	int i;
	struct hlist_node *tmp;
	struct vgt_wp_page_entry *e;

	hash_for_each_safe((vgt->wp_table), i, tmp, e, hlist)
		kfree(e);

	hash_init((vgt->wp_table));
}

/* Default MMIO handler registration
 * These MMIO are registered as at least 4-byte aligned
 */
bool vgt_register_mmio_handler(unsigned int start, int bytes,
	vgt_mmio_read read, vgt_mmio_write write)
{
	int i, j, end;
	struct vgt_mmio_entry *mht;

	end = start + bytes -1;

	vgt_dbg(VGT_DBG_GENERIC, "start=0x%x end=0x%x\n", start, end);

	ASSERT((start & 3) == 0);
	ASSERT(((end+1) & 3) == 0);

	for ( i = start; i < end; i += 4 ) {
		mht = kmalloc(sizeof(*mht), GFP_KERNEL);
		if (mht == NULL) {
			printk("Insufficient memory in %s\n", __FUNCTION__);
			for (j = start; j < i; j += 4) {
				vgt_del_mmio_entry (j);
			}
			BUG();
		}
		mht->base = i;

		/*
		 * Win7 GFX driver uses memcpy to access the vgt PVINFO regs,
		 * hence align_bytes can be 1.
		 */
		if (start >= VGT_PVINFO_PAGE &&
			start < VGT_PVINFO_PAGE + VGT_PVINFO_SIZE)
			mht->align_bytes = 1;
		else
			mht->align_bytes = 4;

		mht->read = read;
		mht->write = write;
		INIT_HLIST_NODE(&mht->hlist);
		vgt_add_mmio_entry(mht);
	}
	return true;
}

static inline unsigned long vgt_get_passthrough_reg(struct vgt_device *vgt,
		unsigned int reg)
{
	__sreg(vgt, reg) = VGT_MMIO_READ(vgt->pdev, reg);
	__vreg(vgt, reg) = mmio_h2g_gmadr(vgt, reg, __sreg(vgt, reg));
	return __vreg(vgt, reg);
}

static unsigned long vgt_get_reg(struct vgt_device *vgt, unsigned int reg)
{
	/* check whether to update vreg from HW */
//	if (reg_hw_status(pdev, reg) &&
	if (reg_hw_access(vgt, reg))
		return vgt_get_passthrough_reg(vgt, reg);
	else
		return __vreg(vgt, reg);
}

static inline unsigned long vgt_get_passthrough_reg_64(struct vgt_device *vgt, unsigned int reg)
{
	__sreg64(vgt, reg) = VGT_MMIO_READ_BYTES(vgt->pdev, reg, 8);
	__vreg(vgt, reg) = mmio_h2g_gmadr(vgt, reg, __sreg(vgt, reg));
	__vreg(vgt, reg + 4) = mmio_h2g_gmadr(vgt, reg + 4, __sreg(vgt, reg + 4));
	return __vreg64(vgt, reg);
}
/*
 * for 64bit reg access, we split into two 32bit accesses since each part may
 * require address fix
 *
 * TODO: any side effect with the split? or instead install specific handler
 * for 64bit regs like fence?
 */
static unsigned long vgt_get_reg_64(struct vgt_device *vgt, unsigned int reg)
{
	/* check whether to update vreg from HW */
//	if (reg_hw_status(pdev, reg) &&
	if (reg_hw_access(vgt, reg))
		return vgt_get_passthrough_reg_64(vgt, reg);
	else
		return __vreg64(vgt, reg);
}

static void vgt_update_reg(struct vgt_device *vgt, unsigned int reg)
{
	struct pgt_device *pdev = vgt->pdev;
	/*
	 * update sreg if pass through;
	 * update preg if boot_time or vgt is reg's cur owner
	 */
	__sreg(vgt, reg) = mmio_g2h_gmadr(vgt, reg, __vreg(vgt, reg));
	if (reg_hw_access(vgt, reg))
		VGT_MMIO_WRITE(pdev, reg, __sreg(vgt, reg));
}

static void vgt_update_reg_64(struct vgt_device *vgt, unsigned int reg)
{
	struct pgt_device *pdev = vgt->pdev;
	/*
	 * update sreg if pass through;
	 * update preg if boot_time or vgt is reg's cur owner
	 */
	__sreg(vgt, reg) = mmio_g2h_gmadr(vgt, reg, __vreg(vgt, reg));
	__sreg(vgt, reg + 4) = mmio_g2h_gmadr(vgt, reg + 4, __vreg(vgt, reg + 4));
	if (reg_hw_access(vgt, reg))
			VGT_MMIO_WRITE_BYTES(pdev, reg, __sreg64(vgt, reg), 8);
}

bool default_mmio_read(struct vgt_device *vgt, unsigned int offset,
	void *p_data, unsigned int bytes)
{
	unsigned int reg;
	unsigned long wvalue;
	reg = offset & ~(bytes - 1);

	if (bytes <= 4) {
		wvalue = vgt_get_reg(vgt, reg);
	} else {
		wvalue = vgt_get_reg_64(vgt, reg);
	}

	memcpy(p_data, &wvalue + (offset & (bytes - 1)), bytes);

	return true;
}

bool default_mmio_write(struct vgt_device *vgt, unsigned int offset,
	void *p_data, unsigned int bytes)
{
	memcpy((char *)vgt->state.vReg + offset,
			p_data, bytes);

	offset &= ~(bytes - 1);
	if (bytes <= 4)
		vgt_update_reg(vgt, offset);
	else
		vgt_update_reg_64(vgt, offset);

	return true;
}

bool default_passthrough_mmio_read(struct vgt_device *vgt, unsigned int offset,
	void *p_data, unsigned int bytes)
{
	unsigned int reg;
	unsigned long wvalue;
	reg = offset & ~(bytes - 1);

	if (bytes <= 4) {
		wvalue = vgt_get_passthrough_reg(vgt, reg);
	} else {
		wvalue = vgt_get_passthrough_reg_64(vgt, reg);
	}

	memcpy(p_data, &wvalue + (offset & (bytes - 1)), bytes);

	return true;
}

#define PCI_BAR_ADDR_MASK (~0xFUL)  /* 4 LSB bits are not address */

static inline unsigned int vgt_pa_to_mmio_offset(struct vgt_device *vgt,
	uint64_t pa)
{
	return (vgt->vm_id == 0)?
		pa - vgt->pdev->gttmmio_base :
		pa - ( (*(uint64_t*)(vgt->state.cfg_space + VGT_REG_CFG_SPACE_BAR0))
				& PCI_BAR_ADDR_MASK );
}

static inline bool valid_mmio_alignment(struct vgt_mmio_entry *mht,
		unsigned int offset, int bytes)
{
	if ((bytes >= mht->align_bytes) && !(offset & (bytes - 1)))
		return true;
	vgt_err("Invalid MMIO offset(%08x), bytes(%d)\n",offset, bytes);
	return false;
}

/*
 * Emulate the VGT MMIO register read ops.
 * Return : true/false
 * */
bool vgt_emulate_read(struct vgt_device *vgt, uint64_t pa, void *p_data,int bytes)
{
	struct vgt_mmio_entry *mht;
	struct pgt_device *pdev = vgt->pdev;
	unsigned int offset;
	unsigned long flags;
	bool rc;
	cycles_t t0, t1;
	struct vgt_statistics *stat = &vgt->stat;
	int cpu;

	t0 = get_cycles();

	/* PPGTT PTE RP comes here too. */
	if (pdev->enable_ppgtt && vgt->vm_id != 0 && vgt->ppgtt_initialized) {
		struct vgt_wp_page_entry *wp;
		wp = vgt_find_wp_page_entry(vgt, pa >> PAGE_SHIFT);
		if (wp) {
			/* XXX lock? */
			vgt_ppgtt_handle_pte_rp(vgt, wp, pa, p_data, bytes);
			return true;
		}
	}

	offset = vgt_pa_to_mmio_offset(vgt, pa);

	/* FENCE registers / GTT entries(sometimes) are accessed in 8 bytes. */
	if (bytes > 8 || (offset & (bytes - 1)))
		goto err_common_chk;

	if (bytes > 4)
		vgt_dbg(VGT_DBG_GENERIC,"vGT: capture >4 bytes read to %x\n", offset);

	vgt_lock_dev_flags(pdev, cpu, flags);

	raise_ctx_sched(vgt);

	if (reg_is_gtt(pdev, offset)) {
		rc = gtt_mmio_read(vgt, offset, p_data, bytes);
		if (!rc)
			vgt_err("gtt_mmio_read failed\n");
		vgt_unlock_dev_flags(pdev, cpu, flags);
		return rc;
	}

	if (!reg_is_mmio(pdev, offset + bytes))
		goto err_mmio;

	mht = vgt_find_mmio_entry(offset);
	if ( mht && mht->read ) {
		if (!valid_mmio_alignment(mht, offset, bytes)) {
			vgt_err("hi\n");
			goto err_mmio;
		}
		if (!mht->read(vgt, offset, p_data, bytes)) {
			vgt_err("hi\n");
			goto err_mmio;
		}
	} else {
		if (!default_mmio_read(vgt, offset, p_data, bytes)) {
			vgt_err("hi\n");
			goto err_mmio;
		}
	}

	if (!reg_is_tracked(pdev, offset) && vgt->warn_untrack) {
		vgt_warn("vGT: untracked MMIO read: vm_id(%d), offset=0x%x,"
			"len=%d, val=0x%x!!!\n",
			vgt->vm_id, offset, bytes, *(u32 *)p_data);

		if (offset == 0x206c) {
			printk("------------------------------------------\n");
			printk("VM(%d) likely triggers a gfx reset\n", vgt->vm_id);
			printk("Disable untracked MMIO warning for VM(%d)\n", vgt->vm_id);
			printk("------------------------------------------\n");
			vgt->warn_untrack = 0;
			show_debug(pdev);
		}

		//WARN_ON(vgt->vm_id == 0); /* The call stack is meaningless for HVM */
	}

	reg_set_accessed(pdev, offset);

	vgt_unlock_dev_flags(pdev, cpu, flags);
	trace_vgt_mmio_rw(VGT_TRACE_READ, vgt->vm_id, offset, p_data, bytes);

	t1 = get_cycles();
	stat->mmio_rcnt++;
	stat->mmio_rcycles += t1 - t0;
	return true;
err_mmio:
	vgt_unlock_dev_flags(pdev, cpu, flags);
err_common_chk:
	vgt_err("VM(%d): invalid MMIO offset(%08x), bytes(%d)!\n",
		vgt->vm_id, offset, bytes);
	show_debug(pdev);
	return false;
}

/*
 * Emulate the VGT MMIO register write ops.
 * Return : true/false
 * */
bool vgt_emulate_write(struct vgt_device *vgt, uint64_t pa,
	void *p_data, int bytes)
{
	struct pgt_device *pdev = vgt->pdev;
	struct vgt_mmio_entry *mht;
	unsigned int offset;
	unsigned long flags;
	int cpu;
	vgt_reg_t old_vreg=0, old_sreg=0;
	bool rc;
	cycles_t t0, t1;
	struct vgt_statistics *stat = &vgt->stat;

	t0 = get_cycles();

	/* PPGTT PTE WP comes here too. */
	if (pdev->enable_ppgtt && vgt->vm_id != 0 && vgt->ppgtt_initialized) {
		struct vgt_wp_page_entry *wp;
		wp = vgt_find_wp_page_entry(vgt, pa >> PAGE_SHIFT);
		if (wp) {
			/* XXX lock? */
			vgt_ppgtt_handle_pte_wp(vgt, wp, pa, p_data, bytes);
			return true;
		}
	}

	offset = vgt_pa_to_mmio_offset(vgt, pa);

	/* FENCE registers / GTT entries(sometimes) are accessed in 8 bytes. */
	if (bytes > 8 || (offset & (bytes - 1)))
		goto err_common_chk;

	if (bytes > 4)
		vgt_dbg(VGT_DBG_GENERIC,"vGT: capture >4 bytes write to %x with val (%lx)\n", offset, *(unsigned long*)p_data);
/*
	if (reg_rdonly(pdev, offset & (~(bytes - 1)))) {
		printk("vGT: captured write to read-only reg (%x)\n", offset);
		return true;
	}
*/

	vgt_lock_dev_flags(pdev, cpu, flags);

	raise_ctx_sched(vgt);

	if (reg_is_gtt(pdev, offset)) {
		rc = gtt_mmio_write(vgt, offset, p_data, bytes);
		if (!rc)
			vgt_err("gtt_mmio_write failed\n");
		vgt_unlock_dev_flags(pdev, cpu, flags);
		return rc;
	}

	if (!reg_is_mmio(pdev, offset + bytes))
		goto err_mmio;

	if (reg_mode_ctl(pdev, offset)) {
		old_vreg = __vreg(vgt, offset);
		old_sreg = __sreg(vgt, offset);
	}

	if (!reg_is_tracked(pdev, offset) && vgt->warn_untrack) {
		vgt_warn("vGT: untracked MMIO write: vm_id(%d), offset=0x%x,"
			"len=%d, val=0x%x!!!\n",
			vgt->vm_id, offset, bytes, *(u32 *)p_data);

		//WARN_ON(vgt->vm_id == 0); /* The call stack is meaningless for HVM */
	}

	mht = vgt_find_mmio_entry(offset);
	if ( mht && mht->write ) {
		if (!valid_mmio_alignment(mht, offset, bytes))
			goto err_mmio;
		if (!mht->write(vgt, offset, p_data, bytes))
			goto err_mmio;
	} else
		if (!default_mmio_write(vgt, offset, p_data, bytes))
			goto err_mmio;

	/* higher 16bits of mode ctl regs are mask bits for change */
	if (reg_mode_ctl(pdev, offset)) {
		u32 mask = __vreg(vgt, offset) >> 16;

		vgt_dbg(VGT_DBG_GENERIC,"old mode (%x): %x/%x, mask(%x)\n", offset,
			__vreg(vgt, offset), __sreg(vgt, offset),
			reg_aux_mode_mask(pdev, offset));
		/*
		 * share the global mask among VMs, since having one VM touch a bit
		 * not changed by another VM should be still saved/restored later
		 */
		reg_aux_mode_mask(pdev, offset) |= mask << 16;
		__vreg(vgt, offset) = (old_vreg & ~mask) | (__vreg(vgt, offset) & mask);
		__sreg(vgt, offset) = (old_sreg & ~mask) | (__sreg(vgt, offset) & mask);
		vgt_dbg(VGT_DBG_GENERIC,"new mode (%x): %x/%x, mask(%x)\n", offset,
			__vreg(vgt, offset), __sreg(vgt, offset),
			reg_aux_mode_mask(pdev, offset));
		//show_mode_settings(vgt->pdev);
	}

	if (offset == _REG_RCS_UHPTR)
		vgt_dbg(VGT_DBG_GENERIC,"vGT: write to UHPTR (%x,%x)\n", __vreg(vgt, offset), __sreg(vgt, offset));

	reg_set_accessed(pdev, offset);
	vgt_unlock_dev_flags(pdev, cpu, flags);
	trace_vgt_mmio_rw(VGT_TRACE_WRITE, vgt->vm_id, offset, p_data, bytes);

	t1 = get_cycles();
	stat->mmio_wcycles += t1 - t0;
	stat->mmio_wcnt++;
	return true;
err_mmio:
	vgt_unlock_dev_flags(pdev, cpu, flags);
err_common_chk:
	vgt_err("VM(%d): invalid MMIO offset(%08x),"
		"bytes(%d)!\n", vgt->vm_id, offset, bytes);
	show_debug(pdev);
	return false;
}

#ifdef CONFIG_XENGT
static int vgt_hvm_do_ioreq(struct vgt_device *vgt, struct ioreq *ioreq);
static void vgt_crash_domain(struct vgt_device *vgt)
{
	vgt_pause_domain(vgt);
	vgt_shutdown_domain(vgt);
}
#endif

#ifdef CONFIG_XENGT
static int vgt_emulation_thread(void *priv)
{
	struct vgt_device *vgt = (struct vgt_device *)priv;
	struct vgt_hvm_info *info = vgt->hvm_info;

	int vcpu;
	int nr_vcpus = info->nr_vcpu;

	struct ioreq *ioreq;
	int irq, ret;

	vgt_info("start kthread for VM%d\n", vgt->vm_id);

	ASSERT(info->nr_vcpu <= MAX_HVM_VCPUS_SUPPORTED);

	set_freezable();
	while (1) {
		ret = wait_event_freezable(info->io_event_wq,
			kthread_should_stop() ||
			bitmap_weight(info->ioreq_pending, nr_vcpus));
		if (ret)
			vgt_warn("Emulation thread(%d) waken up"
				 "by unexpected signal!\n", vgt->vm_id);

		if (kthread_should_stop())
			return 0;

		for (vcpu = 0; vcpu < nr_vcpus; vcpu++) {
			if (!test_and_clear_bit(vcpu, info->ioreq_pending))
				continue;

			ioreq = vgt_get_hvm_ioreq(vgt, vcpu);

			ret = vgt_hvm_do_ioreq(vgt, ioreq);
			if (unlikely(ret))
				vgt_crash_domain(vgt);

			ioreq->state = STATE_IORESP_READY;

			irq = info->evtchn_irq[vcpu];
			notify_remote_via_irq(irq);
		}
	}

	BUG(); /* It's actually impossible to reach here */
	return 0;
}

int _hvm_mmio_emulation(struct vgt_device *vgt, struct ioreq *req)
{
	int i, sign;
	void *gva;
	unsigned long gpa;
	char *cfg_space = &vgt->state.cfg_space[0];
	uint64_t base = * (uint64_t *) (cfg_space + VGT_REG_CFG_SPACE_BAR0);
	uint64_t tmp;
	int pvinfo_page;

	if (vgt->vmem_vma == NULL) {
		tmp = vgt_pa_to_mmio_offset(vgt, req->addr);
		pvinfo_page = (tmp >= VGT_PVINFO_PAGE
				&& tmp < (VGT_PVINFO_PAGE + VGT_PVINFO_SIZE));
		/*
		 * hvmloader will read PVINFO to identify if HVM is in VGT
		 * or VTD. So we don't trigger HVM mapping logic here.
		 */
		if (!pvinfo_page && vgt_hvm_vmem_init(vgt) < 0) {
			vgt_err("can not map the memory of VM%d!!!\n", vgt->vm_id);
			ASSERT_VM(vgt->vmem_vma != NULL, vgt);
			return -EINVAL;
		}
	}

	sign = req->df ? -1 : 1;

	if (req->dir == IOREQ_READ) {
		/* MMIO READ */
		if (!req->data_is_ptr) {
			if (req->count != 1)
				goto err_ioreq_count;

			//vgt_dbg(VGT_DBG_GENERIC,"HVM_MMIO_read: target register (%lx).\n",
			//	(unsigned long)req->addr);
			if (!vgt_emulate_read(vgt, req->addr, &req->data, req->size))
				return -EINVAL;
		}
		else {
			if ((req->addr + sign * req->count * req->size < base)
			   || (req->addr + sign * req->count * req->size >=
				base + vgt->state.bar_size[0]))
				goto err_ioreq_range;
			//vgt_dbg(VGT_DBG_GENERIC,"HVM_MMIO_read: rep %d target memory %lx, slow!\n",
			//	req->count, (unsigned long)req->addr);

			for (i = 0; i < req->count; i++) {
				if (!vgt_emulate_read(vgt, req->addr + sign * i * req->size,
					&tmp, req->size))
					return -EINVAL;
				gpa = req->data + sign * i * req->size;
				gva = vgt_vmem_gpa_2_va(vgt, gpa);
				// On the SNB laptop, writing tmp to gva can
				//cause bug 119. So let's do the writing only on HSW for now.
				if (gva != NULL && IS_HSW(vgt->pdev))
					memcpy(gva, &tmp, req->size);
				else
					vgt_dbg(VGT_DBG_GENERIC,"vGT: can not write gpa = 0x%lx!!!\n", gpa);
			}
		}
	}
	else { /* MMIO Write */
		if (!req->data_is_ptr) {
			if (req->count != 1)
				goto err_ioreq_count;
			//vgt_dbg(VGT_DBG_GENERIC,"HVM_MMIO_write: target register (%lx).\n", (unsigned long)req->addr);
			if (!vgt_emulate_write(vgt, req->addr, &req->data, req->size))
				return -EINVAL;
		}
		else {
			if ((req->addr + sign * req->count * req->size < base)
			    || (req->addr + sign * req->count * req->size >=
				base + vgt->state.bar_size[0]))
				goto err_ioreq_range;
			//vgt_dbg(VGT_DBG_GENERIC,"HVM_MMIO_write: rep %d target memory %lx, slow!\n",
			//	req->count, (unsigned long)req->addr);

			for (i = 0; i < req->count; i++) {
				gpa = req->data + sign * i * req->size;
				gva = vgt_vmem_gpa_2_va(vgt, gpa);
				if (gva != NULL)
					memcpy(&tmp, gva, req->size);
				else {
					tmp = 0;
					vgt_dbg(VGT_DBG_GENERIC, "vGT: can not read gpa = 0x%lx!!!\n", gpa);
				}
				if (!vgt_emulate_write(vgt, req->addr + sign * i * req->size, &tmp, req->size))
					return -EINVAL;
			}
		}
	}
	return 0;

err_ioreq_count:
	vgt_err("VM(%d): Unexpected %s request count(%d)\n",
		vgt->vm_id, req->dir == IOREQ_READ ? "read" : "write",
		req->count);
	return -EINVAL;

err_ioreq_range:
	vgt_err("VM(%d): Invalid %s request addr end(%016llx)\n",
		vgt->vm_id, req->dir == IOREQ_READ ? "read" : "write",
		req->addr + sign * req->count * req->size);
	return -ERANGE;
}

int _hvm_pio_emulation(struct vgt_device *vgt, struct ioreq *ioreq)
{
	int sign;
	//char *pdata;

	sign = ioreq->df ? -1 : 1;

	if (ioreq->dir == IOREQ_READ) {
		/* PIO READ */
		if (!ioreq->data_is_ptr) {
			if(!vgt_hvm_read_cf8_cfc_new(vgt,
				ioreq->addr,
				ioreq->size,
				(unsigned long*) &ioreq->data))
				return -EINVAL;
		}
		else {
			vgt_dbg(VGT_DBG_GENERIC,"VGT: _hvm_pio_emulation read data_ptr %lx\n",
			(long)ioreq->data);
			goto err_data_ptr;
#if 0
			pdata = (char *)ioreq->data;
			for (i=0; i < ioreq->count; i++) {
				vgt_hvm_read_cf8_cfc(vgt,
					ioreq->addr,
					ioreq->size,
					(unsigned long *)pdata);
				pdata += ioreq->size * sign;
			}
#endif
		}
	}
	else {
		/* PIO WRITE */
		if (!ioreq->data_is_ptr) {
			if (!vgt_hvm_write_cf8_cfc_new(vgt,
				ioreq->addr,
				ioreq->size,
				(unsigned long) ioreq->data))
				return -EINVAL;
		}
		else {
			vgt_dbg(VGT_DBG_GENERIC,"VGT: _hvm_pio_emulation write data_ptr %lx\n",
			(long)ioreq->data);
			goto err_data_ptr;
#if 0
			pdata = (char *)ioreq->data;

			for (i=0; i < ioreq->count; i++) {
				vgt_hvm_write_cf8_cfc(vgt,
					ioreq->addr,
					ioreq->size, *(unsigned long *)pdata);
				pdata += ioreq->size * sign;
			}
#endif
		}
	}
	return 0;
err_data_ptr:
	/* The data pointer of emulation is guest physical address
	 * so far, which goes to Qemu emulation, but hard for
	 * vGT driver which doesn't know gpn_2_mfn translation.
	 * We may ask hypervisor to use mfn for vGT driver.
	 * We mark it as unsupported in case guest really it.
	 */
	vgt_err("VM(%d): Unsupported %s data_ptr(%lx)\n",
		vgt->vm_id, ioreq->dir == IOREQ_READ ? "read" : "write",
		(long)ioreq->data);
	return -EINVAL;
}

static int vgt_hvm_do_ioreq(struct vgt_device *vgt, struct ioreq *ioreq)
{
	struct pgt_device *pdev = vgt->pdev;
	uint64_t bdf = PCI_BDF2(pdev->pbus->number, pdev->devfn);

	/* When using ioreq-server, sometimes an event channal
	 * notification is received with invalid ioreq. Don't
	 * know the root cause. Put the workaround here.
	 */
	if (ioreq->state == STATE_IOREQ_NONE)
		return 0;

	if (ioreq->type == IOREQ_TYPE_INVALIDATE)
		return 0;

	switch (ioreq->type) {
		case IOREQ_TYPE_PCI_CONFIG:
			/* High 32 bit of ioreq->addr is bdf */
			if ((ioreq->addr >> 32) != bdf) {
				printk(KERN_ERR "vGT: Unexpected PCI Dev %lx emulation\n",
					(unsigned long) (ioreq->addr>>32));
				return -EINVAL;
			} else
				return _hvm_pio_emulation(vgt, ioreq);
			break;
		case IOREQ_TYPE_COPY:	/* MMIO */
			return _hvm_mmio_emulation(vgt, ioreq);
			break;
		default:
			printk(KERN_ERR "vGT: Unknown ioreq type %x addr %llx size %u state %u\n",
				ioreq->type, ioreq->addr, ioreq->size, ioreq->state);
			return -EINVAL;
	}
	return 0;
}

static inline void vgt_raise_emulation_request(struct vgt_device *vgt,
	int vcpu)
{
	struct vgt_hvm_info *info = vgt->hvm_info;
	set_bit(vcpu, info->ioreq_pending);
	if (waitqueue_active(&info->io_event_wq))
		wake_up(&info->io_event_wq);
}

static irqreturn_t vgt_hvm_io_req_handler(int irq, void* dev)
{
	struct vgt_device *vgt;
	struct vgt_hvm_info *info;
	int vcpu;

	vgt = (struct vgt_device *)dev;
	info = vgt->hvm_info;

	for(vcpu=0; vcpu < info->nr_vcpu; vcpu++){
		if(info->evtchn_irq[vcpu] == irq)
			break;
	}
	if (vcpu == info->nr_vcpu){
		/*opps, irq is not the registered one*/
		vgt_info("Received a IOREQ w/o vcpu target\n");
		vgt_info("Possible a false request from event binding\n");
		return IRQ_NONE;
	}

	vgt_raise_emulation_request(vgt, vcpu);

	return IRQ_HANDLED;
}
#endif

static bool vgt_hvm_opregion_resinit(struct vgt_device *vgt, uint32_t gpa)
{
	void *orig_va = vgt->pdev->opregion_va;
	uint8_t	*buf;
	int i;
	int rc;

	if (vgt->state.opregion_va) {
		vgt_err("VM%d tried to init opregion multiple times!\n",
				vgt->vm_id);
		return false;
	}
	if (orig_va == NULL) {
		vgt_err("VM%d: No mapped OpRegion available\n", vgt->vm_id);
		return false;
	}

	if (vgt_in_xen) {
		vgt->state.opregion_va = (void *)__get_free_pages(GFP_ATOMIC |
				GFP_DMA32 | __GFP_ZERO,
				VGT_OPREGION_PORDER);
		if (vgt->state.opregion_va == NULL) {
			vgt_err("VM%d: failed to allocate memory for opregion\n",
					vgt->vm_id);
			return false;
		}

		for (i = 0; i < VGT_OPREGION_PAGES; i++)
			vgt->state.opregion_gfn[i] = (gpa >> PAGE_SHIFT) + i;

		memcpy_fromio(vgt->state.opregion_va, orig_va, VGT_OPREGION_SIZE);
	} else {
		struct kvm *kvm = kvm_find_by_domid(vgt->vm_id);
		if (kvm == NULL) {
			vgt_err("Failed to find kvm with domid == %d\n", vgt->vm_id);
			return false;
		}

		rc = kvmgt_add_opreg_slot(vgt, VGT_OPREGION_PAGES);
		if (!rc) {
			vgt_err("VM%d: kvmgt_add_opreg_slot failed\n", vgt->vm_id);
			return false;
		}

		down_read(&kvm->mm->mmap_sem);
		rc = get_user_pages(NULL, kvm->mm, kvm->opregion_hva, VGT_OPREGION_PAGES, 1,
				1, vgt->state.opregion_pages, NULL);
		up_read(&kvm->mm->mmap_sem);
		if (rc != VGT_OPREGION_PAGES) {
			vgt_err("get_user_pages failed, rc is %d\n", rc);
			return false;
		}

		vgt->state.opregion_va = vmap(vgt->state.opregion_pages, VGT_OPREGION_PAGES, 0, PAGE_KERNEL);
		if (vgt->state.opregion_va == NULL) {
			vgt_err("VM%d: failed to allocate memory for opregion\n",
					vgt->vm_id);
			goto kvm_fail;
		}
		/* adjust the offset */
		vgt->state.opregion_va += offset_in_page(kvm->opregion_gpa);

		memcpy_fromio(vgt->state.opregion_va, orig_va, VGT_OPREGION_SIZE -
					offset_in_page(kvm->opregion_gpa));
	}

	/* for unknown reason, the value in LID field is incorrect
	 * which block the windows guest, so workaround it by force
	 * setting it to "OPEN"
	 */
	buf = (uint8_t *)vgt->state.opregion_va;
	buf[VGT_OPREGION_REG_CLID] = 0x3;

	return true;
kvm_fail:
	for (i = 0; i < VGT_OPREGION_PAGES; i++)
		put_page(vgt->state.opregion_pages[i]);
	return false;
}

int vgt_hvm_opregion_init(struct vgt_device *vgt, uint32_t gpa)
{
	int ret;

	if (vgt_hvm_opregion_resinit(vgt, gpa)) {

		/* modify the vbios parameters for PORTs,
		 * Let guest see full port capability.
		 */
		if (!propagate_monitor_to_guest && !is_current_display_owner(vgt)) {
			vgt_prepare_vbios_general_definition(vgt);
		}

		ret = vgt_hvm_opregion_map(vgt, 1);
		memcpy(&vgt->state.cfg_space[VGT_REG_CFG_OPREGION], &gpa, sizeof(gpa));
		return ret;
	}

	return false;
}

void vgt_initial_opregion_setup(struct pgt_device *pdev)
{
	pci_read_config_dword(pdev->pdev, VGT_REG_CFG_OPREGION,
			&pdev->opregion_pa);
	pdev->opregion_va = acpi_os_ioremap(pdev->opregion_pa,
			VGT_OPREGION_SIZE);
	if (pdev->opregion_va == NULL)
		vgt_err("Directly map OpRegion failed\n");
}

int vgt_hvm_info_init(struct vgt_device *vgt)
{
	struct vgt_hvm_info *info;
	int vcpu, irq, rc = 0;
	struct task_struct *thread;
	struct pgt_device *pdev = vgt->pdev;

	if (!vgt_in_xen)
		return 0;

	info = kzalloc(sizeof(struct vgt_hvm_info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;

	vgt->hvm_info = info;

	info->iopage_vma = map_hvm_iopage(vgt);
	if (info->iopage_vma == NULL) {
		printk(KERN_ERR "Failed to map HVM I/O page for VM%d\n", vgt->vm_id);
		rc = -EFAULT;
		goto err;
	}
	info->iopage = info->iopage_vma->addr;

	init_waitqueue_head(&info->io_event_wq);

	info->nr_vcpu = xen_get_nr_vcpu(vgt->vm_id);
	ASSERT(info->nr_vcpu > 0);
	ASSERT(info->nr_vcpu <= MAX_HVM_VCPUS_SUPPORTED);

	info->evtchn_irq = kmalloc(info->nr_vcpu * sizeof(int), GFP_KERNEL);
	if (info->evtchn_irq == NULL){
		rc = -ENOMEM;
		goto err;
	}
	for( vcpu = 0; vcpu < info->nr_vcpu; vcpu++ )
		info->evtchn_irq[vcpu] = -1;

	rc = hvm_map_pcidev_to_ioreq_server(vgt, PCI_BDF2(pdev->pbus->number, pdev->devfn));
	if (rc < 0)
		goto err;
	rc = hvm_enable_iorequest_server(vgt, 1);
	if (rc < 0)
		goto err;
	for( vcpu = 0; vcpu < info->nr_vcpu; vcpu++ ){
		irq = bind_interdomain_evtchn_to_irqhandler( vgt->vm_id,
				info->iopage->vcpu_ioreq[vcpu].vp_eport,
				vgt_hvm_io_req_handler, 0,
				"vgt", vgt );
		if ( irq < 0 ){
			rc = irq;
			printk(KERN_ERR "Failed to bind event channle for vgt HVM IO handler, rc=%d\n", rc);
			goto err;
		}
		info->evtchn_irq[vcpu] = irq;
	}

	thread = kthread_run(vgt_emulation_thread, vgt,
			"vgt_emulation:%d", vgt->vm_id);
	if(IS_ERR(thread))
		goto err;
	info->emulation_thread = thread;

	return 0;

err:
	vgt_hvm_info_deinit(vgt);
	return rc;
}

void vgt_hvm_info_deinit(struct vgt_device *vgt)
{
	struct vgt_hvm_info *info;
	int vcpu;

	if (!vgt_in_xen)
		return;

	if (vgt->iosrv_id != 0)
		hvm_destroy_iorequest_server(vgt);

	info = vgt->hvm_info;

	if (info == NULL)
		return;

	if (info->emulation_thread != NULL)
		kthread_stop(info->emulation_thread);

	if (vgt->state.opregion_va) {
		vgt_hvm_opregion_map(vgt, 0);
		if (vgt_in_xen)
			free_pages((unsigned long)vgt->state.opregion_va,
					VGT_OPREGION_PORDER);
	}

	if (!info->nr_vcpu || info->evtchn_irq == NULL)
		goto out1;

	for (vcpu=0; vcpu < info->nr_vcpu; vcpu++){
		if( info->evtchn_irq[vcpu] >= 0)
			unbind_from_irqhandler(info->evtchn_irq[vcpu], vgt);
	}

	if (info->iopage_vma != NULL)
		xen_unmap_domain_mfn_range_in_kernel(info->iopage_vma, 1, vgt->vm_id);

	kfree(info->evtchn_irq);

out1:
	kfree(info);

	return;
}

static void vgt_set_reg_attr(struct pgt_device *pdev,
	u32 reg, reg_attr_t *attr, bool track)
{
	/* ensure one entry per reg */
	ASSERT_NUM(!reg_is_tracked(pdev, reg) || !track, reg);

	if (reg_is_tracked(pdev, reg)) {
		if (track)
			printk("vGT: init a tracked reg (%x)!!!\n", reg);

		return;
	}

	reg_set_owner(pdev, reg, attr->flags & VGT_REG_OWNER);
	if (attr->flags & VGT_REG_PASSTHROUGH)
		reg_set_passthrough(pdev, reg);
	if (attr->flags & VGT_REG_ADDR_FIX ) {
		if (!attr->addr_mask)
			printk("vGT: ZERO addr fix mask for %x\n", reg);
		reg_set_addr_fix(pdev, reg, attr->addr_mask);

		/* set the default range size to 4, might be updated later */
		reg_aux_addr_size(pdev, reg) = 4;
	}
	if (attr->flags & VGT_REG_MODE_CTL)
		reg_set_mode_ctl(pdev, reg);
	if (attr->flags & VGT_REG_VIRT)
		reg_set_virt(pdev, reg);
	if (attr->flags & VGT_REG_HW_STATUS)
		reg_set_hw_status(pdev, reg);

	/* last mark the reg as tracked */
	if (track)
		reg_set_tracked(pdev, reg);
}

static void vgt_initialize_reg_attr(struct pgt_device *pdev,
	reg_attr_t *info, int num, bool track)
{
	int i, cnt = 0, tot = 0;
	u32 reg;
	reg_attr_t *attr;

	attr = info;
	for (i = 0; i < num; i++, attr++) {
		if (!vgt_match_device_attr(pdev, attr))
			continue;

		cnt++;
		if (track)
			vgt_dbg(VGT_DBG_GENERIC,"reg(%x): size(%x), device(%d), flags(%x), mask(%x), read(%llx), write(%llx)\n",
				attr->reg, attr->size, attr->device,
				attr->flags,
				attr->addr_mask,
				(u64)attr->read, (u64)attr->write);
		for (reg = attr->reg;
			reg < attr->reg + attr->size;
			reg += REG_SIZE) {
			vgt_set_reg_attr(pdev, reg, attr, track);
			tot++;
		}

		if (attr->read || attr->write)
			vgt_register_mmio_handler(attr->reg, attr->size,
				attr->read, attr->write);
	}
	printk("%d listed, %d used\n", num, cnt);
	printk("total %d registers tracked\n", tot);
}

void vgt_setup_reg_info(struct pgt_device *pdev)
{
	int i, reg;
	struct vgt_mmio_entry *mht;
	reg_addr_sz_t *reg_addr_sz;

	printk("vGT: setup tracked reg info\n");
	vgt_initialize_reg_attr(pdev, vgt_base_reg_info,
		vgt_get_base_reg_num(), true);

	/* GDRST can be accessed by byte */
	mht = vgt_find_mmio_entry(_REG_GEN6_GDRST);
	if (mht)
		mht->align_bytes = 1;

	for (i = 0; i < vgt_get_sticky_reg_num(); i++) {
		for (reg = vgt_sticky_regs[i].reg;
		     reg < vgt_sticky_regs[i].reg + vgt_sticky_regs[i].size;
		     reg += REG_SIZE)
			reg_set_sticky(pdev, reg);
	}

	/* update the address range size in aux table */
	for (i =0; i < vgt_get_reg_addr_sz_num(); i++) {
		reg_addr_sz = &vgt_reg_addr_sz[i];
		if (reg_addr_sz->device & vgt_gen_dev_type(pdev))
			reg_aux_addr_size(pdev, reg_addr_sz->reg) = reg_addr_sz->size;
	}
}

static void __vgt_initial_mmio_space (struct pgt_device *pdev,
					reg_attr_t *info, int num)
{
	int i, j;
	reg_attr_t *attr;

	attr = info;

	for (i = 0; i < num; i++, attr++) {
		if (!vgt_match_device_attr(pdev, attr))
			continue;

		for (j = 0; j < attr->size; j += 4) {
			pdev->initial_mmio_state[REG_INDEX(attr->reg + j)] =
				VGT_MMIO_READ(pdev, attr->reg + j);
		}
	}

}

bool vgt_initial_mmio_setup (struct pgt_device *pdev)
{
	if (!pdev->initial_mmio_state) {
		pdev->initial_mmio_state = vzalloc(pdev->mmio_size);
		if (!pdev->initial_mmio_state) {
			printk("vGT: failed to allocate initial_mmio_state\n");
			return false;
		}
	}

	__vgt_initial_mmio_space(pdev, vgt_base_reg_info, vgt_get_base_reg_num());

	/* customize the initial MMIO
	 * 1, GMBUS status
	 * 2, Initial port status. 
	 */

	/* GMBUS2 has an in-use bit as the hw semaphore, and we should recover
	 * it after the snapshot.
	 */
	pdev->initial_mmio_state[REG_INDEX(_REG_PCH_GMBUS2)] &= ~0x8000;
	VGT_MMIO_WRITE(pdev, _REG_PCH_GMBUS2,
			VGT_MMIO_READ(pdev, _REG_PCH_GMBUS2) | 0x8000);

	vgt_dpy_init_modes(pdev->initial_mmio_state);

	return true;
}

void state_vreg_init(struct vgt_device *vgt)
{
	int i;
	struct pgt_device *pdev = vgt->pdev;

	for (i = 0; i < pdev->mmio_size; i += sizeof(vgt_reg_t)) {
		/*
		 * skip the area of VGT PV INFO PAGE because we need keep
		 * its content across Dom0 S3.
		*/
		if (i >= VGT_PVINFO_PAGE &&
			i < VGT_PVINFO_PAGE + VGT_PVINFO_SIZE)
			continue;

		__vreg(vgt, i) = pdev->initial_mmio_state[i/sizeof(vgt_reg_t)];
	}

	/* set the bit 0:2 (Thread C-State) to C0
	 * TODO: consider other bit 3:31
	 */
	__vreg(vgt, _REG_GT_THREAD_STATUS) = 0;

	/* set the bit 0:2(Core C-State ) to C0 */
	__vreg(vgt, _REG_GT_CORE_STATUS) = 0;

	/*TODO: init other regs that need different value from pdev */

	if (IS_HSW(vgt->pdev)) {
		/*
		 * Clear _REGBIT_FPGA_DBG_RM_NOCLAIM for not causing DOM0
		 * or Ubuntu HVM complains about unclaimed MMIO registers.
		 */
		__vreg(vgt, _REG_FPGA_DBG) &= ~_REGBIT_FPGA_DBG_RM_NOCLAIM;
	}
}

/* TODO: figure out any security holes by giving the whole initial state */
void state_sreg_init(struct vgt_device *vgt)
{
	vgt_reg_t *sreg;

	sreg = vgt->state.sReg;
	memcpy (sreg, vgt->pdev->initial_mmio_state, vgt->pdev->mmio_size);

	/*
	 * Do we really need address fix for initial state? Any address information
	 * there is meaningless to a VM, unless that address is related to allocated
	 * GM space to the VM. Translate a host address '0' to a guest GM address
	 * is just a joke.
	 */
#if 0
	/* FIXME: add off in addr table to avoid checking all regs */
	for (i = 0; i < vgt->pdev->reg_num; i++) {
		if (reg_addr_fix(vgt->pdev, i * REG_SIZE)) {
			__sreg(vgt, i) = mmio_g2h_gmadr(vgt, i, __vreg(vgt, i));
			vgt_dbg(VGT_DBG_GENERIC,"vGT: address fix for reg (%x): (%x->%x)\n",
				i, __vreg(vgt, i), __sreg(vgt, i));
		}
	}
#endif
}
