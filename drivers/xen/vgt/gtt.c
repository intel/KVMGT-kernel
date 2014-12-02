/*
 * GTT virtualization
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

#include <linux/highmem.h>

#ifdef CONFIG_XEN
#include <xen/page.h>
#include <xen/events.h>
#include <xen/xen-ops.h>
#include <xen/interface/hvm/hvm_op.h>
#endif

#include "vgt.h"

unsigned long gtt_pte_get_pfn(struct pgt_device *pdev, u32 pte)
{
	u64 addr = 0;

	if (IS_SNB(pdev) || IS_IVB(pdev))
		addr = (((u64)pte & 0xff0) << 28) | (u64)(pte & 0xfffff000);
	else if (IS_HSW(pdev))
		addr = (((u64)pte & 0x7f0) << 28) | (u64)(pte & 0xfffff000);

	return (addr >> GTT_PAGE_SHIFT);
}

static u32 gtt_pte_update(struct pgt_device *pdev, unsigned long pfn, u32 old_pte)
{
	u64 addr = pfn << GTT_PAGE_SHIFT;
	u32 pte, addr_mask = 0, ctl_mask = 0;

	if (IS_SNB(pdev) || IS_IVB(pdev)) {
		addr_mask = 0xff0;
		ctl_mask = _REGBIT_PTE_CTL_MASK_GEN7;
	} else if (IS_HSW(pdev)) {
		addr_mask = 0x7f0;
		ctl_mask = _REGBIT_PTE_CTL_MASK_GEN7_5;
	}

	pte = (addr & ~0xfff) | ((addr >> 28) & addr_mask);
	pte |= (old_pte & ctl_mask);
	pte |= _REGBIT_PTE_VALID;

	return pte;
}

/*
 * IN:  p_gtt_val - guest GTT entry
 * OUT: m_gtt_val - translated machine GTT entry from guest GTT entry
 *					on success, it will be written with correct value
 *					otherwise, it will not be written
 */
int gtt_p2m(struct vgt_device *vgt, uint32_t p_gtt_val, uint32_t *m_gtt_val)
{
	unsigned long g_pfn, mfn;

	if (!(p_gtt_val & _REGBIT_PTE_VALID)) {
		*m_gtt_val = p_gtt_val;
		return 0;
	}

	g_pfn = gtt_pte_get_pfn(vgt->pdev, p_gtt_val);

	mfn = g2m_pfn(vgt, g_pfn);
	if (mfn == INVALID_MFN){
		vgt_err("Invalid gtt entry 0x%x\n", p_gtt_val);
		return -EINVAL;
	}

	*m_gtt_val = gtt_pte_update(vgt->pdev, mfn, p_gtt_val);

	return 0;
}

/*  translate gma (graphics memory address) to guest phyiscal address
 *  by walking guest GTT table
 */
unsigned long vgt_gma_2_gpa(struct vgt_device *vgt, unsigned long gma)
{
	uint32_t gtt_index;
	unsigned long pfn, pa;

	/* Global GTT */
	if (!g_gm_is_valid(vgt, gma)) {
		vgt_err("invalid gma %lx\n", gma);
		return INVALID_ADDR;
	}
	gtt_index = gma >> GTT_PAGE_SHIFT;
	pfn = gtt_pte_get_pfn(vgt->pdev, vgt->vgtt[gtt_index]);
	pa = (pfn << PAGE_SHIFT) + (gma & ~PAGE_MASK);
	return pa;
}

static unsigned long vgt_gma_2_shadow_gpa(struct vgt_device *vgt, unsigned long gma)
{
	unsigned long gpa;
	vgt_ppgtt_pte_t *p;
	u32 *e, pte;

	ASSERT(vgt->vm_id != 0);

	if (unlikely(gma >= (1 << 31))) {
		vgt_warn("invalid gma value 0x%lx\n", gma);
		return INVALID_ADDR;
	}

	p = &vgt->shadow_pte_table[((gma >> 22) & 0x1ff)];

	/* gpa is physical pfn from shadow page table, we need VM's
	 * pte page entry */
	if (!p->guest_pte_va) {
		vgt_warn("No guest pte mapping? index %lu\n",(gma >> 22) & 0x3ff);
		return INVALID_ADDR;
	}

	e = (u32 *)p->guest_pte_va;
	pte = *((u32*)(e + ((gma >> 12) & 0x3ff)));
	gpa = (gtt_pte_get_pfn(vgt->pdev, pte) << PAGE_SHIFT) + (gma & ~PAGE_MASK);
	return gpa;
}

static unsigned long vgt_gma_2_dom0_ppgtt_gpa(struct vgt_device *vgt, unsigned long gma)
{
	/* dom0 has no shadow PTE */
	uint32_t gtt_index;
	unsigned long pfn, gpa;
	u32 *ent, pte;

	if (unlikely(gma >= (1 << 31))) {
		vgt_warn("invalid gma value 0x%lx\n", gma);
		return INVALID_ADDR;
	}

	gtt_index = vgt->ppgtt_base + ((gma >> 22) & 0x1ff);
	pfn = gtt_pte_get_pfn(vgt->pdev, vgt->vgtt[gtt_index]);

	/* dom0 PTE page */
	ent = (u32*)vgt_mfn_to_virt(pfn);
	pte = *((u32*)(ent + ((gma >> 12) & 0x3ff)));
	gpa = (gtt_pte_get_pfn(vgt->pdev, pte) << PAGE_SHIFT) + (gma & ~PAGE_MASK);
	return gpa;
}

void* vgt_gma_to_va(struct vgt_device *vgt, unsigned long gma, bool ppgtt)
{
	unsigned long gpa;
	void *ret = NULL;

	if (!ppgtt) {
		gpa = vgt_gma_2_gpa(vgt, gma);
	} else {
		if (vgt->vm_id != 0)
			gpa = vgt_gma_2_shadow_gpa(vgt, gma);
		else
			gpa = vgt_gma_2_dom0_ppgtt_gpa(vgt, gma);
	}

	if (gpa == INVALID_ADDR) {
		vgt_warn("invalid gpa! gma 0x%lx, ppgtt %s\n", gma, ppgtt ? "yes":"no");
		return NULL;
	}

	ret = vgt_vmem_gpa_2_va(vgt, gpa);
	return ret;
}

/* handler to set page wp */

int vgt_set_wp_pages(struct vgt_device *vgt, int nr, unsigned long *pages,
			int *idx)
{
	int i, rc = 0;

	if (!vgt_in_xen)
		return 0;

	if (nr > MAX_WP_BATCH_PAGES)
		return -1;

	rc = hvm_wp_pages_to_ioreq_server(vgt, nr, pages, 1);
	if (rc)
		vgt_err("Set WP pages failed!\n");
	else {
		/* Add pages in hash table */
		struct vgt_wp_page_entry *mht;

		for (i = 0; i < nr; i++) {
			mht = kmalloc(sizeof(*mht), GFP_ATOMIC);
			if (!mht) {
				vgt_err("out of memory!\n");
				vgt_unset_wp_pages(vgt, nr, pages);
				return -ENOMEM;
			}
			mht->pfn = pages[i];
			mht->idx = idx[i];
			vgt_add_wp_page_entry(vgt, mht);
		}
	}

	return rc;
}


int vgt_set_wp_page(struct vgt_device *vgt, unsigned long pfn, int idx)
{
	return vgt_set_wp_pages(vgt, 1, &pfn, &idx);
}

int vgt_unset_wp_pages(struct vgt_device *vgt, int nr, unsigned long *pages)
{
	int i, rc = 0;

	if (!vgt_in_xen)
		return 0;
	if (nr > MAX_WP_BATCH_PAGES)
		return -1;

	rc = hvm_wp_pages_to_ioreq_server(vgt, nr, pages, 0);
	if (rc)
		vgt_err("Unset WP pages failed!\n");
	else {
		for (i = 0; i < nr; i++)
			vgt_del_wp_page_entry(vgt, pages[i]);
	}

	return rc;
}

int vgt_unset_wp_page(struct vgt_device *vgt, unsigned long pfn)
{
	return vgt_unset_wp_pages(vgt, 1, &pfn);
}

int vgt_ppgtt_shadow_pte_init(struct vgt_device *vgt, int idx, dma_addr_t virt_pte)
{
	int i;
	vgt_ppgtt_pte_t *p = &vgt->shadow_pte_table[idx];
	u32 *ent;
	u32 *shadow_ent;
	dma_addr_t addr, s_addr;
	struct pgt_device *pdev = vgt->pdev;

	ASSERT(vgt->vm_id != 0);

	if (!p->pte_page) {
		vgt_err("Uninitialized shadow PTE page at index %d?\n", idx);
		return -1;
	}

	p->guest_pte_va = vgt_vmem_gpa_2_va(vgt, virt_pte);
	if (!p->guest_pte_va) {
		vgt_err("Failed to get guest PTE page memory access!\n");
		return -1;
	}
	ent = p->guest_pte_va;

	shadow_ent = kmap_atomic(p->pte_page);

	/* for each PTE entry */
	for (i = 0; i < 1024; i++) {
		/* check valid */
		if ((ent[i] & _REGBIT_PTE_VALID) == 0)
			continue;
		/* get page physical address */
		addr = gtt_pte_get_pfn(pdev, ent[i]);

		/* get real physical address for that page */
		s_addr = g2m_pfn(vgt, addr);
		if (s_addr == INVALID_MFN) {
			vgt_err("vGT: VM[%d]: Failed to get machine address for 0x%lx\n",
				vgt->vm_id, (unsigned long)addr);
			return -1;
		}

		/* update shadow PTE entry with targe page address */
		shadow_ent[i] = gtt_pte_update(pdev, s_addr, ent[i]);
	}
	kunmap_atomic(shadow_ent);
	/* XXX unmap guest VM page? */
	return 0;
}

/* Process needed shadow setup for one PDE entry.
 * i: index from PDE base
 * pde: guest GTT PDE entry value
 */
static void
vgt_ppgtt_pde_handle(struct vgt_device *vgt, unsigned int i, u32 pde)
{
	struct pgt_device *pdev = vgt->pdev;
	u32 shadow_pde;
	unsigned int index, h_index;
	dma_addr_t pte_phy;

	if (!(pde & _REGBIT_PDE_VALID)) {
		printk("vGT(%d): PDE %d not valid!\n", vgt->vgt_id, i);
		return;
	}

	if ((pde & _REGBIT_PDE_PAGE_32K)) {
		printk("vGT(%d): 32K page in PDE!\n", vgt->vgt_id);
		vgt->shadow_pde_table[i].big_page = true;
	} else
		vgt->shadow_pde_table[i].big_page = false;

	vgt->shadow_pde_table[i].entry = pde;

	pte_phy = gtt_pte_get_pfn(pdev, pde);
	pte_phy <<= PAGE_SHIFT;

	vgt->shadow_pde_table[i].virtual_phyaddr = pte_phy;

	/* allocate shadow PTE page, and fix it up */
	vgt_ppgtt_shadow_pte_init(vgt, i, pte_phy);

	/* WP original PTE page */
	vgt_set_wp_page(vgt, pte_phy >> PAGE_SHIFT, i);

	shadow_pde = gtt_pte_update(pdev,
					vgt->shadow_pde_table[i].shadow_pte_maddr >> GTT_PAGE_SHIFT,
					pde);

	if (vgt->shadow_pde_table[i].big_page) {
		/* For 32K page, even HVM thinks it's continual, it's
		 * really not on physical pages. But fallback to 4K
		 * addressing can still provide correct page reference.
		 */
		shadow_pde &= ~_REGBIT_PDE_PAGE_32K;
	}

	index = vgt->ppgtt_base + i;
	h_index = g2h_gtt_index(vgt, index);

	/* write_gtt with new shadow PTE page address */
	vgt_write_gtt(vgt->pdev, h_index, shadow_pde);
}


static void
vgt_ppgtt_pde_write(struct vgt_device *vgt, unsigned int g_gtt_index, u32 g_gtt_val)
{
	int i = g_gtt_index - vgt->ppgtt_base;
	u32 h_gtt_index;

	if (vgt->shadow_pde_table[i].entry == g_gtt_val) {
		vgt_dbg(VGT_DBG_MEM, "write same PDE value?\n");
		return;
	}

	vgt_dbg(VGT_DBG_MEM, "write PDE[%d] old: 0x%x new: 0x%x\n", i, vgt->shadow_pde_table[i].entry, g_gtt_val);

	if (vgt->shadow_pde_table[i].entry & _REGBIT_PDE_VALID)
		vgt_unset_wp_page(vgt, vgt->shadow_pde_table[i].virtual_phyaddr >> PAGE_SHIFT);

	if (!(g_gtt_val & _REGBIT_PDE_VALID)) {
		h_gtt_index = g2h_gtt_index(vgt, g_gtt_index);
		vgt_write_gtt(vgt->pdev, h_gtt_index, 0);
	} else {
		vgt_ppgtt_pde_handle(vgt, i, g_gtt_val);
	}
}

static bool gtt_mmio_read32(struct vgt_device *vgt, unsigned int off,
	void *p_data, unsigned int bytes)
{
	uint32_t g_gtt_index;

	ASSERT(bytes == 4);

	off -= vgt->pdev->mmio_size;
	/*
	if (off >= vgt->vgtt_sz) {
		vgt_dbg(VGT_DBG_MEM, "vGT(%d): captured out of range GTT read on off %x\n", vgt->vgt_id, off);
		return false;
	}
	*/

	g_gtt_index = GTT_OFFSET_TO_INDEX(off);
	*(uint32_t*)p_data = vgt->vgtt[g_gtt_index];
	if (vgt->vm_id == 0) {
		*(uint32_t*)p_data = vgt_read_gtt(vgt->pdev,
						  g_gtt_index);
	} else if (off < vgt->vgtt_sz) {
		*(uint32_t*)p_data = vgt->vgtt[g_gtt_index];
	} else {
		printk("vGT(%d): captured out of range GTT read on "
		       "off %x\n", vgt->vgt_id, off);
		return false;
	}
	
	return true;
}

bool gtt_mmio_read(struct vgt_device *vgt, unsigned int off,
	void *p_data, unsigned int bytes)
{
	int ret;
	cycles_t t0, t1;
	struct vgt_statistics *stat = &vgt->stat;

	t0 = get_cycles();
	stat->gtt_mmio_rcnt++;

	ASSERT(bytes == 4 || bytes == 8);

	ret = gtt_mmio_read32(vgt, off, p_data, 4);
	if (ret && bytes == 8)
		ret = gtt_mmio_read32(vgt, off + 4, (char*)p_data + 4, 4);

	t1 = get_cycles();
	stat->gtt_mmio_rcycles += (u64) (t1 - t0);
	return ret;
}

#define GTT_INDEX_MB(x) ((SIZE_1MB*(x)) >> GTT_PAGE_SHIFT)

static bool gtt_mmio_write32(struct vgt_device *vgt, unsigned int off,
	void *p_data, unsigned int bytes)
{
	uint32_t g_gtt_val, h_gtt_val, g_gtt_index, h_gtt_index;
	int rc;
	uint64_t g_addr;

	ASSERT(bytes == 4);

	off -= vgt->pdev->mmio_size;

	g_gtt_index = GTT_OFFSET_TO_INDEX(off);
	g_gtt_val = *(uint32_t*)p_data;
	vgt->vgtt[g_gtt_index] = g_gtt_val;

	g_addr = g_gtt_index << GTT_PAGE_SHIFT;
	/* the VM may configure the whole GM space when ballooning is used */
	if (!g_gm_is_valid(vgt, g_addr)) {
		static int count = 0;

		/* print info every 32MB */
		if (!(count % 8192))
			vgt_dbg(VGT_DBG_MEM, "vGT(%d): capture ballooned write for %d times (%x)\n",
				vgt->vgt_id, count, off);

		count++;
		/* in this case still return true since the impact is on vgtt only */
		goto out;
	}

	if (vgt->ppgtt_initialized && vgt->vm_id &&
			g_gtt_index >= vgt->ppgtt_base &&
			g_gtt_index < vgt->ppgtt_base + VGT_PPGTT_PDE_ENTRIES) {
		vgt_dbg(VGT_DBG_MEM, "vGT(%d): Change PPGTT PDE %d!\n", vgt->vgt_id, g_gtt_index);
		vgt_ppgtt_pde_write(vgt, g_gtt_index, g_gtt_val);
		goto out;
	}

	rc = gtt_p2m(vgt, g_gtt_val, &h_gtt_val);
	if (rc < 0){
		vgt_err("vGT(%d): failed to translate g_gtt_val(%x)\n", vgt->vgt_id, g_gtt_val);
		return false;
	}

	h_gtt_index = g2h_gtt_index(vgt, g_gtt_index);
	vgt_write_gtt( vgt->pdev, h_gtt_index, h_gtt_val );
#ifdef DOM0_DUAL_MAP
	if ( (h_gtt_index >= GTT_INDEX_MB(128)) && (h_gtt_index < GTT_INDEX_MB(192)) ){
		vgt_write_gtt( vgt->pdev, h_gtt_index - GTT_INDEX_MB(128), h_gtt_val );
	}
#endif
out:
	return true;
}

bool gtt_mmio_write(struct vgt_device *vgt, unsigned int off,
	void *p_data, unsigned int bytes)
{
	int ret;
	cycles_t t0, t1;
	struct vgt_statistics *stat = &vgt->stat;

	t0 = get_cycles();
	stat->gtt_mmio_wcnt++;

	ASSERT(bytes == 4 || bytes == 8);

	ret = gtt_mmio_write32(vgt, off, p_data, 4);
	if (ret && bytes == 8)
		ret = gtt_mmio_write32(vgt, off + 4, (char*)p_data + 4, 4);

	t1 = get_cycles();
	stat->gtt_mmio_wcycles += (u64) (t1 - t0);
	return ret;
}

bool vgt_ppgtt_handle_pte_rp(struct vgt_device *vgt, struct vgt_wp_page_entry *e,
				unsigned int offset, void *p_data, unsigned int bytes)
{
	struct pgt_device *pdev = vgt->pdev;
	int index, i;
	unsigned long g_val = 0, g_addr = 0, h_addr = 0;
	struct vgt_statistics *stat = &vgt->stat;
	cycles_t t0, t1;

	ASSERT(vgt->vm_id != 0);

	t0 = get_cycles();

	vgt_dbg(VGT_DBG_MEM, "PTE RP handler: offset 0x%x data 0x%lx bytes %d\n", offset, *(unsigned long *)p_data, bytes);

	i = e->idx;

	g_val = *(unsigned long*)p_data;

	/* find entry index, fill in shadow PTE */

	index = (offset & (PAGE_SIZE - 1)) >> 2;

	g_addr = gtt_pte_get_pfn(pdev, g_val);

	h_addr = g2m_pfn(vgt, g_addr);
	if (h_addr == INVALID_MFN) {
		vgt_err("Failed to convert RP page at 0x%lx\n", g_addr);
		return false;
	}

	if (vgt->shadow_pte_table[i].guest_pte_va) {
		u32 *guest_pte;
		guest_pte = (u32*)vgt->shadow_pte_table[i].guest_pte_va;
		*(uint32_t *)p_data = guest_pte[index];
	} else {
		vgt_err("Failed to read RP paget.\n");
		return false;
	}

	t1 = get_cycles();
	stat->ppgtt_rp_cnt++;
	stat->ppgtt_rp_cycles += t1 - t0;		

	return true;
}

/* So idea is that for PPGTT base in GGTT, real PDE entry will point to shadow
 * PTE, then shadow PTE entry will point to final page. So have to fix shadow
 * PTE address in PDE, and final page address in PTE. That's two-phrase address
 * fixing.
 */

/* Handle write protect fault on virtual PTE page */
bool vgt_ppgtt_handle_pte_wp(struct vgt_device *vgt, struct vgt_wp_page_entry *e,
				unsigned int offset, void *p_data, unsigned int bytes)
{
	struct pgt_device *pdev = vgt->pdev;
	int index, i;
	u32 *pte;
	unsigned long g_val = 0, g_addr = 0, h_addr = 0;
	struct vgt_statistics *stat = &vgt->stat;
	cycles_t t0, t1;

	ASSERT(vgt->vm_id != 0);

	t0 = get_cycles();

	vgt_dbg(VGT_DBG_MEM, "PTE WP handler: offset 0x%x data 0x%lx bytes %d\n", offset, *(unsigned long *)p_data, bytes);

	i = e->idx;

	g_val = *(unsigned long*)p_data;

	/* find entry index, fill in shadow PTE */

	index = (offset & (PAGE_SIZE - 1)) >> 2;

	g_addr = gtt_pte_get_pfn(pdev, g_val);

	h_addr = g2m_pfn(vgt, g_addr);
	if (h_addr == INVALID_MFN) {
		vgt_err("Failed to convert WP page at 0x%lx\n", g_addr);
		return false;
	}

	if (vgt->shadow_pte_table[i].guest_pte_va) {
		u32 *guest_pte;
		guest_pte = (u32*)vgt->shadow_pte_table[i].guest_pte_va;
		guest_pte[index] = gtt_pte_update(pdev, g_addr, g_val);
	}

	pte = kmap_atomic(vgt->shadow_pte_table[i].pte_page);
	pte[index] = gtt_pte_update(pdev, h_addr, g_val);
	clflush((u8 *)pte + index * 4);
	kunmap_atomic(pte);

	vgt_dbg(VGT_DBG_MEM, "WP: PDE[%d], PTE[%d], entry 0x%x, g_addr 0x%lx, h_addr 0x%lx\n", i, index, pte[index], g_addr, h_addr);

	t1 = get_cycles();
	stat->ppgtt_wp_cnt++;
	stat->ppgtt_wp_cycles += t1 - t0;

	return true;
}

static void vgt_init_ppgtt_hw(struct vgt_device *vgt, u32 base)
{
	/* only change HW setting if vgt is current render owner.*/
	if (current_render_owner(vgt->pdev) != vgt)
		return;

	/* Rewrite PP_DIR_BASE to let HW reload PDs in internal cache */
	VGT_MMIO_WRITE(vgt->pdev, _REG_RCS_PP_DCLV, 0xffffffff);
	VGT_MMIO_WRITE(vgt->pdev, _REG_RCS_PP_DIR_BASE_IVB, base);

	VGT_MMIO_WRITE(vgt->pdev, _REG_BCS_PP_DCLV, 0xffffffff);
	VGT_MMIO_WRITE(vgt->pdev, _REG_BCS_PP_DIR_BASE, base);

	VGT_MMIO_WRITE(vgt->pdev, _REG_VCS_PP_DCLV, 0xffffffff);
	VGT_MMIO_WRITE(vgt->pdev, _REG_VCS_PP_DIR_BASE, base);

	if (IS_HSW(vgt->pdev) && vgt->vebox_support) {
		VGT_MMIO_WRITE(vgt->pdev, _REG_VECS_PP_DCLV, 0xffffffff);
		VGT_MMIO_WRITE(vgt->pdev, _REG_VECS_PP_DIR_BASE, base);
	}
}

void vgt_ppgtt_switch(struct vgt_device *vgt)
{
	u32 base = vgt->rb[0].sring_ppgtt_info.base;
	vgt_dbg(VGT_DBG_MEM, "vGT: VM(%d): switch to ppgtt base 0x%x\n", vgt->vm_id, base);
	vgt_init_ppgtt_hw(vgt, base);
}

bool vgt_setup_ppgtt(struct vgt_device *vgt)
{
	u32 base = vgt->rb[0].sring_ppgtt_info.base;
	int i;
	u32 pde, gtt_base;
	unsigned int index;

	vgt_info("vgt_setup_ppgtt on vm %d: PDE base 0x%x\n", vgt->vm_id, base);

	gtt_base = base >> PAGE_SHIFT;

	vgt->ppgtt_base = gtt_base;

	/* dom0 already does mapping for PTE page itself and PTE entry target
	 * page. So we're just ready to go.
	 */
	if (vgt->vm_id == 0)
		goto finish;

	for (i = 0; i < VGT_PPGTT_PDE_ENTRIES; i++) {
		index = gtt_base + i;

		/* Just use guest virtual value instead of real machine address */
		pde = vgt->vgtt[index];

		vgt_ppgtt_pde_handle(vgt, i, pde);
	}

finish:
	vgt_init_ppgtt_hw(vgt, base);

	vgt->ppgtt_initialized = true;

	return true;
}

bool vgt_init_shadow_ppgtt(struct vgt_device *vgt)
{
	struct pgt_device *pdev = vgt->pdev;
	int i;
	vgt_ppgtt_pte_t *p;
	dma_addr_t dma_addr;

	/* only hvm guest needs shadowed PT pages */
	ASSERT(vgt->vm_id != 0);

	vgt_dbg(VGT_DBG_MEM, "vgt_init_shadow_ppgtt for vm %d\n", vgt->vm_id);

	/* each PDE entry has one shadow PTE page */
	for (i = 0; i < VGT_PPGTT_PDE_ENTRIES; i++) {
		p = &vgt->shadow_pte_table[i];
		p->pte_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!p->pte_page) {
			vgt_err("Init shadow PTE page failed!\n");
			return false;
		}

		dma_addr = pci_map_page(pdev->pdev, p->pte_page, 0, PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		if (pci_dma_mapping_error(pdev->pdev, dma_addr)) {
			vgt_err("Pci map shadow PTE page failed!\n");
			return false;
		}

		p->shadow_addr = dma_addr;
		vgt->shadow_pde_table[i].shadow_pte_maddr = p->shadow_addr;
	}
	return true;
}

void vgt_destroy_shadow_ppgtt(struct vgt_device *vgt)
{
	int i;
	vgt_ppgtt_pte_t *p;

	/* only hvm guest needs shadowed PT pages */
	ASSERT(vgt->vm_id != 0);

	for (i = 0; i < VGT_PPGTT_PDE_ENTRIES; i++) {
		p = &vgt->shadow_pte_table[i];

		if (vgt->ppgtt_initialized) {
			vgt_unset_wp_page(vgt, vgt->shadow_pde_table[i].virtual_phyaddr >> PAGE_SHIFT);
		}
		__free_page(p->pte_page);
	}
}

void vgt_reset_dom0_ppgtt_state(void)
{
	int i;
	struct vgt_device *vgt = vgt_dom0;

	vgt->ppgtt_initialized = false;

	for (i = 0; i < MAX_ENGINES; i++) {
		vgt->rb[i].has_ppgtt_mode_enabled = 0;
		vgt->rb[i].has_ppgtt_base_set = 0;
	}
}

/* XXX assume all rings use same PPGTT table, so try to initialize once
 * all bases are set.
 */
void vgt_try_setup_ppgtt(struct vgt_device *vgt)
{
	int ring, i, num;
	u32 base;

	if (vgt->vebox_support)
		num = 4;
	else
		num = 3;

	for (ring = 0; ring < num; ring++) {
		if (!vgt->rb[ring].has_ppgtt_base_set)
			return;
	}

	base = vgt->rb[0].vring_ppgtt_info.base;
	for (i = 1; i < num; i++) {
		if (vgt->rb[i].vring_ppgtt_info.base != base) {
			printk(KERN_WARNING "zhen: different PPGTT base set is not supported now!\n");
			vgt->pdev->enable_ppgtt = 0;
			return;
		}
	}
	vgt_dbg(VGT_DBG_MEM, "zhen: all rings are set PPGTT base and use single table!\n");
	vgt_setup_ppgtt(vgt);
}

int ring_ppgtt_mode(struct vgt_device *vgt, int ring_id, u32 off, u32 mode)
{
	vgt_ring_ppgtt_t *v_info = &vgt->rb[ring_id].vring_ppgtt_info;
	vgt_ring_ppgtt_t *s_info = &vgt->rb[ring_id].sring_ppgtt_info;

	v_info->mode = mode;
	s_info->mode = mode;

	__sreg(vgt, off) = mode;
	__vreg(vgt, off) = mode;

	if (reg_hw_access(vgt, off)) {
		vgt_dbg(VGT_DBG_MEM, "RING mode: offset 0x%x write 0x%x\n", off, s_info->mode);
		VGT_MMIO_WRITE(vgt->pdev, off, s_info->mode);
	}

	/* sanity check */
	if ((mode & _REGBIT_PPGTT_ENABLE) && (mode & (_REGBIT_PPGTT_ENABLE << 16))) {
		printk("PPGTT enabling on ring %d\n", ring_id);
		/* XXX the order of mode enable for PPGTT and PPGTT dir base
		 * setting is not strictly defined, e.g linux driver first
		 * enables PPGTT bit in mode reg, then write PP dir base...
		 */
		vgt->rb[ring_id].has_ppgtt_mode_enabled = 1;
	}

	return 0;
}
