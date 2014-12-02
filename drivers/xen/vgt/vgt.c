/*
 * vGT module interface
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

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#ifdef CONFIG_XEN
#include <asm/xen/hypercall.h>
#include <xen/interface/vcpu.h>
#endif

#include "host_mediate.h"

#include "vgt.h"


MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("vGT mediated graphics passthrough driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

bool ignore_hvm_forcewake_req = true;
module_param_named(ignore_hvm_forcewake_req, ignore_hvm_forcewake_req, bool, 0400);
MODULE_PARM_DESC(ignore_hvm_forcewake_req, "ignore HVM's forwake request (default: true)");

bool hvm_render_owner = false;
module_param_named(hvm_render_owner, hvm_render_owner, bool, 0600);
MODULE_PARM_DESC(hvm_render_owner, "Make HVM to be render owner after create (default: false)");

bool hvm_dpy_owner = false;
module_param_named(hvm_dpy_owner, hvm_dpy_owner, bool, 0600);
MODULE_PARM_DESC(hvm_dpy_owner, "Deprecated option! Please use hvm_boot_foreground or hvm_display_owner!");

bool hvm_display_owner = false;
module_param_named(hvm_display_owner, hvm_display_owner, bool, 0600);
MODULE_PARM_DESC(hvm_display_owner, "Make HVM to be display owner after create (default: false)");

bool hvm_super_owner = false;
module_param_named(hvm_super_owner, hvm_super_owner, bool, 0600);
MODULE_PARM_DESC(hvm_super_owner, "Make HVM to be GPU owner after create (default: false)");

bool hvm_boot_foreground = false;
module_param_named(hvm_boot_foreground, hvm_boot_foreground, bool, 0600);
MODULE_PARM_DESC(hvm_boot_foreground, "Make HVM to be foreground after create and visible on screen from booting (default: false)");

bool vgt_primary = false;
module_param_named(vgt_primary, vgt_primary, bool, 0600);

bool vgt_track_nest = true;
module_param_named(track_nest, vgt_track_nest, bool, 0600);

bool vgt_delay_nest = true;
module_param_named(delay_nest, vgt_delay_nest, bool, 0600);

int vgt_debug = 0;
module_param_named(debug, vgt_debug, int, 0600);

bool vgt_enabled = true;
module_param_named(vgt, vgt_enabled, bool, 0400);

bool fastpath_dpy_switch = true;
module_param_named(fastpath_dpy_switch, fastpath_dpy_switch, bool, 0600);

bool event_based_qos = false;
module_param_named(event_based_qos, event_based_qos, bool, 0600);
MODULE_PARM_DESC(event_based_qos, "Use event based QoS scheduler (default: false)");

bool shadow_tail_based_qos = false;
module_param_named(shadow_tail_based_qos, shadow_tail_based_qos, bool, 0600);
MODULE_PARM_DESC(shadow_tail_based_qos, "Use Shadow tail based QoS scheduler (default: false)");

bool render_engine_reset = true;
module_param_named(render_engine_reset, render_engine_reset, bool, 0600);
MODULE_PARM_DESC(render_engine_reset, "Reset rendering engines before loading another VM's context");

bool propagate_monitor_to_guest = true;
module_param_named(propagate_monitor_to_guest, propagate_monitor_to_guest, bool, 0600);
MODULE_PARM_DESC(propagate_monitor_to_guest, "Propagate monitor information to guest by XenGT, other than dom0 services to do so");

/*
 * FIXME: now video ring switch has weird issue. The cmd
 * parser may enter endless loop even when head/tail is
 * zero. earlier posting read doesn't solve the issue.
 * so disable it for now.
 *
 * Dexuan: let's enable VCS switch, because on HSW, win7 gfx drver's PAVP
 * initialization uses VCS. Without enabling this option, win7 guest's gfx
 * driver's initializtion will hang when we create the guest for the 2nd
 * time(VCS.TAIL is 0x70, but VCS.HEAD is always 0x30).
 */
int enable_video_switch = 1;
module_param_named(enable_video_switch, enable_video_switch, int, 0600);

/*
 * On HSW, the max low/high gm sizes are 512MB/1536MB.
 * If each VM takes 512MB GM, we can support 4VMs.
 * By default Dom0 has 512MB GM, including 120MB low gm used by i915 and
 * 8MB low gm used by vGT driver itself(see VGT_RSVD_APERTURE_SZ), and
 * (512-120-8)MB high GM space used by i915.
 * We can reduce the GM space used by Dom0 i915, but remember: Dom0
 * render/display may not work properly without enough GM space.
 */
int dom0_low_gm_sz = 120;	//in MB.
module_param_named(dom0_low_gm_sz, dom0_low_gm_sz, int, 0600);

int dom0_high_gm_sz = 384;	//in MB.
module_param_named(dom0_high_gm_sz, dom0_high_gm_sz, int, 0600);

int dom0_fence_sz = 4;
module_param_named(dom0_fence_sz, dom0_fence_sz, int, 0600);

int bypass_scan_mask = 0;
module_param_named(bypass_scan, bypass_scan_mask, int, 0600);

bool bypass_dom0_addr_check = false;
module_param_named(bypass_dom0_addr_check, bypass_dom0_addr_check, bool, 0600);

bool enable_panel_fitting = true;
module_param_named(enable_panel_fitting, enable_panel_fitting, bool, 0600);

bool enable_reset = true;
module_param_named(enable_reset, enable_reset, bool, 0600);

bool vgt_lock_irq = false;
module_param_named(vgt_lock_irq, vgt_lock_irq, bool, 0400);

bool vgt_in_xen __read_mostly = false;

static vgt_ops_t vgt_xops = {
	.mem_read = vgt_emulate_read,
	.mem_write = vgt_emulate_write,
	.cfg_read = vgt_emulate_cfg_read,
	.cfg_write = vgt_emulate_cfg_write,
	.boot_time = true,
	.initialized = false,
};
vgt_ops_t *vgt_ops = NULL;

LIST_HEAD(pgt_devices);
struct pgt_device default_device = {
	.bus = 0,
	.devfn = 0x10,		/* BDF: 0:2:0 */
};

struct vgt_device *vgt_dom0;
DEFINE_PER_CPU(u8, in_vgt);

/* TODO: cleanup and rename after IOREQ server */
static bool vgt_start_io_forwarding(struct pgt_device *pdev)
{
	uint64_t bar0; /* the MMIO BAR for regs(2MB) and GTT */

#if 0
#ifdef CONFIG_XEN_DOM0
	struct xen_platform_op xpop;
#endif
#endif

	bar0 = *(uint64_t *)&pdev->initial_cfg_space[VGT_REG_CFG_SPACE_BAR0];
	bar0 &= ~0xf;	/* bit0~3 of the bar is the attribution info */

#ifdef CONFIG_XEN
	if (xen_initial_domain()) {
		/*
		 * Pass the GEN device's BDF and the type(SNB/IVB/HSW?) to
		 * the xen hypervisor: xen needs the info to decide which device's
		 * PCI CFG R/W access should be forwarded to the vgt driver, and
		 * to decice the proper forcewake logic.
		 */
#if 0
		xpop.cmd = XENPF_set_vgt_info;
		xpop.u.vgt_info.gen_dev_bdf = PCI_BDF2(pdev->pbus->number, pdev->devfn);
		xpop.u.vgt_info.gen_dev_type = pdev->gen_dev_type;
		if (HYPERVISOR_dom0_op(&xpop) != 0)
			return false;
#endif
	}
#endif

	return true;
}

/*
 * The thread to perform the VGT ownership switch.
 *
 * We need to handle race conditions from different paths around
 * vreg/sreg/hwreg. So far there're 4 paths at least:
 *   a) the vgt thread to conduct context switch
 *   b) the GP handler to emulate MMIO for dom0
 *   c) the event handler to emulate MMIO for other VMs
 *   d) the interrupt handler to do interrupt virtualization
 *   e) /sysfs interaction from userland program
 *
 * Now d) is removed from the race path, because we adopt a delayed
 * injection mechanism. Physical interrupt handler only saves pending
 * IIR bits, and then wake up the vgt thread. Later the vgt thread
 * checks the pending bits to do the actual virq injection. This approach
 * allows vgt thread to handle ownership switch cleanly.
 *
 * So it's possible for other 3 paths to touch vreg/sreg/hwreg:
 *   a) the vgt thread may need to update HW updated regs into
 *	  vreg/sreg of the prev owner
 *   b) the GP handler and event handler always updates vreg/sreg,
 *	  and may touch hwreg if vgt is the current owner
 *	  and then update vreg for interrupt virtualization
 *
 * To simplify the lock design, we make below assumptions:
 *   a) the vgt thread doesn't trigger GP fault itself, i.e. always
 *	  issues hypercall to do hwreg access
 *   b) the event handler simply notifies another kernel thread, leaving
 *	  to that thread for actual MMIO emulation
 *
 * Given above assumption, no nest would happen among 4 paths, and a
 * simple global spinlock now should be enough to protect the whole
 * vreg/sreg/ hwreg. In the future we can futher tune this part on
 * a necessary base.
 */
static int vgt_thread(void *priv)
{
	struct pgt_device *pdev = (struct pgt_device *)priv;
	int ret;
	int cpu;

	//ASSERT(current_render_owner(pdev));
	printk("vGT: start kthread for dev (%x, %x)\n", pdev->bus, pdev->devfn);

	set_freezable();
	while (!kthread_should_stop()) {
		ret = wait_event_interruptible(pdev->event_wq,
			pdev->request || freezing(current));

		if (ret)
			vgt_warn("Main thread waken up by unexpected signal!\n");

		if (!pdev->request && !freezing(current)) {
			vgt_warn("Main thread waken up by unknown reasons!\n");
			continue;
		}

		if (freezing(current)) {
			if (current_render_owner(pdev) == vgt_dom0) {
				try_to_freeze();
			}
			else {
				vgt_lock_dev(pdev, cpu);
				pdev->next_sched_vgt = vgt_dom0;
				vgt_raise_request(pdev, VGT_REQUEST_CTX_SWITCH);
				vgt_unlock_dev(pdev, cpu);
			}
		}

		if (test_and_clear_bit(VGT_REQUEST_DEVICE_RESET,
					(void *)&pdev->request)) {
			vgt_reset_device(pdev);
		}

		/* forward physical GPU events to VMs */
		if (test_and_clear_bit(VGT_REQUEST_IRQ,
					(void *)&pdev->request)) {
			vgt_lock_dev(pdev, cpu);
			vgt_forward_events(pdev);
			vgt_unlock_dev(pdev, cpu);
		}

		/* Send uevent to userspace */
		if (test_and_clear_bit(VGT_REQUEST_UEVENT,
					(void *)&pdev->request)) {
			vgt_signal_uevent(pdev);
		}

		if (test_and_clear_bit(VGT_REQUEST_DPY_SWITCH,
					(void *)&pdev->request)) {
			vgt_lock_dev(pdev, cpu);
			if (prepare_for_display_switch(pdev) == 0)
				do_vgt_fast_display_switch(pdev);
			vgt_unlock_dev(pdev, cpu);
		}

		/* Handle render context switch request */
		if (vgt_ctx_switch &&
		    test_and_clear_bit(VGT_REQUEST_CTX_SWITCH,
				(void *)&pdev->request)) {
			if (!vgt_do_render_context_switch(pdev)) {
				if (enable_reset) {
					vgt_err("Hang in context switch, try to reset device.\n");

					vgt_reset_device(pdev);
				} else {
					vgt_err("Hang in context switch, panic the system.\n");
					ASSERT(0);
				}
			}
		}

		if (test_and_clear_bit(VGT_REQUEST_EMUL_DPY_EVENTS,
				(void *)&pdev->request)) {
			vgt_lock_dev(pdev, cpu);
			vgt_emulate_dpy_events(pdev);
			vgt_unlock_dev(pdev, cpu);
		}
	}
	return 0;
}


bool initial_phys_states(struct pgt_device *pdev)
{
	int i;
	uint64_t	bar0, bar1;
	struct pci_dev *dev = pdev->pdev;

	vgt_dbg(VGT_DBG_GENERIC, "VGT: Initial_phys_states\n");

	pdev->gtt_size = vgt_get_gtt_size(pdev->pbus);
	gm_sz(pdev) = vgt_get_gtt_size(pdev->pbus) * 1024;
	pdev->saved_gtt = vzalloc(pdev->gtt_size);
	if (!pdev->saved_gtt)
		return false;

	for (i=0; i<VGT_CFG_SPACE_SZ; i+=4)
		pci_read_config_dword(dev, i,
				(uint32_t *)&pdev->initial_cfg_space[i]);

	for (i=0; i<VGT_CFG_SPACE_SZ; i+=4) {
		if (!(i % 16))
			vgt_dbg(VGT_DBG_GENERIC, "\n[%2x]: ", i);

		vgt_dbg(VGT_DBG_GENERIC, "%02x %02x %02x %02x ",
			*((uint32_t *)&pdev->initial_cfg_space[i]) & 0xff,
			(*((uint32_t *)&pdev->initial_cfg_space[i]) & 0xff00) >> 8,
			(*((uint32_t *)&pdev->initial_cfg_space[i]) & 0xff0000) >> 16,
			(*((uint32_t *)&pdev->initial_cfg_space[i]) & 0xff000000) >> 24);
	}
	for (i=0; i < 3; i++) {
		pdev->bar_size[i] = pci_bar_size(pdev, VGT_REG_CFG_SPACE_BAR0 + 8*i);
		printk("bar-%d size: %x\n", i, pdev->bar_size[i]);
	}

	bar0 = *(uint64_t *)&pdev->initial_cfg_space[VGT_REG_CFG_SPACE_BAR0];
	bar1 = *(uint64_t *)&pdev->initial_cfg_space[VGT_REG_CFG_SPACE_BAR1];
	printk("bar0: 0x%llx, Bar1: 0x%llx\n", bar0, bar1);

	ASSERT ((bar0 & 7) == 4);
	/* memory, 64 bits bar0 */
	pdev->gttmmio_base = bar0 & ~0xf;
	pdev->mmio_size = VGT_MMIO_SPACE_SZ;
	pdev->reg_num = pdev->mmio_size/REG_SIZE;
	printk("mmio size: %x, gtt size: %x\n", pdev->mmio_size,
		pdev->gtt_size);
	ASSERT(pdev->mmio_size + pdev->gtt_size <= pdev->bar_size[0]);

	ASSERT ((bar1 & 7) == 4);
	/* memory, 64 bits bar */
	pdev->gmadr_base = bar1 & ~0xf;
	printk("gttmmio: 0x%llx, gmadr: 0x%llx\n", pdev->gttmmio_base, pdev->gmadr_base);

	pdev->gttmmio_base_va = ioremap(pdev->gttmmio_base,
			pdev->mmio_size + pdev->gtt_size);
	if (pdev->gttmmio_base_va == NULL) {
		WARN_ONCE(1, "insufficient memory for ioremap!\n");
		return false;
	}
	printk("gttmmio_base_va: 0x%llx\n", (uint64_t)pdev->gttmmio_base_va);
	tmp_vgt_force_wake_setup(pdev);


	/* start the io forwarding! */
	if (!vgt_start_io_forwarding(pdev))
		return false;;

	/*
	 * From now on, the vgt driver can invoke the
	 * VGT_MMIO_READ()/VGT_MMIO_WRITE()hypercalls, and any access to the
	 * 4MB MMIO of the GEN device is trapped into the vgt driver.
	 */

	// TODO: runtime sanity check warning...
	pdev->gmadr_va = ioremap(pdev->gmadr_base, pdev->bar_size[1]);
	if (pdev->gmadr_va == NULL) {
		iounmap(pdev->gttmmio_base_va);
		printk("Insufficient memory for ioremap2\n");
		return false;
	}
	printk("gmadr_va: 0x%llx\n", (uint64_t)pdev->gmadr_va);

	vgt_initial_mmio_setup(pdev);
	vgt_initial_opregion_setup(pdev);

	/* FIXME: GMBUS2 has an in-use bit as the hw semaphore, and we should recover
	 * it after the snapshot. Remove this workaround after GMBUS virtualization
	 */
	{
		u32 val = VGT_MMIO_READ(pdev, 0xc5108);
		pdev->initial_mmio_state[REG_INDEX(0xc5108)] &= ~0x8000;
		printk("vGT: GMBUS2 init value: %x, %x\n", pdev->initial_mmio_state[REG_INDEX(0xc5108)], val);
		VGT_MMIO_WRITE(pdev, 0xc5108, val | 0x8000);
	}

	return true;
}

static bool vgt_set_device_type(struct pgt_device *pdev)
{
	if (_is_sandybridge(pdev->pdev->device)) {
		pdev->gen_dev_type = XEN_IGD_SNB;
		vgt_info("Detected Sandybridge\n");
		return true;
	}

	if (_is_ivybridge(pdev->pdev->device)) {
		pdev->gen_dev_type = XEN_IGD_IVB;
		vgt_info("Detected Ivybridge\n");
		return true;
	}

	if (_is_haswell(pdev->pdev->device)) {
		pdev->gen_dev_type = XEN_IGD_HSW;
		vgt_info("Detected Haswell\n");
		return true;
	}

	vgt_err("Unknown chip 0x%x\n", pdev->pdev->device);
	return false;
}

static bool vgt_initialize_pgt_device(struct pci_dev *dev, struct pgt_device *pdev)
{
	int i;

	pdev->pdev = dev;
	pdev->pbus = dev->bus;

	if (!vgt_set_device_type(pdev))
		return false;

	if (!IS_HSW(pdev)) {
		vgt_err("Unsupported gen_dev_type(%s)!\n",
			IS_IVB(pdev) ?
			"IVB" : "SNB(or unknown GEN types)");
		return false;
	}

	/* check PPGTT enabling. */
	if (IS_IVB(pdev) || IS_HSW(pdev))
		pdev->enable_ppgtt = 1;

	INIT_LIST_HEAD(&pdev->rendering_runq_head);
	INIT_LIST_HEAD(&pdev->rendering_idleq_head);

	pdev->max_engines = 3;
	pdev->ring_mmio_base[RING_BUFFER_RCS] = _REG_RCS_TAIL;
	pdev->ring_mmio_base[RING_BUFFER_VCS] = _REG_VCS_TAIL;
	pdev->ring_mmio_base[RING_BUFFER_BCS] = _REG_BCS_TAIL;

	pdev->ring_mi_mode[RING_BUFFER_RCS] = _REG_RCS_MI_MODE;
	pdev->ring_mi_mode[RING_BUFFER_VCS] = _REG_VCS_MI_MODE;
	pdev->ring_mi_mode[RING_BUFFER_BCS] = _REG_BCS_MI_MODE;

	pdev->ring_xxx[RING_BUFFER_RCS] = 0x2050;
	pdev->ring_xxx[RING_BUFFER_VCS] = 0x12050;
	pdev->ring_xxx[RING_BUFFER_BCS] = 0x22050;
	pdev->ring_xxx_bit[RING_BUFFER_RCS] = 3;
	pdev->ring_xxx_bit[RING_BUFFER_VCS] = 3;
	pdev->ring_xxx_bit[RING_BUFFER_BCS] = 3;
	/* this check is broken on SNB */
	pdev->ring_xxx_valid = 0;

	if (IS_HSW(pdev)) {
		pdev->max_engines = 4;
		pdev->ring_mmio_base[RING_BUFFER_VECS] = _REG_VECS_TAIL;
		pdev->ring_mi_mode[RING_BUFFER_VECS] = _REG_VECS_MI_MODE;
		pdev->ring_xxx[RING_BUFFER_RCS] = 0x8000;
		pdev->ring_xxx[RING_BUFFER_VCS] = 0x8000;
		pdev->ring_xxx[RING_BUFFER_BCS] = 0x8000;
		pdev->ring_xxx[RING_BUFFER_VECS] = 0x8008;
		pdev->ring_xxx_bit[RING_BUFFER_RCS] = 0;
		pdev->ring_xxx_bit[RING_BUFFER_VCS] = 1;
		pdev->ring_xxx_bit[RING_BUFFER_BCS] = 2;
		pdev->ring_xxx_bit[RING_BUFFER_VECS] = 10;
		pdev->ring_xxx_valid = 1;
	}

	bitmap_zero(pdev->dpy_emul_request, VGT_MAX_VMS);

	/* initialize ports */
	memset(pdev->ports, 0, sizeof(struct gt_port) * I915_MAX_PORTS);
	for (i = 0; i < I915_MAX_PORTS; i ++) {
		pdev->ports[i].type = VGT_PORT_MAX;
		pdev->ports[i].cache.type = VGT_PORT_MAX;
		pdev->ports[i].port_override = i;
		pdev->ports[i].physcal_port = i;
	}

	if (!initial_phys_states(pdev)) {
		printk("vGT: failed to initialize physical state\n");
		return false;
	}

	pdev->reg_info = vzalloc (pdev->reg_num * sizeof(reg_info_t));
	if (!pdev->reg_info) {
		printk("vGT: failed to allocate reg_info\n");
		return false;
	}

	initialize_gm_fence_allocation_bitmaps(pdev);

	vgt_setup_reg_info(pdev);
	vgt_post_setup_mmio_hooks(pdev);
	if (vgt_irq_init(pdev) != 0) {
		printk("vGT: failed to initialize irq\n");
		return false;
	}

	bitmap_zero(pdev->v_force_wake_bitmap, VGT_MAX_VMS);
	spin_lock_init(&pdev->v_force_wake_lock);

	vgt_init_reserved_aperture(pdev);

	for (i = 0; i < pdev->max_engines; i++)
		vgt_ring_init(pdev, i);

	perf_pgt = pdev;
	return true;
}

/*
 * Initialize the vgt driver.
 *  return 0: success
 *	-1: error
 */
int vgt_initialize(struct pci_dev *dev)
{
	struct pgt_device *pdev = &default_device;
	struct task_struct *p_thread;
	vgt_params_t vp;

	if (!vgt_enabled)
		return -1;

	spin_lock_init(&pdev->lock);

	if (!vgt_initialize_pgt_device(dev, pdev))
		return -EINVAL;

	if (vgt_cmd_parser_init(pdev) < 0)
		goto err;

	mutex_init(&pdev->hpd_work.hpd_mutex);
	INIT_WORK(&pdev->hpd_work.work, vgt_hotplug_udev_notify_func);
	
	/* create debugfs interface */
	if (!vgt_init_debugfs(pdev)) {
		printk("vGT:failed to create debugfs\n");
		goto err;
	}

	/* init all mmio_device */
	vgt_init_mmio_device(pdev);

	/* create domain 0 instance */
	vp.vm_id = 0;
	vp.aperture_sz = dom0_low_gm_sz;
	vp.gm_sz = dom0_low_gm_sz + dom0_high_gm_sz;
	vp.fence_sz = dom0_fence_sz;
	vp.vgt_primary = 1; /* this isn't actually used for dom0 */
	if (create_vgt_instance(pdev, &vgt_dom0, vp) < 0)
		goto err;

	pdev->owner[VGT_OT_DISPLAY] = vgt_dom0;
	vgt_dbg(VGT_DBG_GENERIC, "create dom0 instance succeeds\n");

	//show_mode_settings(pdev);

	if (setup_gtt(pdev))
		goto err;

	vgt_ops = &vgt_xops;
	vgt_ops->initialized = true;

	if (!hvm_render_owner)
		current_render_owner(pdev) = vgt_dom0;
	else
		vgt_ctx_switch = 0;

	if (!hvm_display_owner) {
		current_display_owner(pdev) = vgt_dom0;
		current_foreground_vm(pdev) = vgt_dom0;
	}

	if (hvm_super_owner) {
		ASSERT(hvm_render_owner);
		ASSERT(hvm_display_owner);
		ASSERT(hvm_boot_foreground);
	} else {
		current_config_owner(pdev) = vgt_dom0;
	}

	pdev->ctx_check = 0;
	pdev->ctx_switch = 0;
	pdev->magic = 0;

	init_waitqueue_head(&pdev->event_wq);
	init_waitqueue_head(&pdev->destroy_wq);

	pdev->device_reset_flags = 0;

	p_thread = kthread_run(vgt_thread, pdev, "vgt_main");
	if (!p_thread) {
		goto err;
	}
	pdev->p_thread = p_thread;
	//show_debug(pdev, 0);

	vgt_initialize_ctx_scheduler(pdev);

	list_add(&pdev->list, &pgt_devices);

	vgt_init_sysfs(pdev);

	vgt_init_fb_notify();

	printk("vgt_initialize succeeds.\n");
	return 0;
err:
	printk("vgt_initialize failed.\n");
	vgt_destroy();
	return -1;
}

void vgt_destroy(void)
{
	struct list_head *pos, *next;
	struct vgt_device *vgt;
	struct pgt_device *pdev = &default_device;
	int i;

	vgt_cleanup_mmio_dev(pdev);

	perf_pgt = NULL;
	list_del(&pdev->list);

	vgt_cleanup_ctx_scheduler(pdev);

	/* do we need the thread actually stopped? */
	kthread_stop(pdev->p_thread);

	vgt_irq_exit(pdev);

	/* Deactive all VGTs */
	while ( !list_empty(&pdev->rendering_runq_head) ) {
		list_for_each (pos, &pdev->rendering_runq_head) {
			vgt = list_entry (pos, struct vgt_device, list);
			vgt_disable_render(vgt);
		}
	};

	/* Destruct all vgt_debugfs */
	vgt_release_debugfs();

	vgt_destroy_sysfs();
	if (pdev->saved_gtt)
		vfree(pdev->saved_gtt);
	free_gtt(pdev);

	if (pdev->gmadr_va)
		iounmap(pdev->gmadr_va);
	if (pdev->opregion_va)
		iounmap(pdev->opregion_va);

	while ( !list_empty(&pdev->rendering_idleq_head)) {
		for (pos = pdev->rendering_idleq_head.next;
			pos != &pdev->rendering_idleq_head; pos = next) {
			next = pos->next;
			vgt = list_entry (pos, struct vgt_device, list);
			vgt_release_instance(vgt);
		}
	}
	vgt_clear_mmio_table();
	vfree(pdev->reg_info);
	vfree(pdev->initial_mmio_state);

	for (i = 0; i < I915_MAX_PORTS; ++ i) {
		if (pdev->ports[i].edid) {
			kfree(pdev->ports[i].edid);
			pdev->ports[i].edid = NULL;
		}

		if (pdev->ports[i].dpcd) {
			kfree(pdev->ports[i].dpcd);
			pdev->ports[i].dpcd = NULL;
		}

		if (pdev->ports[i].cache.edid) {
			kfree(pdev->ports[i].cache.edid);
			pdev->ports[i].cache.edid = NULL;
		}
	}

	vgt_cmd_parser_exit();
}

int vgt_suspend(struct pci_dev *pdev)
{
	struct pgt_device *node, *pgt = NULL;

	if (!vgt_in_host())
		return 0;

	if (list_empty(&pgt_devices)) {
		printk("vGT: no valid pgt_device registered at suspend\n");
		return 0;
	}

	list_for_each_entry(node, &pgt_devices, list) {
		if (node->pdev == pdev) {
			pgt = node;
			break;
		}
	}

	if (!pgt) {
		printk("vGT: no matching pgt_device at suspend\n");
		return 0;
	}

	vgt_info("Suspending vGT driver...\n");

	/* TODO: check vGT instance state */
	/* ... */

	pgt->saved_rrmr = VGT_MMIO_READ(pgt, _REG_DE_RRMR);

	/* save GTT and FENCE information */
	vgt_save_gtt_and_fence(pgt);

	vgt_reset_dom0_ppgtt_state();

	vgt_xops.boot_time = true;

	return 0;
}
EXPORT_SYMBOL(vgt_suspend);

int vgt_resume(struct pci_dev *pdev)
{
	struct pgt_device *node, *pgt = NULL;

	if (!vgt_in_host())
		return 0;


	if (list_empty(&pgt_devices)) {
		printk("vGT: no valid pgt_device registered at resume\n");
		return 0;
	}

	list_for_each_entry(node, &pgt_devices, list) {
		if (node->pdev == pdev) {
			pgt = node;
			break;
		}
	}

	if (!pgt) {
		printk("vGT: no matching pgt_device at resume\n");
		return 0;
	}

	vgt_info("Resuming vGT driver...\n");

	/* restore GTT table and FENCE regs */
	vgt_restore_gtt_and_fence(pgt);

	VGT_MMIO_WRITE(pgt, _REG_DE_RRMR, pgt->saved_rrmr);

	/* redo the MMIO snapshot */
	vgt_initial_mmio_setup(pgt);

	/* XXX: need redo the PCI config space snapshot too? */

	/*
	 * TODO: need a better place to sync vmmio state
	 * for now, force override dom0's vmmio only. other
	 * VMs are supposed to be paused.
	 */
	state_sreg_init(vgt_dom0);
	state_vreg_init(vgt_dom0);

	/* TODO, GMBUS inuse bit? */

	spin_lock(&pgt->lock);

	recalculate_and_update_imr(pgt, _REG_DEIMR);
	recalculate_and_update_imr(pgt, _REG_GTIMR);
	recalculate_and_update_imr(pgt, _REG_PMIMR);
	recalculate_and_update_imr(pgt, _REG_SDEIMR);

	recalculate_and_update_imr(pgt, _REG_RCS_IMR);
	recalculate_and_update_imr(pgt, _REG_BCS_IMR);
	recalculate_and_update_imr(pgt, _REG_VCS_IMR);

	if (IS_HSW(pgt))
		recalculate_and_update_imr(pgt, _REG_VECS_IMR);

	recalculate_and_update_ier(pgt, _REG_GTIER);
	recalculate_and_update_ier(pgt, _REG_PMIER);
	recalculate_and_update_ier(pgt, _REG_SDEIER);

	spin_unlock(&pgt->lock);

	vgt_xops.boot_time = false;

	return 0;
}
EXPORT_SYMBOL(vgt_resume);

static void do_device_reset(struct pgt_device *pdev)
{
	struct drm_device *drm_dev = pci_get_drvdata(pdev->pdev);
	vgt_reg_t head, tail, start, ctl;
	vgt_reg_t ier, imr, iir, isr;
	int i;

	vgt_info("Request DOM0 to reset device.\n");

	ASSERT(drm_dev);

	set_bit(WAIT_RESET, &vgt_dom0->reset_flags);

	i915_handle_error(drm_dev, true);

	i915_wait_error_work_complete(drm_dev);

	/*
	 * User may set i915.reset=0 in kernel command line, which will
	 * disable the reset logic of i915, without that logics we can
	 * do nothing, so we panic here and let user remove that parameters.
	 */
	if (test_bit(WAIT_RESET, &vgt_dom0->reset_flags)) {
		vgt_err("DOM0 GPU reset didn't happen?.\n");
		vgt_err("Maybe you set i915.reset=0 in kernel command line? Panic the system.\n");
		ASSERT(0);
	}

	vgt_info("GPU ring status:\n");

	for (i = 0; i < pdev->max_engines; i++) {
		head = VGT_READ_HEAD(pdev, i);
		tail = VGT_READ_TAIL(pdev, i);
		start = VGT_READ_START(pdev, i);
		ctl = VGT_READ_CTL(pdev, i);

		vgt_info("RING %d: H: %x T: %x S: %x C: %x.\n",
				i, head, tail, start, ctl);
	}

	ier = VGT_MMIO_READ(pdev, _REG_DEIER);
	iir = VGT_MMIO_READ(pdev, _REG_DEIIR);
	imr = VGT_MMIO_READ(pdev, _REG_DEIMR);
	isr = VGT_MMIO_READ(pdev, _REG_DEISR);

	vgt_info("DE: ier: %x iir: %x imr: %x isr: %x.\n",
			ier, iir, imr, isr);

	vgt_info("Finish.\n");

	return;
}

int vgt_handle_dom0_device_reset(void)
{
	struct pgt_device *pdev = &default_device;
	struct drm_device *drm_dev;

	unsigned long flags;
	int cpu;

	int id;
	bool rc;

	if (!xen_initial_domain() || !vgt_enabled)
		return 0;

	vgt_info("DOM0 hangcheck timer request reset device.\n");

	drm_dev = pci_get_drvdata(pdev->pdev);
	ASSERT(drm_dev);

	vgt_lock_dev_flags(pdev, cpu, flags);
	rc = idle_rendering_engines(pdev, &id);
	vgt_unlock_dev_flags(pdev, cpu, flags);

	if (!rc) {
		vgt_info("Really hung, request to reset device.\n");
		vgt_raise_request(pdev, VGT_REQUEST_DEVICE_RESET);
	} else {
		vgt_info("Not really hung, continue DOM0 reset sequence.\n");
		i915_handle_error(drm_dev, true);
	}

	return 0;
}

int vgt_reset_device(struct pgt_device *pdev)
{
	struct vgt_device *vgt;
	struct list_head *pos, *n;
	unsigned long ier;
	unsigned long flags;
	int i;

	if (get_seconds() - vgt_dom0->last_reset_time < 6) {
		vgt_err("Try to reset device too fast.\n");
		return -EAGAIN;
	}

	if (test_and_set_bit(DEVICE_RESET_INPROGRESS,
				&pdev->device_reset_flags)) {
		vgt_err("Another device reset has been already running.\n");
		return -EBUSY;
	}

	vgt_info("Stop VGT context switch.\n");

	vgt_cleanup_ctx_scheduler(pdev);

	current_render_owner(pdev) = vgt_dom0;

	current_foreground_vm(pdev) = vgt_dom0;

	spin_lock_irqsave(&pdev->lock, flags);

	list_for_each_safe(pos, n, &pdev->rendering_runq_head) {
		vgt = list_entry(pos, struct vgt_device, list);

		if (vgt->vm_id) {
			for (i = 0; i < pdev->max_engines; i++) {
				if (test_bit(i, (void *)vgt->enabled_rings)) {
					vgt_info("VM %d: disable ring %d\n", vgt->vm_id, i);

					vgt_disable_ring(vgt, i);

					set_bit(i, &vgt->enabled_rings_before_reset);
				}
			}

			set_bit(WAIT_RESET, &vgt->reset_flags);
		}
	}

	spin_unlock_irqrestore(&pdev->lock, flags);

	vgt_info("Disable master interrupt.\n");

	vgt_get_irq_lock(pdev, flags);

	VGT_MMIO_WRITE(pdev, _REG_DEIER,
			VGT_MMIO_READ(pdev, _REG_DEIER) & ~_REGBIT_MASTER_INTERRUPT);

	vgt_put_irq_lock(pdev, flags);

	do_device_reset(pdev);

	vgt_info("Restart VGT context switch.\n");

	vgt_initialize_ctx_scheduler(pdev);

	clear_bit(DEVICE_RESET_INPROGRESS, &pdev->device_reset_flags);

	spin_lock_irqsave(&pdev->lock, flags);
	vgt_get_irq_lock(pdev, flags);

	ier = vgt_recalculate_ier(pdev, _REG_DEIER);
	VGT_MMIO_WRITE(pdev, _REG_DEIER, ier);

	vgt_put_irq_lock(pdev, flags);

	spin_unlock_irqrestore(&pdev->lock, flags);

	vgt_info("Enable master interrupt, DEIER: %lx\n", ier);

	return 0;
}

/* for GFX driver */
int i915_start_vgt(struct pci_dev *pdev)
{
	if (!vgt_in_host())
		return 1;

	if (vgt_xops.initialized) {
		vgt_info("VGT has been intialized?\n");
		return 1;
	}

	return vgt_initialize(pdev);
}
EXPORT_SYMBOL(i915_start_vgt);

static void vgt_param_check(void)
{
	/* TODO: hvm_display/render_owner are broken */
	if (hvm_super_owner) {
		hvm_display_owner = true;
		hvm_render_owner = true;
		hvm_boot_foreground = true;
	}

	if (hvm_display_owner) {
		hvm_boot_foreground = true;
	}

	if (hvm_dpy_owner) {
		vgt_warn("hvm_dpy_owner is deprecated option! "
			 "Please use hvm_boot_foreground or hvm_display_owner instead!\n");
	}

	/* see the comment where dom0_low_gm_sz is defined */
	if (dom0_low_gm_sz > 512 - 64)
		dom0_low_gm_sz = 512 - 64;

	if (dom0_low_gm_sz + dom0_high_gm_sz > 2048)
		dom0_high_gm_sz = 2048 - dom0_low_gm_sz;

	if (dom0_fence_sz > 16)
		dom0_fence_sz = 16;
}

static int __init vgt_init_module(void)
{
	if (!vgt_in_host())
		return 0;

	vgt_param_check();

	vgt_klog_init();

	return 0;
}
module_init(vgt_init_module);

static void __exit vgt_exit_module(void)
{
	if (!vgt_in_host())
		return;

	// fill other exit works here
	vgt_destroy();
	vgt_klog_cleanup();
	return;
}
module_exit(vgt_exit_module);
