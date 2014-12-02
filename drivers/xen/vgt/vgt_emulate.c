/*
 * vGT instruction emulator
 * Copyright (c) 2011, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <asm/bitops.h>
#include <asm/ptrace.h>
#include <asm/traps.h>

#include "vgt.h"

#include <linux/init.h>
#include <linux/page-flags.h>

#define FORCEWAKE_ACK_HSW			0x130044
#define FORCEWAKE_MT				0xa188
#define FORCEWAKE_MT_ENABLE			(1<<5)
#define ECOBUS					0xa180
#define GTFIFODBG				0x120000
#define GT_FIFO_CPU_ERROR_MASK			7

#define GEN6_GT_THREAD_STATUS_REG		0x13805c
#define GEN6_GT_THREAD_STATUS_CORE_MASK_HSW	(0x7 | (0x07 << 16))
#define wait_for_atomic_us(COND, US) ({ \
	int i, ret__ = -1;      	\
	for (i = 0; i < (US); i++) {    \
		if ((COND)) {           \
			ret__ = 0;      \
			break;          \
		}                       \
		udelay(1);              \
	}                               \
	ret__;                          \
})
#define VGT_REG_READ(pdev, offset)		*((const volatile u32 *)(pdev->gttmmio_base_va + offset))
#define VGT_REG_WRITE(pdev, offset, val)	*((volatile u32 *)(pdev->gttmmio_base_va + offset)) = (val)
static void gen7_force_wake_mt_get(struct pgt_device *pdev)
{
	int forcewake_ack = FORCEWAKE_ACK_HSW;
	u32 gt_thread_status_mask = GEN6_GT_THREAD_STATUS_CORE_MASK_HSW;

	if (wait_for_atomic_us((VGT_REG_READ(pdev, forcewake_ack) & 1) == 0, 500))
		WARN(1, "Force wake wait timed out\n");

	VGT_REG_WRITE(pdev, FORCEWAKE_MT, _MASKED_BIT_ENABLE(1));
	VGT_REG_READ(pdev, ECOBUS);

	if (wait_for_atomic_us((VGT_REG_READ(pdev, forcewake_ack) & 1), 500))
		WARN(1, "Force wake wait timed out\n");

	/* emulate: gen6_wait_for_thread_c0() */
	if (wait_for_atomic_us((VGT_REG_READ(pdev, GEN6_GT_THREAD_STATUS_REG) & gt_thread_status_mask) == 0, 500))
		WARN(1, "Force wake wait timed out\n");
}

static void gen7_force_wake_mt_put(struct pgt_device *pdev)
{
	u32 gtfifodbg;

	VGT_REG_WRITE(pdev, FORCEWAKE_MT, _MASKED_BIT_DISABLE(1));
	VGT_REG_READ(pdev, ECOBUS);
	/* emulate: gen6_gt_check_fifodbg() */
	gtfifodbg = VGT_REG_READ(pdev, GTFIFODBG);
	if (gtfifodbg & GT_FIFO_CPU_ERROR_MASK) {
		WARN(1, "MMIO read or write has been dropped %x\n", gtfifodbg);
		VGT_REG_WRITE(pdev, GTFIFODBG, GT_FIFO_CPU_ERROR_MASK);
	}
}

void tmp_vgt_force_wake_get(struct pgt_device *pdev)
{
	//gen7_force_wake_mt_get(pdev);
}

void tmp_vgt_force_wake_put(struct pgt_device *pdev)
{
	//gen7_force_wake_mt_put(pdev);
}

void tmp_vgt_force_wake_setup(struct pgt_device *pdev)
{
	int ecobus;
	gen7_force_wake_mt_get(pdev);
	ecobus = VGT_REG_READ(pdev, ECOBUS);
	gen7_force_wake_mt_put(pdev);

	if (ecobus & FORCEWAKE_MT_ENABLE) {
		DPRINT("Using MT force wake\n");
	} else {
		BUG();
	}

	/* enable forever */
	gen7_force_wake_mt_get(pdev);
}
