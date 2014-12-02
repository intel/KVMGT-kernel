#include <linux/io.h>
#include <drm/drmP.h>
#include "host_mediate.h"

#include "vgt.h"

bool native_mmio_read(uint64_t va, int bytes, void *val)
{
	switch (bytes) {
		case 1:
			*(u8 *)val = readb((void *)va);
			break;
		case 2:
			*(u16 *)val = readw((void *)va);
			break;
		case 4:
			*(u32 *)val = readl((void *)va);
			break;
		case 8:
			*(u64 *)val = readq((void *)va);
			break;
		default:
			ERROR("your bytes is wrong: %d\n", bytes);
			return false;
	}

	return true;
}

bool vgt_hm_emulate_read(uint64_t vab, u32 reg, void *val, int bytes)
{
	uint64_t va = vab + reg;
	uint64_t pa;
	bool ret;

	if (reg >= VGT_MMIO_SPACE_SZ) {
		va -= VGT_MMIO_SPACE_SZ;
	}

	if (vgt_ops && vgt_ops->initialized) {
		pa = _vgt_mmio_pa(vgt_dom0->pdev, reg);
		ret = vgt_ops->mem_read(vgt_dom0, pa, val, bytes);
		goto out;
	}

	/* old school */
	return native_mmio_read(va, bytes, &val);

out:
	return ret;
}

bool native_mmio_write(uint64_t va, int bytes, unsigned long val)
{

	switch (bytes) {
		case 1:
			writeb((u8)val, (void *)va);
			break;
		case 2:
			writew((u16)val, (void *)va);
			break;
		case 4:
			writel((u32)val, (void *)va);
			break;
		case 8:
			writeq((u64)val, (void *)va);
			break;
		default:
			ERROR("your bytes is wrong: %d\n", bytes);
			return false;
	}
	return true;
}

bool vgt_hm_emulate_write(uint64_t vab, u32 reg, void *val, int bytes)
{
	uint64_t va = vab + reg;
	uint64_t pa;
	bool ret;

	if (reg >= VGT_MMIO_SPACE_SZ) {
		va -= VGT_MMIO_SPACE_SZ;
	}

	if (vgt_ops && vgt_ops->initialized) {
		pa = _vgt_mmio_pa(vgt_dom0->pdev, reg);
		ret = vgt_ops->mem_write(vgt_dom0, pa, val, bytes);
		goto out;
	}

	/* old school */
	return native_mmio_write(va, bytes, *(unsigned long *)val);

out:
	return ret;
}

struct pgt_device *igd_pgt = NULL;
void kick_off_i915_isr(int irq)
{
	struct drm_device *dev;
	if (unlikely(igd_pgt == NULL)) {
		ERROR("FIXME: igd_pgt is NULL!\n");
		return;
	}

	dev = pci_get_drvdata(igd_pgt->pdev);
	i915_isr_schedule(dev);
}
