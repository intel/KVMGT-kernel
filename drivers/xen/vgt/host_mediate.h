#ifndef _VGT_HOST_MEDIATE_H_
#define _VGT_HOST_MEDIATE_H_

#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/percpu.h>
#include <drm/drmP.h>

#define ERROR(fmt, ...) \
	printk("%s()-%d: jike: "fmt, __func__, __LINE__, ##__VA_ARGS__);
#if 1
#define DPRINT ERROR
#else
#define DPRINT do {} while (0)
#endif


extern struct pgt_device *igd_pgt;


bool vgt_hm_emulate_read(uint64_t vab, u32 reg, void *val, int bytes);
bool vgt_hm_emulate_write(uint64_t vab, u32 reg, void *val, int bytes);
void kick_off_i915_isr(int irq);

/* inline functions */
void tmp_vgt_force_wake_get(struct pgt_device *pdev);
void tmp_vgt_force_wake_put(struct pgt_device *pdev);
void tmp_vgt_force_wake_setup(struct pgt_device *pdev);


bool native_mmio_read(uint64_t va, int bytes, void *val);
bool native_mmio_write(uint64_t va, int bytes, unsigned long val);

#endif /* _VGT_HOST_MEDIATE_H_ */
