#include "i915_drv.h"
#include "host_mediate.h"

/* MMIO mediation */
#define __i915_hm_read(x, y)						\
u##x i915_hm_read##y(uint64_t vab, u32 reg) {				\
	u##x val = 0;							\
	bool res = vgt_hm_emulate_read(vab, reg, &val, sizeof(u##x));	\
	if (!res)							\
		printk("vgt_hm_emulate_read failed\n");			\
	return (u##x)val;						\
}
__i915_hm_read(8, b)
__i915_hm_read(16, w)
__i915_hm_read(32, l)
__i915_hm_read(64, q)
#undef __i915_hm_read

#define __i915_hm_write(x, y)						\
u##x i915_hm_write##y(u##x *val, uint64_t vab, u32 reg) {		\
	bool res = vgt_hm_emulate_write(vab, reg, val, sizeof(u##x));	\
	if (!res)							\
		printk("vgt_hm_emulate_write failed\n");		\
	return 0;							\
}
__i915_hm_write(8, b)
__i915_hm_write(16, w)
__i915_hm_write(32, l)
__i915_hm_write(64, q)
#undef __i915_hm_write

