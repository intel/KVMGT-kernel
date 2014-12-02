#ifndef _I915_MEDIATE_H_
#define _I915_MEDIATE_H_

#include <linux/kernel.h>
#include <linux/types.h>
#include "i915_drv.h"

/* MMIO mediation */
struct drm_i915_private;
#define i915_hm_read(x, y)						\
u##x i915_hm_read##y(uint64_t vav, u32 reg);
i915_hm_read(8, b)
i915_hm_read(16, w)
i915_hm_read(32, l)
i915_hm_read(64, q)
#undef i915_hm_read

#define i915_hm_write(x, y)						\
u##x i915_hm_write##y(u##x *val, uint64_t vav, u32 reg);
i915_hm_write(8, b)
i915_hm_write(16, w)
i915_hm_write(32, l)
i915_hm_write(64, q)
#undef i915_hm_write

#endif /* _I915_MEDIATE_H_ */

