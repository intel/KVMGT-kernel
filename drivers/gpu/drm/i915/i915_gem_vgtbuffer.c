/*
 * Copyright © 2012 Intel Corporation
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include "drmP.h"
#include "i915_drm.h"
#include "i915_drv.h"
#include "i915_trace.h"
#include "intel_drv.h"
#include <linux/mmu_notifier.h>
#include <linux/swap.h>

#include "fb_decoder.h"

static struct i915_gem_vgtbuffer_object *to_vgtbuffer_object(struct drm_i915_gem_object *obj)
{
	return container_of(obj, struct i915_gem_vgtbuffer_object, gem);
}

#if defined(CONFIG_MMU_NOTIFIER)
static void i915_gem_vgtbuffer_mn_invalidate_range_start(struct mmu_notifier *mn,
							   struct mm_struct *mm,
							   unsigned long start,
							   unsigned long end)
{
	struct i915_gem_vgtbuffer_object *vmap;
	struct drm_device *dev;

	/* XXX race between obj unref and mmu notifier? */
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_mn_invalidate_range_start\n");

	vmap = container_of(mn, struct i915_gem_vgtbuffer_object, mn);
	BUG_ON(vmap->mm != mm);

	if (vmap->user_ptr >= end || vmap->user_ptr + vmap->user_size <= start)
		return;

	if (vmap->gem.pages == NULL) /* opportunistic check */
		return;

	dev = vmap->gem.base.dev;
	mutex_lock(&dev->struct_mutex);
	if (vmap->gem.gtt_space) {
		struct drm_i915_private *dev_priv = dev->dev_private;
		bool was_interruptible;
		int ret;

		was_interruptible = dev_priv->mm.interruptible;
		dev_priv->mm.interruptible = false;

		ret = i915_gem_object_unbind(&vmap->gem);
		BUG_ON(ret && ret != -EIO);

		dev_priv->mm.interruptible = was_interruptible;
	}

	BUG_ON(i915_gem_object_put_pages(&vmap->gem));
	mutex_unlock(&dev->struct_mutex);
}

static void i915_gem_vgtbuffer_mn_release(struct mmu_notifier *mn,
					struct mm_struct *mm)
{
	struct i915_gem_vgtbuffer_object *vmap;
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_mn_release\n");
	vmap = container_of(mn, struct i915_gem_vgtbuffer_object, mn);
	BUG_ON(vmap->mm != mm);
	vmap->mm = NULL;

	/* XXX Schedule an eventual unbind? E.g. hook into require request?
	 * However, locking will be complicated.
	 */
}

static const struct mmu_notifier_ops i915_gem_vgtbuffer_notifier = {
	.invalidate_range_start = i915_gem_vgtbuffer_mn_invalidate_range_start,
	.release = i915_gem_vgtbuffer_mn_release,
};

static void
i915_gem_vgtbuffer_release__mmu_notifier(struct i915_gem_vgtbuffer_object *vmap)
{
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_release_mmu_notifier\n");
	if (vmap->mn.ops && vmap->mm) {
		mmu_notifier_unregister(&vmap->mn, vmap->mm);
		BUG_ON(vmap->mm);
	}
}

static int
i915_gem_vgtbuffer_init__mmu_notifier(struct i915_gem_vgtbuffer_object *vmap,
					unsigned flags)
{
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_init_mmu_notifier\n");
	if (flags & I915_VGTBUFFER_UNSYNCHRONIZED)
		return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;

	vmap->mn.ops = &i915_gem_vgtbuffer_notifier;
	return mmu_notifier_register(&vmap->mn, vmap->mm);
}

#else

static void
i915_gem_vgtbuffer_release__mmu_notifier(struct i915_gem_vgtbuffer_object *vmap)
{
}

static int
i915_gem_vgtbuffer_init__mmu_notifier(struct i915_gem_vgtbuffer_object *vmap,
					unsigned flags)
{
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_init_mmu_notifier\n");
	if ((flags & I915_VGTBUFFER_UNSYNCHRONIZED) == 0)
		return -ENODEV;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return 0;
}
#endif

static int
i915_gem_vgtbuffer_get_pages(struct drm_i915_gem_object *obj)
{
	struct i915_gem_vgtbuffer_object *vmap = to_vgtbuffer_object(obj);
	int num_pages = obj->base.size >> PAGE_SHIFT;
	struct sg_table *st;
	struct scatterlist *sg;
	struct page **pvec;
	int n, pinned, ret;
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_get_pages\n");
	if (vmap->mm == NULL)
		return -EFAULT;

	if (!access_ok(vmap->read_only ? VERIFY_READ : VERIFY_WRITE,
			   (char __user *)vmap->user_ptr, vmap->user_size))
		return -EFAULT;

	obj->has_vmfb_mapping=true;

	/* If userspace should engineer that these pages are replaced in
	 * the vma between us binding this page into the GTT and completion
	 * of rendering... Their loss. If they change the mapping of their
	 * pages they need to create a new bo to point to the new vma.
	 *
	 * However, that still leaves open the possibility of the vma
	 * being copied upon fork. Which falls under the same userspace
	 * synchronisation issue as a regular bo, except that this time
	 * the process may not be expecting that a particular piece of
	 * memory is tied to the GPU.
	 *
	 * Fortunately, we can hook into the mmu_notifier in order to
	 * discard the page references prior to anything nasty happening
	 * to the vma (discard or cloning) which should prevent the more
	 * egregious cases from causing harm.
	 */

	pvec = kmalloc(num_pages*sizeof(struct page *),
			   GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
	if (pvec == NULL) {
		pvec = drm_malloc_ab(num_pages, sizeof(struct page *));
		if (pvec == NULL)
			return -ENOMEM;
	}

	pinned = 0;
	if (vmap->mm == current->mm)
		pinned = __get_user_pages_fast(vmap->user_ptr, num_pages,
						   !vmap->read_only, pvec);
	if (pinned < num_pages) {
		struct mm_struct *mm = vmap->mm;
		ret = 0;
		mutex_unlock(&obj->base.dev->struct_mutex);
		down_read(&mm->mmap_sem);
		if (vmap->mm != NULL)
			ret = get_user_pages(current, mm,
						 vmap->user_ptr + (pinned << PAGE_SHIFT),
						 num_pages - pinned,
						 !vmap->read_only, 0,
						 pvec + pinned,
						 NULL);
		up_read(&mm->mmap_sem);
		mutex_lock(&obj->base.dev->struct_mutex);
		if (ret > 0)
			pinned += ret;

		if (obj->pages || pinned < num_pages) {
			ret = obj->pages ? 0 : -EFAULT;
			goto cleanup_pinned;
		}
	}

	st = kmalloc(sizeof(*st), GFP_KERNEL);
	if (st == NULL) {
		ret = -ENOMEM;
		goto cleanup_pinned;
	}

	if (sg_alloc_table(st, num_pages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto cleanup_st;
	}

	for_each_sg(st->sgl, sg, num_pages, n) {
		sg_set_page(sg, pvec[n], PAGE_SIZE, 0);
	}
	drm_free_large(pvec);

	obj->pages = st;
	return 0;

cleanup_st:
	kfree(st);
cleanup_pinned:
	release_pages(pvec, pinned, 0);
	drm_free_large(pvec);
	return ret;
}

static void
i915_gem_vgtbuffer_put_pages(struct drm_i915_gem_object *obj)
{
	struct scatterlist *sg;
	int i;
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_get_put_pages\n");
	if (obj->madv != I915_MADV_WILLNEED)
		obj->dirty = 0;

	for_each_sg(obj->pages->sgl, sg, obj->pages->nents, i) {
		struct page *page = sg_page(sg);

		if (obj->dirty)
			set_page_dirty(page);

		mark_page_accessed(page);
		page_cache_release(page);
	}
	obj->dirty = 0;

	sg_free_table(obj->pages);
	kfree(obj->pages);
}

static void
i915_gem_vgtbuffer_release(struct drm_i915_gem_object *obj)
{
	struct i915_gem_vgtbuffer_object *vmap = to_vgtbuffer_object(obj);
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_release\n");
	i915_gem_vgtbuffer_release__mmu_notifier(vmap);
}

static const struct drm_i915_gem_object_ops i915_gem_vgtbuffer_ops = {
	.get_pages = i915_gem_vgtbuffer_get_pages,
	.put_pages = i915_gem_vgtbuffer_put_pages,
	.release = i915_gem_vgtbuffer_release,
};

/**
 * Creates a new mm object that wraps some user memory.
 */
int
i915_gem_vgtbuffer_ioctl(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct drm_i915_gem_vgtbuffer *args = data;
	struct i915_gem_vgtbuffer_object *obj;
	struct vgt_primary_plane_format *p;
	struct vgt_cursor_plane_format *c;
	struct vgt_fb_format *fb;
	struct vgt_pipe_format *pipe;

	int ret;

	loff_t first_data_page, last_data_page;
	int num_pages = 0;

	u32 vmid;
	u32 handle;

	uint32_t __iomem *gtt_base = dev_priv->gtt.gsm;//mappable_base;
	uint32_t gtt_fbstart;
	uint32_t gtt_pte;

	/* Allocate the new object */
	DRM_DEBUG_DRIVER("VGT: gem_vgtbuffer_ioctl\n");
	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (obj == NULL)
		return -ENOMEM;

	vmid = args->vmid;
	DRM_DEBUG_DRIVER("VGT: calling decode\n");
	if(vgt_decode_fb_format(vmid, &obj->fb)) {
		kfree(obj);
		return -EINVAL;
	}

	fb = &obj->fb;
	pipe = ((args->pipe_id >= I915_MAX_PIPES) ?
				NULL : &fb->pipes[args->pipe_id]);

	/* If plane is not enabled, bail */
	if (!pipe || !pipe->primary.enabled) {
		kfree(obj);
		return -ENOENT;
	}
 
	DRM_DEBUG_DRIVER("VGT: pipe = %d\n", args->pipe_id);
	if((args->plane_id) == I915_VGT_PLANE_PRIMARY) {
	  DRM_DEBUG_DRIVER("VGT: &pipe=0x%x\n",(&pipe));
		p = &pipe->primary;
		args->enabled = p->enabled;
		args->x_offset = p->x_offset;
		args->y_offset = p->y_offset;
		args->start = p->base;
		args->width = p->width;
		args->height = p->height;
		args->stride = p->stride;
		args->bpp = p->bpp;
		args->hw_format = p->hw_format;
		args->drm_format = p->drm_format;
		args->tiled = p->tiled;
		args->size = (((p->width * p->height * p->bpp) / 8) +
				(PAGE_SIZE - 1)) >> PAGE_SHIFT;

		if(args->flags & I915_VGTBUFFER_QUERY_ONLY) {
			DRM_DEBUG_DRIVER("VGT: query only: primary");
			kfree(obj);
			return 0;
		}

		obj->gem.vmfb_gtt_offset = p->base;
		obj->gem.gtt_offset = p->base;
		num_pages = args->size;

		DRM_DEBUG_DRIVER("VGT GEM: Surface GTT Offset = %x\n",
				p->base);
		obj->gem.tiling_mode = p->tiled ? I915_TILING_X : 0;
		obj->gem.stride =  p->tiled ? args->stride : 0;
	}

	if((args->plane_id) == I915_VGT_PLANE_CURSOR) {
		c = &pipe->cursor;
		args->enabled = c->enabled;
		args->x_offset = c->x_hot;
		args->y_offset = c->y_hot;
		args->x_pos = c->x_pos;
		args->y_pos = c->y_pos;
		args->start = c->base;
		args->width = c->width;
		args->height = c->height;
		args->stride = c->width * (c->bpp / 8);
		args->bpp = c->bpp;
		args->tiled = 0;
		args->size = (((c->width * c->height * c->bpp) / 8) +
				(PAGE_SIZE-1)) >> PAGE_SHIFT;

		if(args->flags & I915_VGTBUFFER_QUERY_ONLY) {
			DRM_DEBUG_DRIVER("VGT: query only: cursor");
			kfree(obj);
			return 0;
		}

		obj->gem.vmfb_gtt_offset = c->base;
		obj->gem.gtt_offset = c->base;
		num_pages = args->size;

		DRM_DEBUG_DRIVER("VGT GEM: Surface GTT Offset = %x\n",
				c->base);
		obj->gem.tiling_mode = I915_TILING_NONE;
	}

	DRM_DEBUG_DRIVER("VGT GEM: Surface size = %d\n", (int) (num_pages * PAGE_SIZE));
	DRM_DEBUG_DRIVER("VGT: &obj=0x%x\n",&obj);
	DRM_DEBUG_DRIVER("VGT: &obj->gem=0x%x\n",&(obj->gem));
	DRM_DEBUG_DRIVER("VGT: &obj->gem.gttoffset=0x%x\n",&(obj->gem.gtt_offset));
	DRM_DEBUG_DRIVER("VGT: obj->gem.gttoffset=0x%x\n", obj->gem.gtt_offset);

	gtt_fbstart = obj->gem.gtt_offset / 0x1000;

	DRM_DEBUG_DRIVER("VGT GEM: gtt start addr %x\n", (unsigned int) gtt_base);
	DRM_DEBUG_DRIVER("VGT GEM: fb start %x\n", (unsigned int) gtt_fbstart);

	gtt_base += gtt_fbstart;

	DRM_DEBUG_DRIVER("VGT GEM: gtt + fb start  %x\n", (uint32_t) gtt_base);
	
	DRM_DEBUG_DRIVER("VGT: gtt_base=0x%x\n",gtt_base);

	gtt_pte = readl(gtt_base);

	DRM_DEBUG_DRIVER("VGT GEM: pte  %x\n", (uint32_t) gtt_pte);
	DRM_DEBUG_DRIVER("VGT GEM: num_pages from fb decode=%d  \n", (uint32_t) num_pages);
	
	/*DJC
	if (num_pages * PAGE_SIZE > dev_priv->mm.gtt_total) {
		kfree(obj);
		return -E2BIG;
	}
	*/
	if (args->flags & ~(I915_VGTBUFFER_READ_ONLY | I915_VGTBUFFER_UNSYNCHRONIZED)) {
		kfree(obj);
		return -EINVAL;
	}

	first_data_page = args->user_ptr / PAGE_SIZE;
	last_data_page = (args->user_ptr + args->user_size - 1) / PAGE_SIZE;
	num_pages = last_data_page - first_data_page + 1;

	DRM_DEBUG_DRIVER("VGT GEM: num_pages from vgtbuffer= %d\n",num_pages);

	/*DJC
	if (num_pages * PAGE_SIZE > dev_priv->mm.gtt_total) {
		kfree(obj);
		return -E2BIG;
	}
	*/
	if (drm_gem_private_object_init(dev, &obj->gem.base,
					num_pages * PAGE_SIZE)) {
		kfree(obj);
		return -ENOMEM;
	}

	i915_gem_object_init(&obj->gem, &i915_gem_vgtbuffer_ops);
	obj->gem.cache_level = I915_CACHE_LLC_MLC;

	//obj->gem.tiling_mode = I915_TILING_X;

	obj->gem.gtt_offset = 0;
	//obj->gem.gtt_offset = offset_in_page(args->user_ptr);
	obj->user_ptr = args->user_ptr;
	obj->user_size = args->user_size;
	obj->read_only = args->flags & I915_VGTBUFFER_READ_ONLY;

	obj->gem.has_vmfb_mapping = true;
	obj->gem.vmfb_start = gtt_base;

	/* And keep a pointer to the current->mm for resolving the user pages
	 * at binding. This means that we need to hook into the mmu_notifier
	 * in order to detect if the mmu is destroyed.
	 */
	obj->mm = current->mm;

	ret = i915_gem_vgtbuffer_init__mmu_notifier(obj, args->flags);
	if (ret) {
		kfree (obj);
		return ret;
	}

	ret = drm_gem_handle_create(file, &obj->gem.base, &handle);
	/* drop reference from allocate - handle holds it now */
	drm_gem_object_unreference(&obj->gem.base);
	if (ret) {
		kfree (obj);
		return ret;
	}

	args->handle = handle;
	return 0;
}
