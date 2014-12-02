VGT_SOURCE := vgt.o render.o mmio.o handlers.o interrupt.o  \
	sysfs.o display.o debugfs.o edid.o gtt.o aperture_gm.o utility.o \
	klog.o dev.o cmd_parser.o sched.o instance.o cfg_space.o hypercall.o \
	fb_decoder.o vbios.o host_mediate.o

ccflags-y				:= -I$(src) -Wall -Werror -Idrivers/gpu/drm/i915
ccflags-$(CONFIG_KVMGT)			+= -Ivirt/kvm
xen_vgt-y				:= $(VGT_SOURCE)
xen_vgt-y				+= vgt_emulate.o
obj-$(CONFIG_I915_VGT)		+= xen_vgt.o
