# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_BBG) += bbg.o
bbg-y := baseband_guard.o blkdev_helper.o tracing/tracing.o

ccflags-y += -I$(srctree)/security/selinux/include -I$(obj) -I$(srctree)/block
ccflags-y += -DBB_HAS_IOCTL_COMPAT -DBB_HAS_SELINUX_STATE
ccflags-y += -DBBG_COMPAT_SELINUX_CRED -DBBG_COMPAT_HAS_BLOCK_DEVICE_API
ccflags-y += -DBBG_USE_DEFINE_LSM
ccflags-y += -DBBG_VERSION=\"028ff7fd\"
ccflags-y += -DBBG_REPO=\"https://github.com/vc-teahouse/Baseband-guard\"

# Generate SELinux class IDs locally using the same source/class map as
# SELinux. Kbuild tracks inputs; no git/network or parse-time shell mutation.
hostprogs := genheaders
HOST_EXTRACFLAGS += -I$(srctree)/security/selinux/include
targets += flask.h av_permissions.h
quiet_cmd_bbg_genhdrs = GEN     $(obj)/flask.h
      cmd_bbg_genhdrs = $< $(obj)/flask.h $(obj)/av_permissions.h
$(obj)/flask.h: $(obj)/genheaders FORCE
	$(call if_changed,bbg_genhdrs)
$(addprefix $(obj)/,$(bbg-y)): $(obj)/flask.h
