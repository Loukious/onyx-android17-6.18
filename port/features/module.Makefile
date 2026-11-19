# SPDX-License-Identifier: GPL-2.0-only
# Kleaf invokes the default goal here, then modules_install. The kernel reads
# Kbuild for the object list; keep the official nested SUSFS Makefile intact.
.PHONY: modules modules_install clean compile_commands.json
modules modules_install clean compile_commands.json:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) $(KBUILD_OPTIONS) KBUILD_MODPOST_WARN=1 $(@)
