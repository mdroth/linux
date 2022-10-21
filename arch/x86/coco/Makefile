# SPDX-License-Identifier: GPL-2.0
CFLAGS_REMOVE_core.o	= -pg
KASAN_SANITIZE_core.o	:= n
CFLAGS_core.o		+= -fno-stack-protector

obj-$(CONFIG_ARCH_HAS_CC_PLATFORM) += core.o

obj-$(CONFIG_INTEL_TDX_GUEST)	+= tdx/
obj-$(CONFIG_KVM_AMD_SEV)	+= sev/
