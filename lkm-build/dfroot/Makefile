# dfroot_boot.ko — dfroot-style bootstrap LKM (see dfroot_boot.c header note)
# Keep it tiny: -Os + no unwind tables, same flags as the proven minload Makefile.
#
# ★ Cross-compile flags must match build-lkm.sh verbatim:
#   ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-
#   (missing LLVM_IAS=1 makes arm64 inline asm compile as x86 ⇒
#     arch/arm64/include/asm/atomic_lse.h:369: unknown register name 'x0' in asm)
obj-m += dfroot_boot.o
CFLAGS_dfroot_boot.o := -Os -fno-asynchronous-unwind-tables -fno-unwind-tables

# ★ -mcmodel=large: without it the module gets "overflow in relocation type 275"
#   (R_AARCH64_PLT32, ±2GiB) between the module region and high kernel data
#   (verified on the minload module: 1497 overflows → 0).
KBUILD_CFLAGS += -mcmodel=large

KFLAGS := ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(KFLAGS) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $(KFLAGS) clean
.PHONY: all clean
