# ipsec-chain - CVE-2026-43284 engine (IPsec ESP page-cache write chain)
#
# Cross-compiles with the NDK r23c clang for aarch64 Android.
#   out/libdfroot.so  - the engine (PIE executable; .so name is deliberate,
#                       DirtyFrag-style: it is a bin, not a library)
#   out/splicehelper  - bare-syscall static helper (no libc, no start files)
#
# Targets:
#   make            - build engine + helper
#   make host-test  - build & run AES/ELF self-test with the host compiler
#   make clean

NDK       := C:/Users/L1872/Desktop/ndk-r23c/android-ndk-r23c
TOOLBIN   := $(NDK)/toolchains/llvm/prebuilt/windows-x86_64/bin
CC        := $(TOOLBIN)/aarch64-linux-android24-clang
OBJCOPY   := $(TOOLBIN)/llvm-objcopy.exe
HOST_CC   ?= gcc

API       := 24
WARN      := -Wall -Wextra -Werror
CFLAGS    := -O2 -g -std=gnu11 $(WARN) -Iinclude
LDFLAGS   := -fPIE -pie

BUILD     := build
OUT       := out

HELPER_CFLAGS := $(WARN) -O2 -std=gnu11 \
                 -nodefaultlibs -nostartfiles -ffreestanding -static

ENGINE_SRCS := src/engine.c src/elf_parser.c src/libcxx_payload.S
HELPER_SRCS := src/splicehelper.c

.PHONY: all clean host-test
all: $(OUT)/libdfroot.so $(OUT)/splicehelper

$(OUT) $(BUILD):
	mkdir -p $@

# --- splicehelper: freestanding static binary -----------------------------
$(OUT)/splicehelper: $(HELPER_SRCS) include/aes256.h | $(OUT)
	$(CC) $(HELPER_CFLAGS) -Iinclude -o $@ $(HELPER_SRCS)

# --- embed splicehelper into the engine -----------------------------------
$(BUILD)/splicehelper.bin: $(OUT)/splicehelper | $(BUILD)
	cp $< $@

$(BUILD)/splicehelper_bin.o: $(BUILD)/splicehelper.bin
	cd $(BUILD) && $(OBJCOPY) -I binary -O elf64-littleaarch64 -B aarch64 \
		splicehelper.bin splicehelper_bin.o

# --- engine: PIE executable named libdfroot.so ----------------------------
$(OUT)/libdfroot.so: $(ENGINE_SRCS) include/aes256.h include/elf_parser.h \
                     $(BUILD)/splicehelper_bin.o | $(OUT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(ENGINE_SRCS) \
		$(BUILD)/splicehelper_bin.o -llog

# --- host unit test: AES FIPS 197 vector + ELF parser on a real .so -------
host-test: $(BUILD)/hosttest
	$(BUILD)/hosttest

$(BUILD)/hosttest: src/hosttest.c include/aes256.h
	@mkdir -p $(BUILD)
	$(HOST_CC) -O2 -Wall -Wextra -Iinclude -o $@ src/hosttest.c

clean:
	rm -rf $(BUILD) $(OUT)
