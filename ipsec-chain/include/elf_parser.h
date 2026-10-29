/*
 * elf_parser.h - minimal ELF64 reader used to locate hook points inside
 * system libraries (/system/lib64/libc++.so) on-device.
 *
 * Responsibilities:
 *   - load a whole ELF64 (aarch64) file into memory
 *   - resolve a symbol name to its FILE offset (via .symtab, falling back to
 *     .dynsym; vaddr -> file offset through PT_LOAD segments)
 *   - detect PACIASP / BTI prologues so the trampoline is placed +4 bytes in
 *   - find a zero-filled code cave inside an executable PT_LOAD for the
 *     shellcode blob
 */
#ifndef IPSEC_CHAIN_ELF_PARSER_H
#define IPSEC_CHAIN_ELF_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *map;
    size_t   size;
} elf64_img;

/* Load `path` fully into memory. Returns 0 on success. */
int elf64_load(const char *path, elf64_img *img);
void elf64_unload(elf64_img *img);

/*
 * Find `name` and return:
 *   *foff  - file offset of the symbol's first instruction
 *   *skip4 - 1 when the first instruction is PACIASP/BTI (hook goes at +4)
 * Returns 0 on success, -1 when the symbol is missing, -2 on malformed ELF.
 */
int elf64_find_symbol(const elf64_img *img, const char *name,
                      uint64_t *foff, int *skip4);

/* Read the 32-bit little-endian instruction at file offset `foff`. */
int elf64_read_insn(const elf64_img *img, uint64_t foff, uint32_t *insn);

/*
 * Find a run of `need` zero bytes inside an executable PT_LOAD segment,
 * 4-byte aligned. Returns 0 and sets *foff, or -1 if no cave fits.
 */
int elf64_find_zero_cave(const elf64_img *img, size_t need, uint64_t *foff);

/*
 * True when the instruction is PC-relative (B/BL/ADR/ADRP/CBZ/TBZ/LDR-lit),
 * i.e. unsafe to displace into the shellcode trampoline.
 */
int elf64_insn_is_pcrel(uint32_t insn);

/* Encode an unconditional B instruction from `pc` to `target` (file offsets
 * are used as proxies for runtime vaddrs; both live in the same mapping). */
int elf64_encode_b(uint64_t pc, uint64_t target, uint32_t *insn_out);

#endif /* IPSEC_CHAIN_ELF_PARSER_H */
