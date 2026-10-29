/*
 * elf_parser.c - minimal ELF64 (aarch64) reader.
 *
 * Used by the engine to locate hook points inside system libraries:
 *   - resolve a symbol name to its file offset (.symtab, fallback .dynsym)
 *   - vaddr -> file offset conversion through PT_LOAD program headers
 *   - PACIASP / BTI prologue detection (trampoline goes +4 bytes in)
 *   - zero-filled code-cave discovery inside an executable PT_LOAD
 *
 * The whole file is read into memory once; no mmap needed for the sizes of
 * /system/lib64/libc++.so-scale libraries.
 */
#include "elf_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Minimal ELF64 definitions (self-contained, little-endian aarch64).  */
/* ------------------------------------------------------------------ */

#define EI_NIDENT   16
#define EM_AARCH64  183

#define PT_LOAD     1
#define PF_X        1

#define SHT_SYMTAB  2
#define SHT_DYNSYM  11

#define STT_NOTYPE  0
#define STT_FUNC    2
#define STT_GNU_IFUNC 10

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} elf64_shdr;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_sym;

/* ------------------------------------------------------------------ */
/* Instruction encodings                                              */
/* ------------------------------------------------------------------ */

#define INSN_PACIASP 0xD503233Fu
#define INSN_BTI_C   0xD503245Fu
#define INSN_BTI_J   0xD503249Fu
#define INSN_BTI_JC  0xD50324DFu

/* The readers take const void *: callers pass typed struct-member addresses
 * (e.g. &ehdr->e_phnum) straight in, since the file image is little-endian
 * aarch64 ELF and we decode explicitly. */
static uint16_t rd16(const void *pv)
{
    const uint8_t *p = (const uint8_t *)pv;
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32(const void *pv)
{
    const uint8_t *p = (const uint8_t *)pv;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const void *pv)
{
    const uint8_t *p = (const uint8_t *)pv;
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* ------------------------------------------------------------------ */
/* Load / unload                                                      */
/* ------------------------------------------------------------------ */

int elf64_load(const char *path, elf64_img *img)
{
    FILE *f;
    long sz;
    uint8_t *buf;
    const elf64_ehdr *eh;

    img->map = NULL;
    img->size = 0;

    f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    if ((size_t)sz < sizeof(elf64_ehdr)) {
        fclose(f);
        return -2;
    }
    buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return -3;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    eh = (const elf64_ehdr *)buf;
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F' ||
        eh->e_ident[4] != 2 /* ELFCLASS64 */ ||
        eh->e_ident[5] != 1 /* little endian */ ||
        rd16(&eh->e_machine) != EM_AARCH64) {
        free(buf);
        return -2;
    }

    img->map = buf;
    img->size = (size_t)sz;
    return 0;
}

void elf64_unload(elf64_img *img)
{
    if (img->map != NULL) {
        free(img->map);
        img->map = NULL;
    }
    img->size = 0;
}

/* ------------------------------------------------------------------ */
/* Program headers / symbol resolution                                */
/* ------------------------------------------------------------------ */

static const elf64_phdr *find_exec_load(const elf64_img *img, uint64_t vaddr)
{
    const uint8_t *base = img->map;
    const elf64_ehdr *eh = (const elf64_ehdr *)base;
    const elf64_phdr *ph;
    uint16_t i;

    for (i = 0; i < rd16(&eh->e_phnum); i++) {
        size_t off = (size_t)rd64(&eh->e_phoff) + (size_t)i * rd16(&eh->e_phentsize);
        if (off + sizeof(elf64_phdr) > img->size)
            continue;
        ph = (const elf64_phdr *)(base + off);
        if (rd32(&ph->p_type) != PT_LOAD)
            continue;
        if (rd64(&ph->p_vaddr) <= vaddr &&
            vaddr < rd64(&ph->p_vaddr) + rd64(&ph->p_filesz) &&
            (rd32(&ph->p_flags) & PF_X))
            return ph;
    }
    return NULL;
}

static int sym_from_section(const elf64_img *img,
                            const elf64_shdr *sh, const char *name,
                            uint64_t *vaddr_out)
{
    const uint8_t *base = img->map;
    size_t strtab_off;
    size_t entsz, n, i;

    if (sh->sh_link == 0 || sh->sh_entsize == 0)
        return -1;
    strtab_off = 0;
    {
        const elf64_ehdr *ehdr = (const elf64_ehdr *)base;
        const elf64_shdr *strsh = (const elf64_shdr *)(base +
            (size_t)rd64(&ehdr->e_shoff) +
            (size_t)sh->sh_link * rd16(&ehdr->e_shentsize));
        if ((size_t)((const uint8_t *)strsh - base) + sizeof(elf64_shdr) > img->size)
            return -1;
        strtab_off = (size_t)rd64(&strsh->sh_offset);
        if (strtab_off >= img->size)
            return -1;
    }

    entsz = rd64(&sh->sh_entsize);
    if (entsz < sizeof(elf64_sym))
        entsz = sizeof(elf64_sym);
    n = (size_t)rd64(&sh->sh_size) / entsz;

    for (i = 0; i < n; i++) {
        const uint8_t *sym_p = base + (size_t)rd64(&sh->sh_offset) + i * entsz;
        const char *sname;
        uint32_t st_name;
        uint8_t st_info;
        uint64_t st_value;

        if ((size_t)rd64(&sh->sh_offset) + (i + 1) * entsz > img->size)
            break;
        st_name  = rd32(sym_p);
        st_info  = sym_p[4];
        st_value = rd64(sym_p + 8);

        if (st_value == 0 || st_name == 0)
            continue;
        {
            uint8_t type = (uint8_t)(st_info & 0xf);
            if (type != STT_FUNC && type != STT_GNU_IFUNC && type != STT_NOTYPE)
                continue;
        }
        if (strtab_off + st_name >= img->size)
            continue;
        sname = (const char *)(base + strtab_off + st_name);
        if (strcmp(sname, name) == 0) {
            *vaddr_out = st_value;
            return 0;
        }
    }
    return -1;
}

int elf64_find_symbol(const elf64_img *img, const char *name,
                      uint64_t *foff, int *skip4)
{
    const uint8_t *base = img->map;
    const elf64_ehdr *eh = (const elf64_ehdr *)base;
    uint64_t vaddr = 0;
    uint16_t i;
    int found = 0;
    int pass;
    uint32_t insn;
    const elf64_phdr *seg;

    if (rd64(&eh->e_shoff) == 0 || rd16(&eh->e_shnum) == 0)
        return -2;

    /* Prefer .symtab (more symbols); fall back to .dynsym. */
    for (pass = 0; pass < 2 && !found; pass++) {
        uint32_t want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        for (i = 0; i < rd16(&eh->e_shnum); i++) {
            size_t off = (size_t)rd64(&eh->e_shoff) + (size_t)i * rd16(&eh->e_shentsize);
            elf64_shdr sh;
            const uint8_t *shp;

            if (off + sizeof(elf64_shdr) > img->size)
                continue;
            shp = base + off;
            if (rd32(&shp[4]) != want) /* sh_type at offset 4 */
                continue;
            sh.sh_name    = rd32(shp + 0);
            sh.sh_type    = rd32(shp + 4);
            sh.sh_flags   = rd64(shp + 8);
            sh.sh_addr    = rd64(shp + 16);
            sh.sh_offset  = rd64(shp + 24);
            sh.sh_size    = rd64(shp + 32);
            sh.sh_link    = rd32(shp + 40);
            sh.sh_info    = rd32(shp + 44);
            sh.sh_addralign = rd64(shp + 48);
            sh.sh_entsize = rd64(shp + 56);
            if (sym_from_section(img, &sh, name, &vaddr) == 0) {
                found = 1;
                break;
            }
        }
    }
    if (!found)
        return -1;

    seg = find_exec_load(img, vaddr);
    if (seg == NULL) {
        /* Not inside an executable segment: still usable if within a file
         * mapping, but hooks only make sense in exec segments. */
        return -2;
    }
    *foff = vaddr - rd64(&seg->p_vaddr) + rd64(&seg->p_offset);

    /* PACIASP / BTI prologue detection: the trampoline is placed at +4 so the
     * prologue instruction stays intact (PAC must execute exactly once,
     * callers may indirect-branch at a BTI landing site). */
    if (elf64_read_insn(img, *foff, &insn) != 0)
        return -2;
    if (insn == INSN_PACIASP || insn == INSN_BTI_C ||
        insn == INSN_BTI_J || insn == INSN_BTI_JC)
        *skip4 = 1;
    else
        *skip4 = 0;
    return 0;
}

int elf64_read_insn(const elf64_img *img, uint64_t foff, uint32_t *insn)
{
    if (foff + 4 > img->size)
        return -1;
    *insn = rd32(img->map + (size_t)foff);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Code cave                                                          */
/* ------------------------------------------------------------------ */

int elf64_find_zero_cave(const elf64_img *img, size_t need, uint64_t *foff)
{
    const uint8_t *base = img->map;
    const elf64_ehdr *eh = (const elf64_ehdr *)base;
    uint16_t i;

    if (need == 0)
        return -1;

    for (i = 0; i < rd16(&eh->e_phnum); i++) {
        size_t off = (size_t)rd64(&eh->e_phoff) + (size_t)i * rd16(&eh->e_phentsize);
        const elf64_phdr *ph;
        uint64_t p_off, p_filesz, cur;
        size_t run = 0;

        if (off + sizeof(elf64_phdr) > img->size)
            continue;
        ph = (const elf64_phdr *)(base + off);
        if (rd32(&ph->p_type) != PT_LOAD || !(rd32(&ph->p_flags) & PF_X))
            continue;

        p_off = rd64(&ph->p_offset);
        p_filesz = rd64(&ph->p_filesz);
        if (p_off >= img->size)
            continue;
        if (p_off + p_filesz > img->size)
            p_filesz = img->size - p_off;
        if ((uint64_t)need > p_filesz)
            continue;

        for (cur = 0; cur + 4 <= p_filesz; cur += 4) {
            size_t pos = (size_t)(p_off + cur);
            if (pos + 4 <= img->size && rd32(base + pos) == 0) {
                run += 4;
                if (run >= need) {
                    *foff = p_off + cur - run + 4;
                    return 0;
                }
            } else {
                run = 0;
            }
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Instruction helpers                                                */
/* ------------------------------------------------------------------ */

int elf64_insn_is_pcrel(uint32_t insn)
{
    /* B / BL */
    if ((insn & 0x7C000000u) == 0x14000000u)
        return 1;
    /* ADR / ADRP */
    if ((insn & 0x1F000000u) == 0x10000000u)
        return 1;
    /* CBZ / CBNZ */
    if ((insn & 0x7E000000u) == 0x34000000u)
        return 1;
    /* TBZ / TBNZ */
    if ((insn & 0x7E000000u) == 0x36000000u)
        return 1;
    /* LDR/STR literal */
    if ((insn & 0x3B000000u) == 0x18000000u)
        return 1;
    return 0;
}

int elf64_encode_b(uint64_t pc, uint64_t target, uint32_t *insn_out)
{
    int64_t delta;

    if ((pc & 3) != 0 || (target & 3) != 0)
        return -1;
    delta = (int64_t)(target - pc);
    if (delta > 0x07FFFFFFll || delta < -0x08000000ll)
        return -1; /* out of +-128MB branch range */
    *insn_out = 0x14000000u | (uint32_t)(((uint64_t)(delta >> 2)) & 0x03FFFFFFu);
    return 0;
}
