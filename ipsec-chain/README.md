# ipsec-chain — CVE-2026-43284 (IPsec ESP page-cache write chain)

User-space engine for the DirtyFrag-style chain that replaces the abandoned
futex-PI chain (CVE-2026-43499) in this repo.

## Why this chain

The futex chain had to change the caller's own uid to escalate, which trips
the OPPO anti-root watchdog (`oplus_security_guard.ko` watches uid/euid/gid
descending edges) and reboots the phone. This chain never does that:

- The write primitive (CVE-2026-43284) modifies **file page cache from kernel
  space** via the IPsec ESP AES-CBC in-place decrypt path — no syscalls that
  change caller identity.
- All privileged actions happen in **already-root contexts**: the hooked
  ostream sentry ctor runs inside `init` (uid 0, main thread tid 1), and the
  insmod executes after a SELinux domain switch to `u:r:vendor_modprobe:s0`.
- The watchdog has no uid transition to observe.

## Architecture

```
app: IpSecManager.UdpEncapsulationSocket + SPI + AES-CBC transform
                 |
engine (this dir) |  per 16-byte block:
                  |    old = current file bytes  (pread, or splicehelper "r")
                  |    IV  = AES_ECB_DEC(key, old) XOR desired
                  |    ESP packet: (SPI, seq) | IV | CT(=old) | ICV
                  v
kernel XFRM ESP-in-UDP input: in-place CBC decrypt over the spliced page
    new = AES_ECB_DEC(key, old) XOR IV = desired      (ICV fails afterwards,
                                                       packet dropped, but the
                                                       page cache is patched)
```

Patch targets:

| Stage | Target | Payload |
|---|---|---|
| `patch_helper` | `/apex/com.android.runtime/bin/crash_dump64` | `splicehelper` (bare-syscall static bin) — crash_dump domain becomes the read/splice bridge for vendor_file |
| `patch_ko` | `/vendor/lib64/libbinderdebug.so` (per-KMI carrier) | `dfroot.ko` bytes |
| `patch_hook` | `/system/lib64/libc++.so` | shellcode blob + trampoline over the ostream sentry ctor |

Hook execution flow (`libcxx_payload.S`):

1. fork orphan → reparented to init → init runs the hooked sentry ctor
2. shellcode gates: `getuid()==0 && gettid()==1` (inert everywhere else)
3. `/dev/df` mutex (`O_CREAT|O_EXCL`) — runs exactly once per boot
4. `clone` → grandchild writes `u:r:vendor_modprobe:s0` to
   `/proc/self/attr/exec`, then `execve("/vendor/bin/insmod", [insmod, ko])`
5. `dfroot.ko` (kprobe-bootstrapped, built separately in `ko/`) sets
   `selinux_state=false`, runs a usermodehelper bootstrap → ksud late-load → root
6. engine polls `/dev/dfm*` markers for 70 s

PACIASP/BTI: the trampoline is placed **+4 bytes** past a PACIASP/BTI
prologue, so the prologue executes exactly once; the displaced instruction
travels inside the shellcode blob and a patched `B` resumes the original flow
at `hook+4`. PC-relative instructions at the hook site are refused.

## Layout

```
ipsec-chain/
  include/aes256.h      AES-256 single-block ECB decrypt (FIPS 197) + compute_iv
  include/elf_parser.h
  src/engine.c          main engine (stages, ESP send, 70 s marker poll)
  src/elf_parser.c      ELF64 symbol -> file offset, cave finder, B encoder
  src/libcxx_payload.S  shellcode blob (uid/tid gate, /dev/df mutex, domain switch, insmod)
  src/splicehelper.c    bare-syscall helper ([offset] [path] [r|s]), no libc
  src/hosttest.c        host-only unit test (AES vector)
  ko/                   per-KMI dfroot.ko modules (built separately, later phase)
  Makefile              NDK r23c aarch64 build
```

## Build

```
make            # out/libdfroot.so (PIE exec) + out/splicehelper (static)
make host-test  # AES FIPS 197 C.3 vector + IV round trip on the host
```

On-device (after the Java app sets up the SA):

```
./libdfroot.so --encap-port 4500 --sender-port 4600 --spi 0x1234 \
    --aes-key <64 hex> [--ko /data/local/tmp/dfroot.ko] \
    [--stages helper,ko,hook,orphan,poll] [--dry-run]
```

`--local-write` is a debug mode that pwrites blocks directly instead of
sending ESP packets — for file-format bring-up only, never the device flow.

## Relationship to the old chain

`exploit-v29/` (futex-PI, CVE-2026-43499) is **deprecated** by this directory;
nothing there is reused. The kprobe-root module work continues under `ko/`
and `lkm-build/` once this engine's device bring-up lands.

## Status

- [x] Engine compiles clean (`-Werror`) for aarch64 with NDK r23c
- [x] AES-256 decrypt verified against FIPS 197 vector C.3 (host test)
- [ ] dfroot.ko per-KMI builds (separate phase)
- [ ] Device bring-up on Find N2 (PGU110, 5.10.246-android12-9)
