<div align="center">

[English](README.md) | 简体中文

# findn2-ksu-chain

**在 Bootloader 锁定的 OPPO Find N2 上 late-load KernelSU —— 全链自建 LKM，无需解锁 BL。**

`futex-PI 写原语 → cred 覆写 → 修复 ADRP 溢出 → kernelsu.ko Live`

![root](https://img.shields.io/badge/root-achieved-brightgreen)
![KMI](https://img.shields.io/badge/KMI-android12--5.10-blue)
![SoC](https://img.shields.io/badge/SoC-SM8475-orange)
![SELinux](https://img.shields.io/badge/SELinux-Enforcing-success)

</div>

---

## ✨ 这是什么

一套完整跑通的科研级链路：把**自编的 KernelSU 内核模块**装载进一台**OTA 原厂、Bootloader 锁定**
的 OPPO Find N2（PGU110 / SM8475），最终 `su -c id → uid=0 … context=u:r:ksu:s0`，
且 SELinux 保持 **Enforcing**。

`lkm-build/` 里的装载器、符号墙 shim、构建体系均为**本仓库原创**；
用户态 exploit 是 matisse 框架的 GPL-3.0 移植 + 本机适配（见 [NOTICE](exploit-v29/NOTICE.md)）。

## 🏗️ 工作原理

```
 ① futex PI requeue 竞态    →  内核写原语（GhostLock，CVE-2026-43499）
 ② task->cred = &init_cred  →  CapEff 0000000000000000 → 000001ffffffffff
 ③ 权限闸门                  →  capable() ✓ SELinux ✓ 域 ✓（这从来不是真正的墙）
 ④ finit_module             →  R_AARCH64_ADR_PREL_PG_HI21 溢出 ← 真正的墙
                              修复：-mcmodel=large，reloc-275 1497 → 0
 ⑤ kernelsu.ko Live         →  /system/bin/su · u:r:ksu:s0 · SELinux Enforcing
```

## 📊 实测结果

| | |
|---|---|
| **写原语** | `CapEff: 000001ffffffffff` 设备实测（3/3 次命中） |
| **重定位修复** | type-275 数量 **1497 → 0**（ELF `.rela` 直方图逐条验证） |
| **符号墙** | TRIM_UNUSED_KSYMS 裁掉 49 个符号 → kprobe 自举 + 转发定义 → **未定义 0** |
| **SCM 门** | `scmversion` 钉死 `g74d132f4467a`，逐字对齐 |
| **稳定性** | preflight 门禁 + 减重配方；最终 **uptime 27h+ 零 crash** |

## 🚀 快速开始

<details>
<summary><b>构建与运行</b>（点击展开）</summary>

```bash
# 1) 内核模块由 GitHub Actions 构建（build-lkm.yml）——下载 artifact 即可；
#    本地复现：
KSRC=<厂商内核树> KSU=<KernelSU> CLANG=<clang12> CONFIG=config-5.10.236 \
    bash lkm-build/build-lkm.sh

# 2) 用户态前置：先拿到写原语（阶段 A）
adb push exploit-v29/build/oppo-find_n2/bin/preload.so /data/local/tmp/preload29.so
adb shell "LD_PRELOAD=/data/local/tmp/preload29.so /system/bin/toybox id"   # uid=0

# 3) 设备侧装载（阶段 B）
adb push lkm-build/out/ksu_min_load.ko lkm-build/out/kernelsu.ko /data/local/tmp/

# 4) 验收
adb shell "su -c id"                     # uid=0 … context=u:r:ksu:s0
adb shell "grep kernelsu /proc/modules"  # kernelsu … Live
```

</details>

## 📁 仓库导览

```
exploit-v29/       用户态 exploit（matisse 移植，GPL-3.0）+ Find N2 偏移表
lkm-build/         ★ 原创构建体系：装载器 · 符号 shim · CI 脚本
analysis-scripts/  ELF / 符号 / 偏移分析工具
test-programs/     独立 PoC 探针（仅 C 源码）
docs/              研究笔记 · 取证日志 · 阶段快照
RESEARCH.md        ★ 深度技术复盘（§1–§10）
```

## 📜 完整故事

每一次撞墙、每一行 dmesg、每一个修复，都记录在 **[RESEARCH.md](RESEARCH.md)** ——
包括为什么权限闸门从来不是问题、ADRP 溢出如何被发现并消灭、以及 5.10.246 OTA 之后发生了什么。

## 🙏 致谢

- **NebuSec/CyberMeowfia** — GhostLock（CVE-2026-43499）研究与 exploit 框架
- **ihamn/matisse-public**（GPL-3.0）— `exploit-v29/` 的上游框架
- **Dere3046/ElevateMe** — rb_erase cred 覆写机制
- **JoinChang/ghostlock-oneplus** — 同 SoC 偏移交叉验证
- **DirtyFrag / DFRoot 社区（CVE-2026-43284）** — 仅借鉴**思想**（页缓存清理、DEFEX 空实现、
  绕开 `STATIC_USERMODEHELPER`、umh bootstrap）；**未引入任何代码** —— `lkm-build/minload/`
  为本仓库原创实现，对照分析见 [RESEARCH.md §8](RESEARCH.md)
- lspromise 与看雪社区的公开讨论

## ⚖️ 许可与免责

- `lkm-build/`、文档、脚本：**GPL-2.0-only** · `exploit-v29/`：**GPL-3.0**（上游）
- 仅供安全研究与教学，在自有设备上自担风险。变砖、数据丢失、保修失效都是真实可能。
- 本仓库不含任何 OPPO 专有固件。
