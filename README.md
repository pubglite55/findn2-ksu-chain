# oppo-ghostlock

> **OPPO Find N2 (PGU110 / SM8475) 上的 LKM root 全链**：futex PI 竞态写原语（GhostLock 家族，CVE-2026-43499）拿到内核写能力 → 绕过符号墙 / SCM 门 / ADRP 重定位溢出，把 KernelSU 内核模块 late-load 进**锁定 bootloader（verifiedbootstate=green）**的厂商内核，最终 `su -c id` → `uid=0 … context=u:r:ksu:s0`，SELinux Enforcing。KMI `android12-5.10`，全链在本机实测走通。

[![Status](https://img.shields.io/badge/root-achieved%20%28LKM%20late--load%29-brightgreen)]()
[![KMI](https://img.shields.io/badge/KMI-android12--5.10-blue)]()
[![Target](https://img.shields.io/badge/target-OPPO%20Find%20N2%20%2F%20SM8475-orange)]()
[![License](https://img.shields.io/badge/license-dual%20GPL--2.0%2FGPL--3.0-lightgrey)](#开源协议)

---

## ⚠️ 免责声明

- 本项目**仅供安全研究与教学用途**。所有实验在研究者自购设备上完成。
- 解锁 bootloader / 内核提权 / 加载自制内核模块**存在设备变砖、数据丢失、保修失效的风险**，由此造成的一切后果由操作者本人承担。
- 请勿将本项目用于任何未授权访问、规避设备所有者意愿、或违反当地法律的场景。
- 仓库中**不含**任何 OPPO 专有固件（boot.img / 反编译数据库均已移出版本库，见 `.gitignore`）。

## 目录结构

```
oppo-ghostlock/
├── exploit-v29/              # 用户态 exploit（GhostLock 家族 futex PI 竞态 → 写原语 → 提权）
│   ├── src/                  #   matisse 框架 + 本机适配（GPL-3.0，见 exploit-v29/NOTICE.md）
│   │   └── targets/oppo-find_n2/target.h   # PGU110 全部偏移（逐条标注来源）
│   ├── tools/ksu_go.sh       #   KernelSU 装载辅助脚本
│   └── NOTICE.md             #   上游来源与许可声明（必须读）
├── lkm-build/                # ★ 内核模块构建体系（本仓库原创，GPL-2.0-only）
│   ├── build-lkm.sh          #   CI/本地构建：厂商树 + 设备 .config + clang 12
│   ├── config-5.10.236       #   设备 /proc/config.gz 回收的完整内核配置
│   ├── minload/              #   ksu_min_load —— 极简装载器（绕开 ksud 风暴）
│   ├── stubs/                #   符号墙补丁：kprobe 自举 + 转发定义 + 空实现
│   └── out/                  #   构建产物：kernelsu.ko（交付）+ ksu_min_load.ko（白名单）
├── exploit/  exploit-server/ # 早期验证阶段的原型与服务端脚本
├── test-programs/            # 独立 PoC / 探针程序
├── analysis-scripts/         # ELF/符号/调用链分析脚本（含 findsym.py / findsym2.py）
├── qemu-lab/                 # QEMU 复现沙盒
├── docs/                     # 技术记录：移植日志、堆喷分析、取证日志（evidence-root-*.log）
├── _docs/handoff/            # 阶段冻结快照（按时间归档的权威记录）
├── RESEARCH.md               # ★ 深度技术文档：12 个关键技术节点的完整复盘
├── HANDOFF.md / AGENTS.md    # 交接文档 / 自动化代理操作规程
├── FAQ.md / TROUBLESHOOTING.md / TESTED_METHODS.md / 问题描述.md
└── CHANGELOG.md / CONTRIBUTING.md
```

> 巨型本地产物（boot.img、output.elf 反编译数据库、考古期 .ko 变体）**不进版本库**，留在本地 `../oppo-archive/`（详见 `.gitignore` 尾部规则）。

## 快速开始

内核模块产物由 GitHub Actions 构建（`.github/workflows/build-lkm.yml`）：在**厂商内核源码树**上用设备的 `.config` 与 clang 12（`CONFIG_CFI_CLANG=y` 代的 r416183b）编译，自动钉 `scmversion`、自动补齐未发布的厂商 Kconfig、产物即 `kernelsu.ko` + `ksu_min_load.ko`。

```bash
# 1) CI 产物
#    GitHub → Actions → build-lkm → 下载 artifact（kernelsu.ko / ksu_min_load.ko）
#    本地复现：KSRC=<厂商树> KSU=<KernelSU> CLANG=<clang12> CONFIG=config-5.10.236 bash lkm-build/build-lkm.sh

# 2) 用户态前置：先拿到写原语（阶段 A，见 RESEARCH.md §3）
adb push exploit-v29/build/oppo-find_n2/bin/preload.so /data/local/tmp/preload29.so
adb shell "LD_PRELOAD=/data/local/tmp/preload29.so /system/bin/toybox id"   # uid=0 即阶段 A 达成

# 3) 设备侧装载（阶段 B）：uid=0 后经 minload 路径 late-load 内核模块
adb push lkm-build/out/ksu_min_load.ko lkm-build/out/kernelsu.ko /data/local/tmp/
#    → ksu_min_load.ko 自卸式装载器：解析 kernelsu.ko → finit_module → 卸载自身不留痕
#    → 或 ReSukiSU manager 的 late-load 路径（OTA 5.10.246 上的最终路线）

# 4) 验收
adb shell "su -c id"
# uid=0(root) … context=u:r:ksu:s0      ← SELinux 仍为 Enforcing
adb shell "grep kernelsu /proc/modules"  # kernelsu … Live
```

前置条件、环境变量配方（`PSELECT_*`）、内存与时序要求、失败症状速查：见 **[RESEARCH.md](RESEARCH.md)** §3/§7 与 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)。

## 技术架构

```
用户态 (adb shell, LD_PRELOAD=preload.so)
    │
    │  futex PI requeue 竞态 (GhostLock 家族 CVE-2026-43499 栈 UAF)
    │  pselect 窗口对齐调度风暴落点 (PSELECT_WINDOW_SECONDS, mt19b 风暴)
    ▼
内核写原语 ── perf_event 泄露 cred 地址 → 定向写 task->cred = &init_cred
    │        CapEff 0000000000000000 → 000001ffffffffff
    ▼
uid=0 + 全能力集 (含 CAP_SYS_MODULE)
    │        权限闸门逐个排除: capable()✓ SELinux✓ 域✓
    ▼
LKM late-load ── ksu_min_load.ko（自卸式，绕开 ksud 进程风暴）
    │        或 ReSukiSU manager late-load
    │        kernelsu.ko: -mcmodel=large（ADRP 重定位 1497→0）
    │                      符号墙自举（TRIM_UNUSED_KSYMS 裁 49 → 未定义 0）
    │                      scmversion 钉死 g74d132f4467a
    ▼
KernelSU Live: /proc/modules "kernelsu Live" · /system/bin/su · u:r:ksu:s0
```

## ★ 项目故事线（Timeline）

| # | 节点 | 结果 |
|---|------|------|
| 1 | 锁 BL 绿灯设备 + 厂商内核只读分析 | IDA 数据库（143,599 符号 `.symtab`）建立全部偏移依据 |
| 2 | matisse 框架移植到 PGU110 | `targets/oppo-find_n2/target.h` 逐条实测偏移 |
| 3 | 阶段 A：瞬态 root | `uid=0` 3/3 设备复现（N2/P2/K3），证据 `docs/evidence-root-*.log` |
| 4 | LKM 装载第一课：权限闸门真相 | `finit_module` 能走到**重定位处理** ⇒ `capable(CAP_SYS_MODULE)`/SELinux/域全部已过；此前 shell 域 EPERM 是 ksud 自身逻辑的假象 |
| 5 | 撞墙：重定位溢出 | `module kernelsu: overflow in relocation type 275 val ffffffc00aa41b98`（R_AARCH64_ADR_PREL_PG_HI21，±4GiB；val 是线性映射别名，与模块 PC 相距 ≈16GiB） |
| 6 | 修复：`ccflags-y += -mcmodel=large` | type 275 重定位 **1497 → 0**（ELF `.rela` 直方图逐条验证） |
| 7 | 符号墙：`CONFIG_TRIM_UNUSED_KSYMS=y` 裁掉 49 个符号 | kprobe `kallsyms_lookup_name` 自举 + 44 个真转发定义 + 3 个自有符号空实现 ⇒ 未定义符号 **0** |
| 8 | SCM 门：`CONFIG_MODULE_SCMVERSION=y` | 构建期把 `include/config/scmversion` 钉成 `g74d132f4467a` 逐字对齐 |
| 9 | 崩因 #1：ksud 进程风暴 → panic-on-workqueue-lockup | 改走自研 `ksu_min_load`（自卸式装载器）后归零 |
| 10 | 稳定性工程 | preflight 门禁 + 减重配方 + 跨重启取证；设备 6 次死机全部救回，最终 **uptime 27h+ 无 crash** |
| 11 | ★ 终局 | OTA 后内核 5.10.246 上经 ReSukiSU manager late-load：`kernelsu` Live in `/proc/modules`、`/system/bin/su`、`su -c id → uid=0 … u:r:ksu:s0`、SELinux Enforcing |
| 12 | 收尾 | 固件/IDA 库/考古 .ko 移出版本库；本文档与 [RESEARCH.md](RESEARCH.md) |

各节点的完整技术展开（数据、日志行、命令、机理）见 **[RESEARCH.md](RESEARCH.md)**。

## 致谢

- **[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)** — GhostLock（CVE-2026-43499）原始研究与 exploit 框架
- **[NebuSec IonStack 系列分析](https://nebusec.ai/research/ionstack-part-2/)** — 技术分析
- **[ihamn/matisse-public](https://github.com/ihamn/matisse-public)**（GPL-3.0）— `exploit-v29/` 的上游框架（K50 Pro/MT6983），本仓库逐字移植并完成 Find N2 适配
- **[Dere3046/ElevateMe](https://github.com/Dere3046/ElevateMe)** — rb_erase cred 覆写机制
- **[diyiqiuye/CVE-2025-21479-FX5P](https://github.com/diyiqiuye/CVE-2025-21479-FX5P)** — 偏移工具与 profile 方法论
- **[JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)** — cph2521（同 SoC）偏移交叉验证
- **DirtyFrag（CVE-2026-43284）社区 / DFRoot 及其 fork** — LKM 装载**思想**参考（页缓存清理、DEFEX 空实现、绕开 `STATIC_USERMODEHELPER`、usermode-helper bootstrap）。本项目**仅吸收思路，未引入其任何代码**；`lkm-build/minload/` 全部为本仓库原创实现，对照分析见 [RESEARCH.md](RESEARCH.md) §8
- lspromise / 看雪社区的公开适配讨论

## 开源协议

- **`lkm-build/`**（内核模块构建体系、装载器、符号补丁）：**GPL-2.0-only**（内核模块生态惯例）
- **`exploit-v29/`**：继承上游 matisse 的 **GPL-3.0**（见 `exploit-v29/NOTICE.md`，本目录非本仓库原创框架，来源已逐文件标注）
- 其余文档与脚本：GPL-2.0-only
