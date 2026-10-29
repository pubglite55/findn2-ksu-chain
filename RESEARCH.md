# RESEARCH.md — OPPO Find N2 (PGU110 / SM8475) LKM root 全链技术复盘

> 本文是 [README.md](README.md) 故事线的深度展开。所有数据、日志行、二进制度量均来自本机实测产物；
> 关键二进制断言（`.ko` 重定位直方图、sha16）可由 `analysis-scripts/findsym*.py` 或任意 ELF 解析器复验。
> 时间线：初始内核 `5.10.236-android12-9-o-g74d132f4467a` → OTA 后 `5.10.246-android12-9-o-g931a7e2ba585`。

---

## §1 设备与内核基线

| 项 | 值 |
|---|---|
| 设备 | OPPO Find N2 (PGU110)，SoC Snapdragon 8+ Gen 1 (**SM8475**) |
| 系统 | ColorOS（Android 16 / API 36 路径下的 5.10 KMI 内核） |
| 内核（起点） | `5.10.236-android12-9-o-g74d132f4467a` |
| 内核（OTA 后） | `5.10.246-android12-9-o-g931a7e2ba585` |
| KMI | `android12-5.10`（非 GKI 认证内核，但遵循 KMI 符号约定 + 厂商私有符号层） |
| Bootloader | **锁定**，`verifiedbootstate=green`（不解锁、不刷机） |
| 内核配置关键项 | `CONFIG_CFI_CLANG=y`、`CONFIG_TRIM_UNUSED_KSYMS=y`、`CONFIG_MODULE_SCMVERSION=y`、`CONFIG_MODVERSIONS=y`、panic-on-workqueue-lockup 检测开启 |
| 编译器代际 | clang 12（r416183b）—— 与厂商构建一致，CFI 兼容 |

基线分析方法：`boot.img` 只读提取（`extract-vmlinux`）→ vmlinux 载入 IDA（143,599 个 `.symtab` 符号）→
全部 `task_struct`/`cred`/futex 路径偏移逐条核对后写入
`exploit-v29/src/targets/oppo-find_n2/target.h`（每个偏移标注来源：`.symtab` 直查或反汇编推导）。
固件与反编译数据库本身**不分发**（版权），仅分发偏移结论与来源标注。

## §2 权限闸门的真实边界（capable / SELinux / 域逐个排除法）

**结论先行：LKM 装载失败的唯一内核侧原因是重定位溢出（§4），不是任何权限闸门。**

排除法过程（每一步都有 dmesg / errno 证据）：

1. **初始假象**：shell 域直接 `insmod`/`finit_module` 得到 EPERM，直觉归因于
   `capable(CAP_SYS_MODULE)` 或 SELinux `kernel_module_request` 拒绝。
2. **关键观测**：写原语落地（§3）拿到 uid=0 + 全能力集后再次调用 `finit_module(fd, "", 3)`，
   错误从 **EPERM 变成 ENOEXEC 类的重定位错误** —— dmesg 打出了
   `overflow in relocation type 275`。**能走到重定位处理 = `post_relocation` 之前的所有闸门已全过**：
   - `capable(CAP_SYS_MODULE)` ✓（bit16 已在 CapEff `000001ffffffffff` 中）
   - SELinux hook `kernel_module_request`/`kernel_read_file` ✓（域上下文已切换为 ksu 链路）
   - LSM 域检查 ✓
3. **EPERM 真相**：此前 shell 域里的 EPERM 来自 **ksud 自身逻辑**（它先检查自己的
   运行条件，不满足即自拒，把 shell 域的失败伪装成"权限拒绝"假象）。

意义：**失败模式必须看 dmesg 的具体阶段**（permission hook → load_info → 重定位 → 符号解析），
阶段即真相，errno 只能告诉你"没过"，不能告诉你"死在哪"。

## §3 futex 写原语落地（PERF_CRED 守卫 + WINDOW_SECONDS 时序 + CapEff 证据）

漏洞基座：GhostLock 家族（CVE-2026-43499）futex PI requeue 栈 UAF，
框架逐字移植自 matisse-public（GPL-3.0，见 `exploit-v29/NOTICE.md`），本机适配为 PGU110 偏移。

**写原语落地三要素（实测缺一必败）：**

1. **`PSELECT_PERF_CRED`（决定性开关）**——让 `perf_event_open` 泄露链提取目标
   `task->cred` **地址**（而非只泄自身）。守卫在 `exploit-v29/src/main.c:1442`：

   ```c
   uintptr_t cred_addr = g_perf_cred_cand;
   if (!mt49_task_env && !cred_addr) {
       pr_error("mt40: no cred_cand from perf - need PSELECT_PERF_CRED\n");
       ...
   }
   ```

   没有它：写入目标未知，路线 C（route C：写 cred 内容）直接放弃。
2. **`PSELECT_WINDOW_SECONDS=120`**——pselect 停放窗口的时序旋钮。调度风暴
   （mt19b）必须落进窗口内；窗口过短会 `window closed mid-burst` 中途废弃。
   60s 档在加载了 prep 机器的设备上不够用，实测 120s 稳定。
3. **风暴对齐**——消费线程的 `SLIDE_CONSUME_DELAY`（slide.c）必须短于风暴关窗时延
   （成功 trace 显示风暴 `storm done at t=72ms` 后 `sched_ok=1 t=74ms`），
   否则 mt19b 一次都不执行（三连发 byte-identical trace 的根因）。

**写什么：** `init_cred`（内核静态 `cred` 结构，`cred_addr` 指向它时写入即全局提权）。

**落地证据（实测日志行）：**

```
[+] mt47: ROOT-SEEN … CapEff=ffffff8a368280c0 poll=17     <- caps 写入落地
[*] mt47: after setres uid=0 euid=0 gid=0 egid=0          <- ★ 真 uid=0 ★
```

`CapEff 0000000000000000 → 000001ffffffffff`（全能力集，含 bit16 CAP_SYS_MODULE），
三次独立运行（N2/P2/K3）3/3 命中，原始取证日志：`docs/evidence-root-*.log`。

安全工程（防设备崩）：每次 arb write 在独立 worker 子进程内发生，写完 `pause()` 永久 park
（绝不 `_exit`/`execve` —— 延迟内核状态破坏才是黑屏真凶）；完成信号走继承 pipe fd 而非文件
（提权后 payload 的 fs view 已损坏，`open(O_CREAT)` 会失败）。

## §4 模块装载失败复盘：R_AARCH64_ADR_PREL_PG_HI21 溢出 + -mcmodel=large

**原始失败（dmesg 逐字）：**

```
module kernelsu: overflow in relocation type 275 val ffffffc00aa41b98
```

**机理：** type 275 = `R_AARCH64_ADR_PREL_PG_HI21`（ADRP，页粒度 PC 相对寻址），
±4GiB 位移上限。`ffffffc00aa41b98` 是内核**线性映射（linear map）别名地址**——
模块里某处引用了线性映射中的对象（本例：符号墙自举（§5）里的 kprobe 注册路径
触发的内核数据引用），而模块本体代码段的 VA 与线性映射区相距 **≈16GiB**，
ADRP 的 21 位页位移（±4GiB）数学上必然溢出。这不是符号未定义（那是 ENOENT、
报 `Unknown symbol`），而是**重定位编码容量**问题。

**验证法：ELF `.rela` 直方图**（对 `.ko` 逐段统计 `r_info & 0xffffffff`）——

| 产物 | size (B) | type 275 | 总重定位 | 说明 |
|---|---|---|---|---|
| `kernelsu_weak.ko` | 5,369,873 | 1,222 | 143,640 | 弱符号试验版 |
| `kernelsu_final.ko` | 8,676,401 | **1,497** | 241,427 | 修复前（考古留档） |
| `kernelsu.ko`（交付） | 8,757,024 | **0** | 244,047 | `-mcmodel=large` |

交付版指纹：`sha16 18be49fc8472f66b`（完整 sha256 见 CI 产物清单）。
直方图其余主力：type 258（`R_AARCH64_JUMP26`）225,421、type 257（`ABS64`）10,902、
type 283（`PLT32`）1,504 —— 全部是合法编码，无溢出风险。

**修复：**

```make
ccflags-y += -mcmodel=large
```

large 代码模型把所有数据寻址改成绝对寻址序列（不再依赖 ADRP ±4GiB），
type 275 从 1,497 **归零**（上表实测）。副作用是代码体积略增（+81KB，可接受）。

> 注：早期提交 e6df74e 把 dmesg 报错误记为 `R_AARCH64_PLT32`（type 283），
> 精确定位以本文为准：**275 = ADR_PREL_PG_HI21**。type 283 在直方图中 1,504 处、
> 由 PLT 机制正常消化，不是故障源。

## §5 符号墙（TRIM_UNUSED_KSYMS）与 kprobe 自举 + 转发定义

厂商内核 `CONFIG_TRIM_UNUSED_KSYMS=y`：只导出设备实际用到的符号白名单。
KernelSU 用到的 **49 个符号被裁**（`/proc/kallsyms` 可见但 `__ksymtab` 无条目 ⇒
`finit_module` 符号解析阶段 ENOENT，报 `Unknown symbol xxx (err -2)`）。

三层消解（`lkm-build/stubs/`）：

1. **kprobe 自举**：`kallsyms_lookup_name` 本身未导出 ⇒ 用 kprobe
   （`register_kprobe` 只需要已导出的符号）在运行期解析其余被裁符号的地址。
2. **44 个真转发定义**：为被裁符号提供真实函数体（转发到自举得到的地址），
   **弃用 `#define` 宏**（宏在取址场景失效）—— commit 8f4adfe 的教训。
3. **3 个自有符号空实现**：内核点名缺的最后 3 个 `Unknown symbol`
   （`selinux_hide` 存根缺的 3 个函数，commit 9a3c5fb）—— 本仓库空实现补齐。

**收敛判据：模块 `.symtab` 未定义符号数 = 0**（`analysis-scripts/findsym.py` /
`findsym2.py` 实时解析 `.symtab`/`.strtab`，对每个 `shndx==0` 的符号核对命中集合）。

构建侧注意：`TRIM_UNUSED_KSYMS` 在**构建机**上必须关闭
（`build-lkm.sh` 里 `scripts/config --disable TRIM_UNUSED_KSYMS`，并清空
`UNUSED_KSYMS_WHITELIST` —— 设备 config 里钉着 OPPO 内网路径，olddefconfig 会直接死）。
这只影响构建机导出哪些符号（多导无害），**不影响结构体布局**，ABI 安全。

## §6 SCM 门（CONFIG_MODULE_SCMVERSION=y）

厂商内核开了 `CONFIG_MODULE_SCMVERSION=y`：装载时比对模块 `.modinfo` 里的
`scmversion` 与内核自身值，**不一致即 -ENOENT**（无任何 dmesg 提示，安静失败）。

- 模块出厂自带 `.modinfo scmversion=g932014ab5b2c-dirty`（本地构建树 git 尾巴）→ 必死。
- 修法（`build-lkm.sh:83-97`）：编模块前把 `include/config/scmversion` 钉成
  设备 `uname -r` 的 g 尾巴 —— **`g74d132f4467a` 逐字对齐**（OTA 前基线）：

  ```bash
  rm -f .scmversion && touch .scmversion      # setlocalversion 输出空 ⇒ UTS_RELEASE 干净
  printf '%s' "$SCM_VER" > include/config/scmversion
  ```

- OTA 到 5.10.246 后 `uname -r` 的 g 尾巴变为 `g931a7e2ba585` ⇒ SCM 门值随之改变，
  产物也必须重钉重编（§9）。

## §7 稳定性工程：panic-on-wq-lockup 规避、门禁、减重、取证

**崩因 #1（定位过程）**：ksud 的加载路径会风暴式拉起/轮询大量进程，
在厂商内核（panic-on-workqueue-lockup 检测**开启**）上触发
`BUG: workqueue lockup` → panic。规避：**完全绕开 ksud 进程路径**，
改为 `ksu_min_load`（自卸式装载器，`lkm-build/minload/ksu_min_load.c`）内核内完成
模块解析与 `finit_module`，成功后 `return -E2BIG` 让内核把装载器模块自身卸掉不留痕。
采用后 workqueue lockup 事件归零。

**preflight 门禁**（每发之前自动检查，任一不满足不进入发射序列）：

| 门 | 阈值 | 含义 |
|---|---|---|
| fw | ≥ 2 | framework 关键进程存活数 |
| up | ≥ 240 s | 开机后静置时长（避让开机自启风暴） |
| load | ≤ 15 | 系统负载 |

**减重配方**（发射前环境变量，降低 prep 机器对时序的扰动）：
`PSELECT_SKIP_WARMUP=1` / `PSELECT_RETRY=1`（禁 8 轮连打——悬垂毒叠加 = 黑屏）/
`PSELECT_AP_HB=0` / `PSELECT_CONSUMER_CPU=6`（大核防饿）。

**跨重启取证**（设备侧 fs 不可信——`/data` 挂载 `fsync_mode=nobarrier`，崩溃后
取证文件必损坏为 `-?????????` inode 且永久钉死）：采集器写
`/data/local/tmp` 的 crash 快照 + **trace 直写调用者 stdout（adb socket）+ host 侧 `tee`**。

**战绩**：设备 6 次死机（workqueue panic / 看门狗复位）全部救回——
软重启 `setprop sys.powerctl` / sysrq / 物理电源键组合，无一次进 9008。
最终稳定运行 **27h+ 无 crash**（`uptime` 连续、`oops=0`）。

## §8 与 DirtyFrag 思想对照（仅思想，零代码）

研究对象：DirtyFrag（CVE-2026-43284）社区生态，重点解析 DFRoot（diabl0w/DFRoot）
及其 fork（mitschud）—— **仅做源码阅读与二进制结构解析，未复制任何代码**。
本仓库所有对应实现（`lkm-build/minload/ksu_min_load.c`）为原创，文件头注明思想出处。

**思想对照表：**

| 思想 | DirtyFrag 侧做法（读到的） | 本仓库对应实现 |
|---|---|---|
| 装载器形态 | dfroot.ko ≈11KB、7 符号、umh 模型 | ksu_min_load.ko 240,576B，自卸式（-E2BIG 自毁） |
| 内核态提权后处理 | 页缓存清理（抹 exploit 痕迹） | 同思想原创实现 |
| 厂商反 root | DEFEX 相关空实现 | 同思想原创实现（`stubs/`） |
| helper 拉起 | 绕 `STATIC_USERMODEHELPER` | 同思想原创实现 |
| bootstrap | umh（usermode-helper）bootstrap | 内核内直接 finit_module，不走 umh 拉起进程 |

**8 个 KMI 的二进制对照**（DFRoot 仓库内 8 个预编译模块的 vermagic / 重定位普查，
只读解析其 ELF 元数据，未运行、未分发）：

| KMI | vermagic 尾 | 观测 |
|---|---|---|
| android12-5.10 | `-android12-9` | 与本机同 KMI ⇒ 装载可行域内 |
| android12-5.15 | `-android13-4` | 不同 KMI ⇒ 仅作对照 |
| android13-5.10 / 5.15 | … | 同上 |
| android14-5.15 / 6.1 | … | 同上 |
| android15-6.6 | `-android15-8` | 同上 |

结论：DFRoot 的 umh 模型依赖 `call_usermodehelper` 路径在本机被厂商加固干扰；
本仓库改走"内核内直解 finit_module + 自卸"，路径更短、可观测性更强。
此为**思想借鉴的边界**：架构取向受其启发，代码与工艺全部自研。

## §9 OTA 后（5.10.246）root 迁移观察

OTA 把内核从 `5.10.236-android12-9-o-g74d132f4467a` 推到
`5.10.246-android12-9-o-g931a7e2ba585`（verifiedbootstate 仍 green，BL 仍锁）。

- **KMI 不变**（`android12-5.10`）⇒ 已装载的 `kernelsu` 模块跨 OTA 存活观察成立
  （Live in `/proc/modules`，`kernelsu 225280` 字节常驻）。
- **SCM 门值随内核变**（§6）：g 尾 `g74d132f4467a → g931a7e2ba585` ⇒ 重编模块必须重钉。
- **最终 root 到手路径**：OTA 后经 **ReSukiSU manager** 的 late-load 完成装载
  （manager 形态自带与本机 KMI 匹配的 LKM，且装载流程不依赖 ksud 风暴路径），
  装载后：`/system/bin/su` 就位、`su -c id → uid=0 … context=u:r:ksu:s0`、
  **SELinux 保持 Enforcing**。
- 观察结论：5.10 KMI 的小版本 OTA 对本链**不构成结构性威胁**；真正的断点只会在
  KMI 代际更替（5.10 → 5.15+）时出现——符号墙集合、结构体偏移、SCM 值全部重推。

## §10 待办

- **原创增强版 `ksu_min_load` 在途**：当前 `ksu_min_load.c` 是"最小可装载"版本
  （240,576B），增强版计划：内核内符号墙自举的固化（把 §5 的三层补丁折叠进装载器）、
  OTA 版本自适应 scmversion 钉定、装载后自证（`/proc/modules` 校验）与自毁的原子化。
- `exploit-v29` 与 `lkm-build` 的两阶段（写原语 → 装载）目前是手动衔接；
  计划提供单一驱动脚本串联 preflight 门禁（§7）。
- 符号墙集合（§5 的 49 符号清单）固化为数据文件，便于 KMI 代际更替时做 diff。
- LICENSE 顶层文件化（当前许可声明在 README §开源协议 与 `exploit-v29/NOTICE.md`）。

---

*本文档由 oppo-ghostlock 仓库维护；实测数据截至 2026-10-29，设备状态与 OTA 基线见 §1/§9。*
