/** Lesson body: m7.l1 — Linux LKM fundamentals (markdown). */
export default `## A different kernel, the same ideas

The Windows track ran on ntsim — a model of ntoskrnl. The Linux track runs
a **real Linux kernel**: an i386 Buildroot guest booted by the v86 emulator
inside your browser tab. Real syscall table, real scheduler, real module
loader.

Loadable kernel modules (LKMs) are the Linux equivalent of the .sys
drivers you wrote in Module 1:

    #include <linux/module.h>
    #include <linux/init.h>

    static int __init kflag_init(void)
    {
        pr_info("kflag: loaded\\n");
        return 0;
    }

    static void __exit kflag_exit(void)
    {
        pr_info("kflag: unloaded\\n");
    }

    module_init(kflag_init);
    module_exit(kflag_exit);
    MODULE_LICENSE("GPL");

Compile with \`--target=i386-linux-gnu\`, push the \`insmod\`-able \`.ko\`
into the guest, and read \`dmesg\`. The harness captures serial output;
lines carrying the \`KFFLAG\` magic are your lab channel.

For userspace debugging, the guest speaks the GDB remote protocol over its
second serial port: start a target with \`gdb start /root/lab/app\` in this
console (the buildroot image carries gdb-server) and a full gdb-style
debugger docks above — breakpoints, single-step, registers, memory. Classic
syntax throughout: \`b *0x8048074\`, \`c\`, \`si\`, \`x/8xw $esp\`, \`info registers\`.

## Syscall numbers are ABI

Unlike Windows syscalls (numbers change every build), Linux syscall
numbers are a frozen ABI per architecture. On i386:

| nr | syscall |
|----|---------|
| 11 | execve |
| 128 | init_module |

Ten-year-old shellcode still works because of this stability.

## The lab

Boot the \`lkm-hello\` world (v86 boots the buildroot image; first boot
takes a moment, later boots restore from snapshot), then in the IDE tab:

1. Write a module that prints its own greeting and the answer to:
   *which decimal syscall number is init_module on i386?* (submit it)
2. Extend the module to read \`/root/.kflag\` from kernel space
   (\`filp_open\` + \`kernel_read\`) and print it with the KFFLAG prefix.
   Submit the file's secret string.

## Defensive framing

Everything you learned about rootkit-shaped behavior on Windows has a
Linux mirror: module unlinking ≈ DKOM, ftrace/kprobe hooking ≈ inline
detours, eBPF abuse ≈ callback tampering. The detection stack differs
( lockdown mode, module signing, kallsyms restrictions) but the threat
model maps one-to-one.
`;
