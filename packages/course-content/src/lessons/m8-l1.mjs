/** Lesson body: m8.l1 — Syscall internals & tracing (markdown). */
export default `## Watching the syscall boundary

Every userland action crosses into the kernel through one choke point.
On i386 the path is \`int 0x80\` → entry code → \`sys_call_table[nr]\`.
That table is the master switchboard; nearly every classic Linux hook
technic starts by reading or redirecting it.

## Tracing without patching

Modern kernels let you observe without modifying: **kprobes** fire a
handler at any symbol address, pre-entry:

    static struct kprobe kp = { .symbol_name = "sys_execve" };

    static int handler(struct kprobe *p, struct pt_regs *regs)
    {
        pr_info("kfflag: execve hit\\n");
        return 0;
    }

    register_kprobe(&kp);

Run \`/bin/true\` in the guest and your handler prints. This is the same
instrumentation idea as ETW/EDR telemetry on Windows — and the same
primitive abused by stealthy rootkits when registration goes through
unofficial doors.

## The lab

Boot the \`syscall-trace\` world, then:

1. Submit the decimal i386 syscall number your probe must target to see
   program execution: execve.
2. Write the kprobe module, run the trigger binary (\`/root/trigger\`)
   inside the guest, and submit the secret your handler prints.

## Defensive framing

Production detection uses exactly these primitives defensively: auditd,
eBPF-based runtime security (fentry/fexit programs), and integrity
monitoring of \`sys_call_table\` pages. Knowing where the boundary sits
and how to observe it non-invasively is the difference between an EDR
and the malware it chases.
`;
