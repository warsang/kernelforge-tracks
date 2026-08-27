/** Lesson body: m18.l1 — Linux syscall-table rootkits (markdown). */
export default `## The table without PatchGuard

Linux keeps its system-call dispatch in an array any kernel module can
read — and historically, write. kfhooksy.ko in this guest replaced one
entry of \`sys_call_table\` with a trampoline to its own code. No
kallsyms lie protects it; only cross-checking does.

## The lab

1. Resolve \`__NR_kill\` for i386 (frozen ABI — your first answer).
2. Write a detector module that walks sys_call_table via kallsyms and
   compares each entry's containing symbol against expected prefixes.
   Mismatch -> print your detector secret (KFFLAG over serial).
3. Restore the original pointer (save before overwrite semantics apply;
   the villain exports \`kfhooksy_restore()\`) and confirm the clean
   sweep prints the surrender secret.

## Detection theory

One honest pointer comparison beats heuristics: legit entries always
live inside core-kernel text. The same cross-accounting idea powers the
m9 task-hide detector and Windows hypervisor introspection — trust
independent views, not self-reported state. kernel-internals.org's
syscall-entry and page-table chapters are the map for this terrain.

### Further reading

- kernel-internals.org — System Calls / Syscall Entry Path / Page Tables (CC BY-SA)
- LWN.net — syscall auditing and seccomp series
- Linux source — arch/x86/entry/syscall_64.c, kernel/kallsyms.c
`;
