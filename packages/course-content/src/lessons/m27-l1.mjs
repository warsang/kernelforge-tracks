/** Lesson body: m27.l1 — Linux kernel offense & defense survey.
 *  Sources: tmpout v4 Matheuzsec & Humzak711 (art of LKM rootkits),
 *  lil.skelly (procfs C2), v3 wintermute (arm64 svc patching),
 *  v5 bah (static kernel patching), PinkNoize (side-channel hook detection),
 *  elfmaster (gASLR), v2 FridayOrtiz (eBPF problems). */
export default `## Ring 0, both directions

No emulator here — this module is a survey across five volumes of tmp.0ut
kernel research: how rootkits hook a modern Linux, and how the same pages
betray them.

### Hooking in 2026

The sys_call_table hijack is legacy. The Art of Linux Kernel Rootkit
(Matheuzsec & Humzak711, #4) standardizes on three live surfaces:

- **ftrace** — \`ftrace_set_filter_ip\` + \`register_ftrace_function\`;
  demo hooks \`__x64_sys_kill\` with magic signal **59** → \`prepare_creds\`
  zeroing uid/gid/euid + \`commit_creds\`; port hiding hooks
  \`tcp4_seq_show\`/\`tcp6_seq_show\`.
- **kprobes** — \`register_kprobe\` on \`__x64_sys_setuid\` with a post_handler
  that mints full creds; no text patching at all.
- **eBPF** — kprobe programs via CO-RE reads; no LKM, no signature to strip.

Module hiding stays classic (\`list_del(&THIS_MODULE->list)\`); persistence
drops the \`.ko\` into \`/usr/lib/modules/$(uname -r)/kernel\` plus an
\`/etc/modules-load.d/*.conf\`. The anti-hunter trick: ftrace-hooking
\`__x64_sys_init_module\`/\`__x64_sys_finit_module\` with stubs that return 0
— insmod reports success while loading nothing.

C2 without kill signals: lil.skelly (#4) hooks the \`proc_read\` (\`seq_read\`)
member of \`proc_ops\` on **/proc/kallsyms** and hides one-byte commands
(\`0xFA\` hide / \`0xFB\` root) inside ordinary-looking read buffers,
authenticated by a CRC-32 — no anomalous real-time signals 32–64 for EDRs
to notice. wintermute (#3) goes arm64: patch \`el0_svc_common\`'s first five
instructions (0x14 bytes) into a trampoline that redirects selected syscalls
through a vmalloc'd **shadow syscall table**, flipping PTE write bits instead
of CR0.WP (no such register on ARM), all under \`stop_machine()\`.
bah (#5) attacks before boot: patch the on-disk bzImage (BIOS:
\`code32_start\` @ 0x214; UEFI: swap \`ExitBootServices\`) so ring 0 payload
code ships inside the kernel image itself.

### Finding them anyway

- Cross-accounting: \`nr_threads\` vs scheduler list (m9's villain lab).
- tracefs walking: \`available_filter_functions\`,
  \`enabled_functions\`, \`touched_functions\` (6.4+) — ftrace rootkits rarely
  hide there.
- Taint value **12288** in \`/proc/sys/kernel/tainted\` (out-of-tree+unsigned)
  and the taint line that survives \`dmesg -C\` in /dev/kmsg.
- Neutralization: \`echo 0 > /proc/sys/kernel/ftrace_enabled\` makes the whole
  ftrace class inert.
- PinkNoize (#5): **GhostCache** — timer-free L1i eviction fingerprinting on
  weakly-coherent ARM cores; deviations beyond **3σ** from baseline flag
  patched syscall paths, catching both diamorphine's table hijack and ~5-line
  ftrace detours without root.
- Hardening mirror: elfmaster's **Granular ASLR** (#5) transplants every
  global function into its own mapping through chained linking via
  \`PT_INTERP = /lib/shiva\` — one base leak no longer buys the binary.

FridayOrtiz (#2) closes with the defensive engineer's eBPF tax: a 512-byte
stack, 33 tail-call chains, verifier whims that differ per kernel version —
the same constraints attackers exploiting eBPF CVEs juggle in reverse.

## Lab — the survey gauntlet (quiz)

Seven flags, each pinning one fact from the survey above: the arm64 function
wintermute patches; the \`proc_ops\` member hooked for the kallsyms C2;
the tainted value unsigned diamorphine leaves behind; the BPF stack budget in
bytes; the UEFI boot service skp swaps; GhostCache's deviation threshold in
standard deviations; what gASLR stands for.

## Flags

See the lab prompts — formats are pinned per question (names lowercase,
numbers decimal).
`;
