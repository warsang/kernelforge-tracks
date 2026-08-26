/** Lesson body: m28.l1 — VM-exit MSR interception (markdown). */
export default `## The only way to hook syscall flow without PatchGuard

Every technique in this course that touches LSTAR/IDT/GDT ends in 0x109.
The ONLY escape is to own layer two: run a hypervisor below the kernel,
intercept RDMSR/WRMSR via VM-exit, and fake success. The guest thinks the
write landed; the hypervisor stores whatever it wants. PatchGuard never
sees the divergence because it reads through the same intercepted path.

## The model

\`msr-exit\` extends the \`ept-shadow\` world with a hypervisor that traps
LSTAR writes. When the guest executes \`wrmsr 0xC0000082, <addr>\`:

1. CPU exits to VMX root (hypervisor mode)
2. Hypervisor handler sees the attempt, can modify the value
3. Hypervisor returns to guest; guest thinks write succeeded
4. Guest's subsequent \`rdmsr\` also exits; hypervisor returns its stored value

The guest's view of LSTAR is whatever the hypervisor decides. The real
LSTAR (what syscalls actually use) is the hypervisor's value.

## The lab

\`msr-exit\` boots with kfhyp.sys already intercepting LSTAR. Your job:

1. Install a redirect via \`!msr lstar <addr>\` (the guest thinks it wrote)
2. Prove the redirect via \`!syscalltest\` (the guest sees its value)
3. Detect the hypervisor via \`!vmexit\` (the trap log shows the divergence)

The hypervisor's handler fakes success on WRMSR but stores a different
value. RDMSR returns the hypervisor's value, not the guest's.

## Detection

Two techniques catch this:

1. **Timing divergence**: RDMSR under hypervisor takes longer (VM-exit
   overhead). \`!vmexit\` shows the trap log with tick counts.
2. **Consistency check**: Read LSTAR twice with a serializing instruction
   (CPUID) between. If the hypervisor modifies the value between reads,
   the two reads disagree. This lab's defense sensor does exactly that.

## Who catches this in the real world

- **PatchGuard: blind** — it reads through the same intercepted path.
- **Timing-based detectors**: EDRs measure RDMSR latency; VM-exit adds
  ~1000 cycles. Your lab's \`!vmexit\` shows the tick divergence.
- **CPUID/serializing consistency**: read MSR, CPUID, read MSR again;
  divergence = hypervisor owns it.
- **Hypervisor introspection**: if you're under someone else's hypervisor
  (Hyper-V, VMware), their integrity monitors see YOUR hypervisor.

## The arms race

This is the final layer. Below this is SMM (m11-m13) and firmware. Every
layer can hide from the layer above. The only way to detect a hypervisor
is to run code outside it — which requires ring -2 (SMM) or physical
access.
`;
