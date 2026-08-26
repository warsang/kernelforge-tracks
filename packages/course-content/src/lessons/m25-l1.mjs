/** Lesson body: m25.l1 — architectural hooks: MSR / IDT / GDT attack theory (markdown). */
export default `## Hooks below the kernel's data structures

Before tables and pointers, dispatch itself lives in **CPU registers**:

| surface | what it decides | the hook |
|---|---|---|
| \`IA32_LSTAR\` (0xC0000082) | where every \`syscall\` lands | point it at your handler — you see every system call |
| \`IA32_SYSENTER_EIP\` (0x176) | 32-bit \`sysenter\` landing | same idea, legacy path |
| IDT (via IDTR) | which routine services INT n / exceptions | keylog at interrupt level, fake faults |
| GDT (via GDTR) | privilege boundaries themselves | ring transmutation games |

One WRMSR and the entire syscall boundary is yours — no table entries,
no code bytes, nothing for a scanner to diff.

## ...and why you do not do this on x64

PatchGuard treats exactly these structures as protected state. Install
an LSTAR redirect and the next sweep ends the machine:

\`\`\`
*** STOP: 0x00000109  CRITICAL_STRUCTURE_CORRUPTION
\`\`\`

Under HVCI/VBS the hypervisor refuses the write outright. These
techniques survive today only under an \`\`own\`\` hypervisor (m22/m28) or
on systems old enough to predate the verifier.

## The lab worlds

\`arch-hooks\` models the legacy regime: mini-PatchGuard sweeps on the lab
clock, MSR drift included in its checks.

\`\`\`
kd> !msr lstar                    ; baseline: KiSystemCallHandler thunk
kd> !syscalltest                  ; honest completion
kd> !msr lstar 0xfffff8055a760800 ; the redirect (kfarch.sys handler)
kd> !syscalltest                  ; FOREIGN handler executes -> 0xdead0004
kd> !pgscan                       ; [arch] IA32_LSTAR DRIFT ...
kd> !dpcpump 4                    ; cross a sweep -> 0x109
\`\`\`

\`arch-hardened\` runs the same world with HVCI on: the WRMSR dies
instantly.

## Who catches this in the real world

- **PatchGuard: immediate** — this is its home turf.
- **HVCI/VBS: refuses the write** (modeled faithfully by both worlds).
- **EDRs**: rdmsr attestation of LSTAR/SYSENTER against the ntoskrnl
  image range from their own kernel driver — your Sentinel v6 lab.
`;
