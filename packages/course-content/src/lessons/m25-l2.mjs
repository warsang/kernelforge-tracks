/** Lesson body: m25.l2 — architectural hooks: defense & attestation (markdown). */
export default `## Defending the registers you cannot watch

You are a kernel driver; the MSR file is CPU state, not memory. You
cannot diff bytes — but you can **read and reason**:

## rdmsr attestation

1. At boot, record \`IA32_LSTAR\` / \`IA32_SYSENTER_EIP\` (a healthy value
   points into the ntoskrnl image).
2. Periodically re-read. Convict on:
   - **drift**: any change from boot baseline;
   - **containment**: a target outside \`\[nt base, nt base+size\)\` is
     foreign no matter what it was at boot.
3. The same loop over the IDT: 32 handler reads, containment check,
   verdict per vector.

This is Sentinel v6 — the same poll-diff-convict skeleton as v3/v5/v7,
aimed one layer lower than tables.

## Why the ceiling matters more

Every architectural hook lab ends in 0x109 because that IS the modern
answer: Microsoft moved enforcement below the kernel (PatchGuard's
obfuscated periodic sweeps; HVCI's hypervisor-enforced write refusal).
The defensive lesson is not "write a better sensor" — it is knowing
**which layer actually owns each structure**, and that LSTAR/IDT/GDT are
owned by layers you must assume are watched.

## Who catches this in the real world

- **HVCI/VBS**: hardware-assisted refusal — no driver code required.
- **EDR kernel sensors**: rdmsr loops exactly like your v6.
- **Hypervisor-based integrity roots** (m22's dual-view idea applied
  defensively): reads from outside any guest tampering.
`;
