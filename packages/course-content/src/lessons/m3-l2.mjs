/** Lesson body: m3.l2 — KF-Sentinel v3: prologue attestation (defense, markdown). */

export default `## Attestation: comparing memory against truth

You repaired a detour with \`eb\` in m3.l1 and wrote your own in the lab
that followed. Both times the *debugger* did the attestation: \`!hookscan\`
diffed live prologue bytes against a pristine snapshot. Your v3 sensor
moves that diff inside the kernel — the same comparison, running from your
own driver, on every boot and then periodically.

## The three ingredients

1. **Resolve the target honestly.** Your import of
   \`PsLookupProcessByProcessId\` links to the export's real address — the
   same pointer every caller uses. Production sensors use
   \`MmGetSystemRoutineAddress\` plus a second resolution path (pattern
   scan, exception-directory walk) because a hooked IAT/resolve path is
   itself an attack.
2. **Hold a known-good baseline.** Here it is one byte: the model's F4
   marker. Production ships SHA-256 tables of each export's first N bytes,
   captured from signed binaries at build time — which is why module
   updates force baseline refreshes.
3. **Compare and emit.**

\`\`\`c
UCHAR live = ((PUCHAR)PsLookupProcessByProcessId)[0];
if (live != BASELINE_FIRST_BYTE) { /* telemetry: INLINE HOOK */ }
\`\`\`

## What attestation catches — and what it cannot

| technique | caught? | why |
|---|---|---|
| E9 jmp over prologue | yes | first byte differs |
| mov rax, hook; jmp rax | yes | multi-byte rewrite |
| trampoline AFTER stolen instrs | no* | prologue restored verbatim |
| SSDT/shadow-table swap | no | different memory entirely |
| hypervisor shadow execution | no | guest sees pristine view |

*Prologue-restoring trampolines are why real sensors hash MORE bytes,
verify page permissions (no RWX), resolve call targets on the hot path and
let the hypervisor hold a second opinion. Attestation is a layer, never a
wall.

## Custom debugger extensions used

- \`!hookscan [export]\` — **lab extension**: diffs live vs pristine thunk
  bytes and symbolizes detour targets. Driver-equivalent is exactly your v3
  sensor: read bytes at the resolved export address, compare with baseline.
- \`!hooktest <exp> [args]\` — **lab extension**: exercises the modeled call
  path so behavior proves or disproves suppression. A driver does this by
  simply calling the API and checking results against expectations.

## Defensive framing — production control-flow integrity

- **Periodic attestation loops**: anticheats re-hash hot exports every few
  seconds from a worker thread; EDRs do the same for their own drivers —
  self-integrity first, then the kernel.
- **kCFG / XCFG**: hardware-virtualization-assisted control-flow guards
  make indirect transfers fail unless the target is a validated start;
  wild detour targets die before executing.
- **HVCI + arbitrary code guard**: kernel memory is no longer both
  writable and executable, so the classic "copy trampoline, patch prologue"
  flow needs yet another exploit primitive first.
- **Hypervisor shadow views**: the strongest answer executes instructions
  from an EPT-shadowed copy; guests patching their own text see only their
  own copy — detection falls out of the mismatch.

Compile the starter against the api-hook world (the same world you
un-hooked in m3.l1) and watch it convict kfhook.sys's detour from inside.
`;
