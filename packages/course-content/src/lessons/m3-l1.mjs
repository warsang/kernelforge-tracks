/** Lesson body: m3.l1 — Inline hooks & control flow (markdown). */
export default `## What an inline hook is

Instead of replacing a pointer table (SSDT-style), an **inline hook** rewrites
the first bytes of a function's prologue to jump somewhere else — usually a
\`jmp rel32\` (\`E9 xx xx xx xx\`) into the attacker's code. Every caller,
kernel or user, now flows through the attacker first. The original instruction
bytes are typically copied to a trampoline so the hook can call the real
function and still look innocent.

## Reading a detour from a debugger

You cannot ask the kernel "are you hooked?" — you compare memory against
truth. Truth here is the pristine prologue recorded when each \`nt!\` export
was materialized:

\`\`\`
kd> !hookscan                       # diff live vs pristine for every export
kd> !hookscan PsLookupProcessByProcessId
kd> u nt!PsLookupProcessByProcessId L5    # disassemble the prologue yourself
\`\`\`

A clean export prints its expected bytes; a hooked one shows both byte
streams plus where the jump lands (symbolized as module+offset). Repair is
the same primitive you used in the manual-map lab:

\`\`\`
kd> eb <thunk_addr> f4              # restore the original first byte(s)
\`\`\`

Because behavior gates on *live bytes*, restoring them instantly unhooks the
call — no reboot, no state flag.

## Prove it

\`\`\`
kd> !hooktest <Export> [args...]    # exercise the modeled call path
\`\`\`

Run it before and after your repair; the difference in return value **is**
the hook's payload.

## The lab

The world ships \`kfhook.sys\`. It detoured one executive routine so that
lookups for one specific PID come back \`STATUS_INVALID_PARAMETER\` — that
process has become unkillable-by-name for anything above it in the stack.

1. \`!hookscan\` → which export is detoured? (answer 1: exact export name)
2. The hook suppresses exactly one decimal PID. Find it — the detour page's
   strings and \`!hooktest\` probes will tell you. (answer 2)
3. Restore the prologue with \`eb\`, then \`!hooktest\` the lookup again:
   submit the symbolic NTSTATUS that comes back. (answer 3)

Then flip sides in the second lab of this lesson (\`Author the detour
yourself\`): use \`x nt!PsLookup*\`, \`u\` and \`sym\` to find the export's
address, paste it into the driver template, compile and load it — and watch
\`!hookscan\` convict *your* bytes.

## Custom debugger extensions in this lab

- \`!hookscan [export]\` — **lab extension**: diffs every export's live
  prologue against the pristine snapshot taken at boot and symbolizes the
  detour target.
  *Driver equivalent* — the core loop of any EDR/anticheat integrity engine:
  \`\`\`c
  // Attest one export: resolve honestly, compare with known-good baseline.
  NTSTATUS AttestExport(const char *name, PVOID fn,
                        const UCHAR baseline[8])
  {
      UCHAR live[8];
      RtlCopyMemory(live, fn, sizeof(live));       // read current bytes
      if (RtlCompareMemory(live, baseline, 8) != 8) {
          DbgPrint("sensor: %s @ %p HOOKED\\n", name, fn);   // telemetry
          return STATUS_INVALID_IMAGE_HASH;
      }
      return STATUS_SUCCESS;
  }
  // fn comes from MmGetSystemRoutineAddress(L"PsLookup...") or direct import
  \`\`\`
- \`!hooktest <exp> [args]\` — **lab extension**: exercises the modeled call
  path so you can *prove* suppression behaviorally. A driver does this by
  simply calling the API under test and checking results against expectation.
- \`u\`, \`x\`, \`?\`, \`sym\`, \`eb\`, \`db ... L<len>\` are native-engine
  commands (present in real WinDbg) — our implementations decode real x64 via
  capstone and resolve symbols from the same tables the kernel model uses.

## Defensive framing

Inline hooks on \`nt!\` exports are the granddaddy of rootkit techniques and
still show up in game cheats (render/present hooks) and implants alike.

**Detection families**, roughly in order of deployment cost:

1. **Periodic prologue attestation** — exactly what you just did by hand and
   what \`AttestExport\` does from ring 0; production ships SHA-256 tables of
   each hot export's first N bytes captured at build time.
2. **Call-target validation on the hot path** — before calling an executive
   routine, verify its first instruction is not an unconditional transfer;
   cheap, catches lazy hooks mid-flight.
3. **Self-protection via MDL**: EDRs make their own callbacks read-only so
   attackers cannot simply hook *them* back:
   \`\`\`c
   // Make a driver function page read-only (defender-side hardening)
   PVOID ForceReadOnly(PVOID func)
   {
       ULONG_PTR page = (ULONG_PTR)func & ~0xFFFull;
       PMDL mdl = IoAllocateMdl((PVOID)page, PAGE_SIZE, FALSE, FALSE, NULL);
       if (!mdl) return NULL;
       MmBuildMdlForNonPagedPool(mdl);
       *(BOOLEAN *)((PUCHAR)mdl + 0x0F) = TRUE;        // MDL_PAGES_LOCKED
       return MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached,
                                           NULL, FALSE, HighPagePriority);
   }
   \`\`\`
4. **Hypervisor EPT shadow execution** — the host executes from a pristine
   copy while the guest sees its own patched view; mismatches become alarms.
5. **kCFG / XCFG** — control-flow guard technologies make wild jump targets
   fail validation before they ever execute.

In m3.l2 you compile **KF-Sentinel v3**: a full attestation engine that
resolves critical exports and convicts both the shipped kfhook.sys detour and
the one you authored yourself.
`;
