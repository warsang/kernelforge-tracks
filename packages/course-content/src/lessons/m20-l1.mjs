/** Lesson body: m20.l1 — Kernel hooks & integrity monitoring (markdown).
 *  Taxonomy of kernel hooking plus the fake mini-PatchGuard timing lab. */
export default `## Every hook is a bet against a verifier

A kernel hook redirects control flow or data so the kernel answers the way
you want. The mechanism is almost boring — overwrite a pointer, patch a
prologue, swap a table entry. The engineering is in the **bet**: every hook
lives in memory someone else may be watching. This module is about the
watchers.

## The kernel hook taxonomy

| technique | what it touches | example | visibility |
|---|---|---|---|
| SSDT/SSDT shadow hook | \`KiServiceTable\` entry | re-route \`NtOpenProcess\` | one pointer, table is cached & checked |
| inline (prologue) hook | first bytes of an export | \`E9\` detour over \`PsLookupProcessByProcessId\` | bytes differ from the signed image |
| MSR/LSTAR hook | the syscall entry register | filter every syscall | \`rdmsr\` shows a non-ntoskrnl target |
| IDT hook | an interrupt descriptor | keylogger at interrupt level | descriptors point outside HAL/nt |
| kernel callbacks | notify-routine arrays | \`PsSetCreateProcessNotifyRoutineEx\` | array slots readable via \`!notifyroutines\` |
| DPC/timer hijack | \`_KDPC.DeferredRoutine\` | deferred execution payload | drift between insert-time and live value |

You have already fought on both sides of several rows: m3 hooked an export,
m15 registered sensors, m2.l3 hijacked a \`DeferredRoutine\`, m16 hooked the
SSDT. What none of them had to survive was the verifier.

## PatchGuard: the verifier that ships with Windows

**Kernel Patch Protection** (PatchGuard) periodically validates structures
Microsoft has decided you may not modify: the SSDT, the IDT, the GDT, core
MSRs, selected \`ntoskrnl\` globals and code pages, and key driver callback
arrays. When a sweep notices a difference from its recorded baseline it
does not repair anything and it does not warn anyone —

\`\`\`
*** STOP: 0x00000109 (0x...,0x...,0x...,0x...)
CRITICAL_STRUCTURE_CORRUPTION
\`\`\`

The machine bugchecks. That is the whole enforcement model: tampering with
protected state must cost more than it gains. Three consequences matter:

1. **PG-compliant hooks** never touch protected state: documented
   callbacks, minifilter/fltmgr filtering layers, your own driver's
   objects, hypervisor EPT tricks below the OS. They coexist with
   PatchGuard by construction.
2. **Non-compliant hooks** (most of the table above) work until a sweep
   lands while they are installed. Real PG randomizes its period heavily;
   our lab model uses a fixed, visible period so you can *learn the race*.
3. The classic evasion is therefore **temporal, not spatial**: install the
   hook, do the read/write you needed through it, restore pristine bytes —
   all between two sweeps. You are not hiding the hook from PG; you are
   hiding the *window*.

## The mini-PatchGuard model

This platform ships a small honest model of that arms race (\`!pgstatus\`):

\`\`\`
kd> !pgstatus
mini-PatchGuard state
  period: every 4 tick(s)   sweeps: 1   last @ tick 1048580   next in 2
  protected regions: 4
    nt!PsLookupProcessByProcessId  fffff80100000030 (+0x8 bytes)
    ...
\`\`\`

Sweeps ride the same lab clock as DPCs and timers (\`!dpcpump N\` advances
it). Each pass re-reads the protected regions and compares them against
the bytes captured at boot — exactly how a checksum-based verifier works,
minus the randomness and the obfuscation.

## The lab

Boot the \`pg-hooks\` world. Four regions are watched; the interesting one is
the \`PsLookupProcessByProcessId\` thunk, whose prologue suppresses pid 888
lookups when it reads as detoured (the m3 mechanic). Your run has three
acts — find the thunk address with \`x nt!PsLookup*\` first:

\`\`\`
kd> eb <thunk> e9 00 00 00 00                  # act 1: install the hook
kd> !hooktest PsLookupProcessByProcessId 888   # ...and USE it
kd> eb <thunk> f4 00 00 00 00 00 00 00         # act 2: restore pristine bytes
kd> !dpcpump 4                                 # act 3: cross a sweep cleanly
kd> !pgstatus                                  # verdict + secret
\`\`\`

Get greedy — leave the \`E9\` in place across a sweep — and the world
bugchecks \`0x109\` with the CPU halted. Reboot and retry; that failure IS
the lesson. Compare with the PG-compliant alternative: unregister nothing,
patch nothing — register your interest through documented callbacks (m15)
or filter below the OS (module 21).

## Flags

1. The bugcheck code a caught hook earns (decimal, as in the STOP line).
2. How many regions \`!pgstatus\` reports as protected.
3. The completion secret printed when your window stayed closed.
`;
