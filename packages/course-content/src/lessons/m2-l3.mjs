/** Lesson body: m2.l3 — Attack workshop: four kernel IRQL/DPC techniques (markdown). */
export default `## Ground rules for this module

Everything you compile here runs against the **irql-attackers** world: a
healthy DISPATCH-level machine running \`kvmdrv.sys\` with one queued DPC,
one periodic timer-DPC and a protected canary page. Every technique below
is a real documented attacker pattern — the sources at the bottom map each
lab to its origin. The model is honest about simplifications: directed
cores are side-state (\`!irql -a\`), the clock advances only when you pump
it (\`!dpcpump\`), and drain re-reads \`DeferredRoutine\` from memory so
post-insert patches bite exactly like the real retire path.

## Attack 1 — WPOFFx64: patch read-only memory inside a raised window

The classic (public cheat loaders ship this verbatim): clear CR0.WP inside
an uninterruptible DISPATCH window, copy your bytes, restore.

\`\`\`c
KIRQL irql = KeRaiseIrqlToDpcLevel();   // own core -> 2
UINT64 cr0 = __readcr0();
__writecr0(cr0 & ~(1ULL << 16));        // WP off
_disable();
RtlCopyMemory((void *)CANARY, detour, sizeof(detour));   // tamper
__writecr0(cr0);                        // WP on
_enable();
KeLowerIrql(irql);
\`\`\`

Note what the raise buys: not permission — \`mov cr0\` needs no IRQL — but a
window where no timer DPC, APC or scheduler slot can interleave. Load it,
then prove the damage from the debugger: \`!pgscan\` shows the canary delta
and the CR0.WP history; \`!dpcs\` still drains fine because you *restored*.
Flags: the IRQL inside the window, and the restored CR0 value.

## Attack 2 — Directed-DPC CPU lockdown

One core raising itself is per-CPU; to touch structures other cores race
on, rootkits park **every** core at DISPATCH with spinning DPCs:

\`\`\`c
for (ULONG i = 1; i < KeQueryMaximumProcessorCount(); i++) {
    KeInitializeDpc(&dpc[i], SpinRoutine, NULL);
    KeSetTargetProcessorDpc(&dpc[i], (CHAR)i);   // direct at core i
    KeInsertQueueDpc(&dpc[i], NULL, NULL);       // raises core i to 2
}
// ... kernel structures exposed while every other core is pinned ...
KfReleaseDirectedDpcs();                          // lab release primitive
\`\`\`

Load the starter, then run \`!irql -a\`: cores 1–3 report IRQL 2. Comment
out the release line, reload, and run \`!dpcwatchdog\` — residency over
budget is exactly what \`KiProcessExpiredTimerList\` polices in production.

## Attack 3 — Timer-DPC persistence

A \`KTIMER\` whose DPC points at payload code re-arms forever:

\`\`\`c
KeInitializeTimer(&timer);
LARGE_INTEGER due; due.QuadPart = -(LONGLONG)3;      // 3 ticks from now
KeSetTimerEx(&timer, due, 5, &dpc);                  // period 5 ticks
\`\`\`

Nothing fires until time passes — advance it with \`!dpcpump 13\` and watch
\`!dpcstat\`: the payload ran at +3, +8, +13. This is why EDRs treat an
armed timer whose routine lives in an unknown module as persistence, and
why \`% DPC Time\` telemetry exists.

## Attack 4 — KDPC.DeferredRoutine hijack

The queue stores a pointer; pointers can be rewritten. The victim DPC is
already queued by \`kvmdrv.sys\` — no allocation, no insertion:

\`\`\`c
((PKDPC)VICTIM_DPC)->DeferredRoutine = HijackRoutine;
\`\`\`

Then \`!dpcdrain\`. The retire path re-reads the routine from memory, so the
victim's slot executes *your* function at DISPATCH_LEVEL — and the model's
drain log prints the patched address next to the insert-time snapshot,
which is precisely the forensic artifact defenders grep for. \`!pgscan\`
flags any deferred routine pointing outside known modules.

## Debugging discipline

Every lab boots the WinDbg emulator pane. The loop is always:
compile → load → observe world state (\`!irql -a\`, \`!dpcs\`, \`!dpcstat\`,
\`!pgscan\`) → advance or drain (\`!dpcpump\`, \`!dpcdrain\`) → read the
evidence out of DbgPrint and the modeled logs. If you break the machine,
reload the scenario — the world resets.

## Sources

- OffSec blog, *IRQLs: Close Encounters of the Rootkit Kind* (Malvica,
  2022) — Attacks 2's raise/pin/tamper/release flow, including the exact
  \`KeSetTargetProcessorDpc\` spin-loop.
- Little-Ki, public gist *"[Kernel] IRQL, memory protection and memory
  modify"* — the WPOFFx64/WPONx64 pairing Attack 1 reproduces
  (gist.github.com/Little-Ki/ca9d88101f59e27b0a5feed73d6f748c).
- benjamindoron/vGPU-Unlock-Patcher — the same CR0.WP (+CR4.CET)
  flip-and-restore cycle used by legitimate runtime patchers.
- McAfee Labs, *Analyzing the Uroburos PatchGuard Bypass* (2014) —
  in-the-wild manipulation of the DPC retire path.
- GenX Cyber, *DPCs: Deferred Procedure Calls and Interrupt Deferral*
  (2026) — the CPU-lockdown / timer-DPC-persistence / DeferredRoutine-
  hijack taxonomy these labs implement one-for-one.
- MITRE ATT&CK T1014 (Rootkit), T1068, T1562.001.
`;
