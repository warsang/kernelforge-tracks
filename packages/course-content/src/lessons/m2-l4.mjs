/** Lesson body: m2.l4 — Defense workshop: watchdogs, telemetry, deadlines, ceilings (markdown). */
export default `## The four defenses, and what each one catches

| # | defense | real-world form | catches |
|---|---|---|---|
| 1 | sampling + queue telemetry | EDR DPC monitors, \`% DPC Time\` | pinned cores, stranded queues |
| 2 | self-watchdog deadline alarm | anticheat heartbeat DPCs | anything that steals the scheduler |
| 3 | integrity scan (\`!pgscan\`) | PatchGuard / HVCI policy | patched bytes, hijacked routines |
| 4 | hypervisor/VBS ceiling | HVCI intercepting CR0 writes | the WPOFFx64 technique itself |

## Lab 1 — telemetry sensor on the pinned world (m2.l1's crime scene)

Compile \`SENTINEL-TELEMETRY\` against the original pinned-IRQL world. It
samples \`KeGetCurrentIrql\`, reads the modeled pending-DPC depth
(\`KeQueryDpcQueueDepth\` — the lab's stand-in for walking
\`_KPRCB.DpcData\`), restores DISPATCH_LEVEL and lets you drain. This is
defense #1: behavior over time beats structure snapshots because a clean
structure with a parked core is still a compromised machine.

## Lab 2 — self-watchdog deadline alarm

Anticheats do not trust their own execution context; they schedule a
watchdog DPC and alarm if it misses its deadline. Your starter pins the
other cores (the Attack-2 primitive) *and* arms a periodic timer-DPC
targeted at core 1. A healthy core retires it within a tick; a locked-down
core cannot. The driver polls the clock, sees the deadline slip, and
reports **MISSED** — the same class of signal commercial anti-cheat products raise
when someone parks the scheduler. Run \`!dpcstat\` afterwards: the aged-DPC
anomaly line is the same finding from the outside.

\`\`\`c
KeSetTargetProcessorDpc(&wdDpc, 1);          // watchdog lives on core 1
KeInsertQueueDpc(&wdDpc, NULL, NULL);        // ...which we just pinned
// ticks pass; the routine cannot run while core 1 is at DISPATCH
if (!g_fired) DbgPrint("SENTINEL-WD: DEADLINE-MISSED\\n");
\`\`\`

## Lab 3 — forensics sweep with the emulator

A debugger-only lab on the clean world: establish the baseline before any
attack runs. \`!dpcstat\` shows the heartbeat timer's period;
\`!irql -a\` shows every core idle; \`!pgscan\` reports clean protected
ranges and zero foreign deferred routines; \`!dpcwatchdog\` stays within
budget. Memorize this output — Attack labs 1–4 each break exactly one line
of it, which is how production triage works: diff against baseline.

## Lab 4 — the HVCI ceiling

Switch to the **irql-hardened** world: identical to irql-attackers except
the VBS analog is enforced. Compile and load the *same* WPOFFx64 attack.
This time the WP-clearing \`mov cr0\` never lands: the model intercepts it,
logs the interception, and raises bugcheck **0x109
CRITICAL_STRUCTURE_CORRUPTION** — the same verdict a real hypervisor
issues. Confirm from the debugger (\`!analyze -v\`, then \`!pgscan\`: CR0
still has WP set). This is why public cheat frameworks increasingly moved
from CR0 games to PTE remapping and BYOVD primitives: the ceiling moved.

## Sources

- Microsoft Learn, *Bug Check 0x133: DPC_WATCHDOG_VIOLATION* and *Bug
  Check 0x109: CRITICAL_STRUCTURE_CORRUPTION* — the two enforcement
  points modeled here.
- GenX Cyber, *Windows Kernel IRQL / DPC* articles (2026) — defender
  stack: ETW \`EVENT_TRACE_FLAG_DPC\` per-routine timing, \`% DPC Time\`,
  Sysmon EID 6 driver-load chokepoint, HVCI/CET hardening matrix.
- Microsoft Learn, *Kernel-mode Code Integrity / HVCI* — what the
  hardened world's 0x109 gate represents in production.
- McAfee Labs, *Analyzing the Uroburos PatchGuard Bypass* (2014) — why
  integrity scans and DPC-path attestation exist as a pair.
- MITRE ATT&CK M1040/M1048 mitigations mapped by the GenX Cyber tables.
`;
