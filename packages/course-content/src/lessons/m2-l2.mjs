/** Lesson body: m2.l2 — KF-Sentinel v2: IRQL watchdog (defense, markdown). */

export default `## Why the watchdog exists

Module 2's attack was a driver that raised the IRQL and never came down.
On a real box that state is *loud*: the DPC watchdog bugchecks the machine
with **0x133 \`DPC_WATCHDOG_VIOLATION\`** within seconds of the residency
budget being blown. The scary part is not that nothing crashes — it is the
**tamper window before the deadline**: everything a parked core cannot
react to happens in those seconds, and on a multi-core machine the other
cores keep working normally right up until the bugcheck. Your v1 sensor
watched *structures*; the watchdog watches *behavior over time*.

## What a watchdog measures

| signal | healthy | suspicious |
|---|---|---|
| IRQL sampled from driver context | 0–2, briefly higher | pinned at top band |
| DPC queue depth | drains in microseconds | grows / stranded |
| time-at-level histogram | spikes, returns | plateau at top band |
| directed-core IRQLs (\`!irql -a\`) | cores 1+ idle at 0 | parked at 2 |

One sample lies (your own sensor may run at DISPATCH). Histograms do not:
real kernels live at PASSIVE/DISPATCH with microsecond excursions upward.
Permanent residency anywhere above DISPATCH is never legitimate — and
neither is a *secondary* core parked at DISPATCH, which is the signature
of the directed-DPC lockdown technique (attack side, m2.l3).

\`\`\`c
KIRQL sampled = KeGetCurrentIrql();
if (sampled > DISPATCH_LEVEL) {
    // telemetry first...
    KeLowerIrql(DISPATCH_LEVEL);   // ...then restore the ladder
}
\`\`\`

Production watchdogs sample from a timer DPC (which by definition runs at
DISPATCH — anything above it means someone else broke the rules) or from
the hypervisor, which no guest IRQL game can hide from.

## The lab

The world boots exactly as module 2's attack left it: IRQL pinned, one DPC
stranded. Compile the \`SENTINEL-WATCHDOG\` starter. It samples the IRQL,
reports what it finds, restores DISPATCH_LEVEL and releases the stranded
DPC so you can drain it from the debugger.

1. Load your compiled watchdog; read the sampled level off its DbgPrint
   line (answer 1).
2. Drain with \`!dpcdrain\`; confirm the deferred routine finally ran.
3. The watchdog prints an acknowledgement secret once the ladder is back
   in range (answer 2).

## Custom debugger extensions used

- \`!irql [n|-a]\` — **lab extension** of the model (native WinDbg has none):
  reads/forces the emulated IRQL; \`-a\` shows every logical core. A real
  driver achieves the read with \`KeGetCurrentIrql()\` (the exact call your
  compiled sensor makes) and the force with \`KeLowerIrql\`/\`KeRaiseIrql\`.
- \`!dpcs\` / \`!dpcdrain\` / \`!dpcpump\` / \`!dpcstat\` / \`!dpcwatchdog\` —
  **lab extensions**: enumerate, retire, clock-advance and audit the
  per-CPU DPC machinery. Driver-equivalent: walk \_KPRCB.DpcData for
  entries, then let KiRetireDpcList fire them once the level permits;
  the watchdog check mirrors \`KiProcessExpiredTimerList\` raising 0x133.

## Defensive framing — building it for real

- **Timer-DPC sampling**: \`KeSetTimerEx\` + DPC gives a periodic callback at
  DISPATCH; sample there, compare against expectations, emit ETW events.
- **DPC forensics**: EDRs track per-CPU DPC time (\`% DPC Time\` counters)
  and queue-depth anomalies; anticheats additionally verify that their own
  watchdog DPC fires on schedule — a stuck CPU cannot hide the stall.
  You build exactly this self-watchdog in m2.l4.
- **High-IRQL anti-forensics cuts both ways**: real rootkits hold
  *microsecond* windows or freeze *other* cores via directed DPCs while
  the executing core stays quiet. Residency at the top band is not stealth;
  it is a crash signature with a timestamp.
- **Hypervisor ceiling**: with EPT-based monitoring the IRQL game stops
  working entirely; the host sees guest interrupts regardless of guest
  CR8/APIC state. That is where this platform's phase-4 ept-sim goes.

## Sources

- Microsoft Learn, *KeRaiseIrql / KeLowerIrql / KeGetCurrentIrql* DDI
  references — contracts your compiled sentinel exercises verbatim.
- Microsoft Learn, *Bug Check 0x133: DPC_WATCHDOG_VIOLATION* — the
  residency budget this module models.
- OffSec blog, *IRQLs: Close Encounters of the Rootkit Kind* (2022) —
  why per-core IRQL telemetry (\`!irql -a\`) matters.
- GenX Cyber, *Windows Kernel IRQL / DPC* articles (2026) — defender
  telemetry stack: ETW \`EVENT_TRACE_FLAG_DPC\`, \`% DPC Time\`, watchdog
  deadlines, HVCI/CET hardening.
- MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools.
`;
