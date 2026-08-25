/** Lesson body: m2.l2 — KF-Sentinel v2: IRQL watchdog (defense, markdown). */

export default `## Why the watchdog exists

Module 2's attack was not subtle: a driver raised the IRQL and never came
down. Nothing crashed — that is the scary part. A CPU parked above
DISPATCH_LEVEL silently freezes its thread, starves every queued DPC and,
deliberately used, hides code from instrumentation callbacks that only run
at <= APC_LEVEL. Your v1 sensor watched *structures*; the watchdog watches
*behavior over time*.

## What a watchdog measures

| signal | healthy | suspicious |
|---|---|---|
| IRQL sampled from driver context | 0–2, briefly higher | pinned at 15 |
| DPC queue depth | drains in microseconds | grows / stranded |
| time-at-level histogram | spikes, returns | plateau at top band |

One sample lies (your own sensor may run at DISPATCH). Histograms do not:
real kernels live at PASSIVE/DISPATCH with microsecond excursions upward.
A permanent residency at level 15 is never legitimate.

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

- \`!irql [n]\` — **lab extension** of the model (native WinDbg has none):
  reads/forces the emulated IRQL. A real driver achieves the read with
  \`KeGetCurrentIrql()\` (the exact call your compiled sensor makes) and the
  force with \`KeLowerIrql\`/\`KeRaiseIrql\`.
- \`!dpcs\` / \`!dpcdrain\` — **lab extensions**: enumerate/drain the per-CPU
  DPC queue. Driver-equivalent: walk \_KPRCB.DpcData for entries, then let
  KiRetireDpcList fire them once the level permits — precisely what the
  model does when you drain after lowering.

## Defensive framing — building it for real

- **Timer-DPC sampling**: \`KeSetTimerEx\` + DPC gives a periodic callback at
  DISPATCH; sample there, compare against expectations, emit ETW events.
- **DPC forensics**: EDRs track per-CPU DPC time (\`% DPC Time\` counters)
  and queue depth anomalies; anticheats additionally verify that their own
  watchdog DPC fires on schedule — a stuck CPU cannot hide the stall.
- **High-IRQL anti-forensics** cuts both ways: rootkits spin above
  DISPATCH to dodge callbacks, but they also freeze the core, which the
  latency histograms of any serious product catch immediately.
- **Hypervisor ceiling**: with EPT-based monitoring the IRQL game stops
  working entirely; the host sees guest interrupts regardless of guest
  CR8/APIC state. That is where this platform's phase-4 ept-sim goes.
`;
