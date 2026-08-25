/** Lesson body: m2.l1 — IRQL & deferred procedures (markdown). */
export default `## IRQL: the interrupt priority ladder

On x64 Windows every thread executes at an **Interrupt ReQuest Level** from
0 to 31 (x64 uses 0–15 for software-visible levels). The CPU only lets
higher-priority interrupts in:

| level | name | meaning |
|---|---|---|
| 0 | \`PASSIVE_LEVEL\` | normal thread execution; paging allowed |
| 1 | \`APC_LEVEL\` | APCs blocked |
| 2 | \`DISPATCH_LEVEL\` | DPCs/fire; **no paging, no waits** |
| 3+ | device / clock / IPI / high | interrupts and the scheduler itself |

Rules that get drivers killed:

- Raising below your current level, or lowering *above* it, is a bugcheck
  (\`IRQL_NOT_LESS_OR_EQUAL\`, 0xA).
- Touching paged memory or waiting at \`>= DISPATCH_LEVEL\` is a bugcheck.

\`\`\`
kd> !irql            # current level + name (lab extension of the model)
kd> !irql 2          # force a level — this lab's repair mechanic
\`\`\`

## Deferred procedure calls

Anything a driver postpones from an ISR runs in a **DPC**: a small callback
queued per-CPU and drained when the processor falls back toward
\`DISPATCH_LEVEL\`. A DPC queued while the CPU is pinned *above* DISPATCH
simply never runs — the queue grows, timers stall, watchdogs bite.

\`\`\`
kd> !dpcs            # queue contents: DPC address, DeferredRoutine, status
kd> !dpcdrain        # drop to DISPATCH and let queued DPCs fire
\`\`\`

## The lab

The world boots with \`kfdpc.sys\` loaded. Its initialization raised the IRQL
and then forgot to lower it — the CPU sits pinned at the highest software
level with one DPC stranded in the queue. Your job:

1. Read the stuck level off \`!irql\` (answer 1: decimal).
2. Find the stranded DPC's \`DeferredRoutine\` address via \`!dpcs\`
   (answer 2: full hex address).
3. Repair: \`!irql 2\`, then \`!dpcdrain\`. The routine finally runs and
   DbgPrints its secret (answer 3).

## Custom debugger extensions in this lab

All three commands are **lab extensions** — real WinDbg has none of them;
they exist because the model exposes IRQL/DPC state that a live kernel hides
behind the HAL:

- \`!irql [n]\` — reads (or forces) the emulated processor level.
  *Driver equivalent:* \`KeGetCurrentIrql()\` reads; \`KeRaiseIrql\`/
  \`KeLowerIrql\` move — exactly what your compiled watchdog in m2.l2 does:
  \`\`\`c
  KIRQL sampled = KeGetCurrentIrql();          // the read
  if (sampled > DISPATCH_LEVEL)
      KeLowerIrql(DISPATCH_LEVEL);             // the repair
  \`\`\`
- \`!dpcs\` — dumps the per-CPU deferred queue with drain status.
  *Driver equivalent:* walk \`_KPRCB.DpcData\` entries and read each
  \`_KDPC.DeferredRoutine\` (the debugger shows the same address you would
  read at DPC+0x18 with build-table offsets).
- \`!dpcdrain\` — retires queued DPCs once the level permits, mirroring what
  \`KiRetireDpcList\` does on a healthy core.

## Defensive framing

IRQL abuse is not exotic: a driver that spins at high IRQL freezes the core
for everything on it, which is both a classic kernel panic generator and,
deliberately, an anti-forensics trick — code running above DISPATCH is
invisible to many instrumentation callbacks.

Defender playbook, in increasing order of strength:

1. **Sampling watchdog**: a timer-DPC sensor samples \`KeGetCurrentIrql\`
   across CPUs and histograms time-at-level. Healthy kernels spike; they do
   not plateau at 15. You build this in m2.l2 (**KF-Sentinel v2**), including
   the repair half — lowering the ladder so starved work runs again.
2. **DPC-latency telemetry**: per-CPU queue depth and retire latency feed the
   same pipeline as \`% DPC Time\` counters; a queue that never drains is a
   stalled core wearing a disguise.
3. **Self-watchdog verification**: anticheats schedule their own DPC and
   alarm if it does not fire within N ticks — a stuck core cannot hide its
   own stall from a deadline.
4. **Hypervisor ceiling**: with EPT-based monitoring the host sees guest
   interrupt state directly; no guest CR8/APIC game can hide from the layer
   that owns the APIC page.
`;
