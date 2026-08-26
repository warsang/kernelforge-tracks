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
- IRQL is **per-CPU**. Raising *your* core to 15 does nothing to code
  running on the other cores — this single fact kills most "just raise
  IRQL to hide" folklore, and it is why directed-DPC attacks exist (m2.l3).

\`\`\`
kd> !irql            # current level + name (lab extension of the model)
kd> !irql -a         # per-core view — the directed-DPC labs live here
kd> !irql 2          # force a level — this lab's repair mechanic
\`\`\`

## Deferred procedure calls: queue -> retire -> run

A DPC is how Windows moves work out of a high-IRQL interrupt. The lifecycle
has three phases, and the model in this lab mirrors each one:

1. **Queue** — an ISR (or any driver) fills a \`_KDPC\`:
   \`KeInitializeDpc\` writes the \`DeferredRoutine\` pointer,
   \`KeInsertQueueDpc\` links the object into the target CPU's queue
   (\`_KPRCB.DpcData\`). The routine address is read from the struct at
   insert time — *and again at retire time*, which is exactly what
   DeferredRoutine-hijack attacks abuse (m2.l3).
2. **Retire** — when the processor's IRQL falls back **to** DISPATCH_LEVEL
   on its way down from something higher, the kernel raises back to 2 and
   runs \`KiRetireDpcList\`: it pops entries and invokes each
   \`DeferredRoutine\` **at** DISPATCH_LEVEL.
3. **Run** — because a DPC executes AT level 2, it cannot preempt anything
   above level 2. That is the whole drain gate: a core parked at IRQL 15
   strands its queue, because nothing at 15 can be interrupted by a
   level-2 callback.

\`\`\`
kd> !dpcs            # queue contents: DPC address, DeferredRoutine, status
kd> !dpcdrain        # drop to DISPATCH and let queued DPCs fire
kd> !dpcpump 10      # advance the lab clock: expire timers, retire DPCs
kd> !dpcstat         # queue depth / age telemetry (the ETW analog)
\`\`\`

## How long can a core actually sit up here?

Not long. At IRQL >= CLOCK_LEVEL (13) the core stops taking clock
interrupts; at 14–15 even IPIs are masked. But:

- **Other cores keep running.** One frozen core does not freeze the box —
  until the stuck thread holds a lock everyone else needs.
- The kernel polices residency with the **DPC watchdog**: a core that
  spends too long at or above DISPATCH (or a DPC that runs past its ~100µs
  budget) trips bugcheck **0x133 \`DPC_WATCHDOG_VIOLATION\`** within
  seconds. Try it: \`!dpcwatchdog\`.
- This lab freezes time — there is no scheduler ticking between your
  commands — so treat the boot state as a *snapshot* taken after kfdpc.sys
  raised the ladder and just before the watchdog would have fired.

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

All of these are **lab extensions** — real WinDbg has none of them; they
exist because the model exposes IRQL/DPC state that a live kernel hides
behind the HAL:

- \`!irql [n|-a]\` — reads (or forces) the emulated processor level.
  *Driver equivalent:* \`KeGetCurrentIrql()\` reads; \`KeRaiseIrql\`/
  \`KeLowerIrql\` move — exactly what your compiled watchdog in m2.l2 does:
  \`\`\`c
  KIRQL sampled = KeGetCurrentIrql();          // the read
  if (sampled > DISPATCH_LEVEL)
      KeLowerIrql(DISPATCH_LEVEL);             // the repair
  \`\`\`
- \`!dpcs\` / \`!dpcdrain\` — dump / retire the deferred queue.
  *Driver equivalent:* walk \`_KPRCB.DpcData\` and read each
  \`_KDPC.DeferredRoutine\`; retirement is \`KiRetireDpcList\`.
- \`!dpcpump [n]\` — advances the modeled clock n ticks: expires due timers
  and retires eligible DPCs. *Real analog:* time itself passing.
- \`!dpcstat\` / \`!dpcwatchdog\` — queue-age telemetry and the watchdog
  check. *Real analog:* ETW \`EVENT_TRACE_FLAG_DPC\` sampling and
  \`KiProcessExpiredTimerList\`.

## Attack realism: windows, not residency

The pinned-at-15 driver you just repaired is a *crash signature*, not what
real kernel malware looks like. The techniques you build in m2.l3 look
different:

- **The WPOFFx64 window** — public cheat loaders and rootkits patch
  read-only kernel memory by clearing CR0.WP inside a raised-IRQL window:
  \`KeRaiseIrqlToDpcLevel()\` → clear WP → copy the detour bytes → restore
  WP → \`KeLowerIrql\`. Note what the raise buys: not permission (mov cr0
  needs no IRQL) but an *uninterruptible microsecond* — no timer DPC, no
  APC, no scheduler can interleave and catch the write half-done.
- **Directed-DPC CPU lockdown** — to tamper with structures other CPUs
  touch, rootkits queue spinning DPCs at every other core
  (\`KeSetTargetProcessorDpc\`): all cores park at DISPATCH, the attacker
  core works alone, then releases. Seconds of that trip the watchdog;
  the real technique completes in microseconds.
- What high IRQL does **not** do: stop process-create notify routines
  firing on untouched cores, or hide you from ETW DPC telemetry, or
  survive HVCI — where CR0.WP games get intercepted as
  \`CRITICAL_STRUCTURE_CORRUPTION\` (0x109). See irql-hardened.

## Sources

- Microsoft Learn, *Managing Hardware Priorities* — the canonical IRQL
  rules table (learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities).
- Microsoft Learn, *KeRaiseIrql* DDI reference — raise/lower contracts and
  the bugcheck-on-violation semantics modeled here.
- OffSec blog, *IRQLs: Close Encounters of the Rootkit Kind* (Malvica,
  2022) — the directed-DPC multi-core synchronization technique.
- McAfee Labs, *Analyzing the Uroburos PatchGuard Bypass* (2014) —
  in-the-wild rootkit hooking \`KiRetireDpcList\` itself.
- GenX Cyber, *DPCs: Deferred Procedure Calls and Interrupt Deferral*
  (2026) — DPC abuse taxonomy (CPU lockdown, timer-DPC persistence,
  DeferredRoutine hijack) and defender telemetry.
- MITRE ATT&CK T1014 (Rootkit), T1562.001 (Impair Defenses).
`;
