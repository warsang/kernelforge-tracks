# KERNELFORGE build-out plan (modules 2–4)

Status: approved 2026-08. Supersedes the roadmap stub previously only in README.

## Ground rules

- All work bases on `main`. `feat/browsercc-wasm` is owned by another agent — do not merge.
- Compiler labs use the existing `/api/compile` dev bridge until browsercc lands.
- Flags are **plain question answers** (no `FLAG{}` wrapper). Submissions are
  normalized (trim + lowercase) then sha256'd against precomputed constants in
  `packages/course-content/src/catalog.mjs`. Prompts pin the exact format
  (decimal / 0x-hex / symbol name) so grading stays unambiguous.

## Shipped baseline

Module 1 — Windows Kernel Fundamentals & Manual Mapping (`boot-default`,
`dkom-hide`, `manual-map` scenarios; windbg/compiler/ntsim labs).

## Module 2 — IRQL & Deferred Procedures (scenario `irql-dpc`)

Infra (ntsim):
- Real IRQL model on `NtKernel`: raise/lower validation (raise below current or
  lower above current => modeled bugcheck 0xA), level-name table.
- Per-kernel DPC queue: `KeInitializeDpc`/`KeInsertQueueDpc` (deduped),
  `KeRemoveQueueDpc`, `drainDpcs()` with scenario-registered callbacks.

Debugger: `!irql [<n>]` (inspect / lab-extension force), `!dpcs`, `!dpcdrain`
(refuses above DISPATCH_LEVEL like the real scheduler would).

Lab flow: boot world where `kfdpc.sys` left the CPU at CRITICAL_LEVEL with a
queued-not-drained DPC; student reads IRQL, records DeferredRoutine address,
lowers to DISPATCH and drains to release the secret.

Answers: stuck IRQL (decimal), DeferredRoutine VA (0x…), drain secret string.

## Module 3 — Inline Hooks & Control Flow (scenario `api-hook`)

Infra (ntsim):
- Pristine prologue snapshots for every defined API thunk (recorded in
  `defineApi`).
- Detour modeling: scenario writes an `E9 rel32` over a chosen thunk;
  behavior gates read live bytes, so repairing with `eb` instantly unhooks.

Debugger: `!hookscan [module]` diffs live vs pristine bytes and symbolizes the
detour target; repair uses existing `eb`; `!hooktest <api> <args…>` exercises
the modeled call.

Lab flow: `kfhook.sys` detoured `PsLookupProcessByProcessId` to hide PID 666.
Student identifies the hooked export, the suppressed PID, restores the
prologue, and confirms the lookup succeeds again.

Answers: hooked export name, hidden PID (decimal), post-repair NTSTATUS
symbolic name.

## Module 4 — Pool Internals & Corruption (scenario `pool-corrupt`)

Infra (ntsim):
- Pool upgrade: per-allocation header (magic) + trailing 16-byte 0xA5 guard,
  double-free detection (`BAD_POOL_CALLER` modeled bugcheck),
  `registerPoolBlock()` for scenario-seeded fixed-address allocations,
  `verifyGuards()` sweep.

Debugger: `!poolfind <tag>` (blocks + guard health + expected bytes),
`!poolverify`.

Lab flow: `kfpooler.sys` manages tagged `KfPb` blocks; one guard was smashed
by an upstream overflow. Student locates the corrupted block, repairs the
guard with `eb`, verifies, and captures the checksum secret.

Answers: corrupted block user VA (0x…), heal secret string.

## Integration checklist

- `catalog.version = 2`; lesson chain `m1.l3 -> m2.l1 -> m3.l1 -> m4.l1`.
- Lesson bodies ship as markdown-in-JS under `packages/course-content/src/lessons/`
  rendered client-side via `marked`.
- e2e extended: every new lab boots headless and accepts its answers.
- Unit tests mirror existing patterns (`winapi.test.mjs`, `debugger.test.mjs`,
  scenario tests) for IRQL/DPC/pool/hook infra and each debugger command.

## Later phases (unchanged from README)

Phase 2 Sogen/Sauerbraten userland track · Phase 3 v86 Linux LKM track ·
Phase 4 shadow-EPT hypervisor · Phase 5 UEFI bootkit sim · Phase 6 BYOVD labs.
