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

## Later phases

Phase 2 Sogen/Sauerbraten userland track · Phase 3 v86 Linux LKM track ·
Phase 4 shadow-EPT hypervisor · Phase 5 UEFI bootkit sim · Phase 6 BYOVD labs.

## Phases 2–3 + Ghidra pane (implemented on feat/tracks-userland-linux-ghidra)

Status: implemented 2026-08. Branch base: main @ 7cf7a81. Worktree:
`../kf-phases234`. Catalog v3.

### M0 — platform plumbing
- apps/web pane registry (`panes.js`): lab.kind -> backends/debugger/editor;
  main.js core flow untouched by tracks.
- Vendored-wasm convention (from ntsim-unicorn): pinned provenance README +
  rebuild recipe + lazy dynamic import + loud degrade.

### Phase 2 — sogen userland track (modules 5–6)
- `packages/sogen-runtime`: sogen-shaped session API over a deterministic
  plain-JS reference backend; headless Sauerbraten world with pinned
  constants (image base 0x00400000, entity array stride 0x40, local player
  0x021000d0, health +0x24, cl_sendinput 0x004532a0, cheat stub 0x0046f010).
- kd-style console engine: lm/pe/x/scan/eb/hookscan + !damage/!inputtest.
- Wine root tooling: tools/build-wine-root.mjs (manifest + sha256s).
- GUI decision gate: docs/spike-sogen-gui.md — playable client is a stretch
  goal; OpenGL-in-wasm is the hard part (GPU paravirt is D3D/DXVK-shaped).
- Upgrade path: vendor the real sogen wasm core behind the same API.
- Instructor answers: m5 = 0x00400000 / 0x021000d0 / 0x24;
  m6 = 0x004532a0 / 0x0046f010 / kf-input-restored.

### Phase 3 — v86 linux track (modules 7–9)
- `packages/v86-lab`: serial capture harness (KFFLAG extraction), lazy v86
  session with instructive degrade, guest seed registry, dockerized buildroot
  script (kprobes on, KASLR off), kfvillain rootkit source (GPL-2.0) overlay.
- compiler-worker: ELF32 relocatable parser + i386 module staging
  (parseElf / validateLinuxModule / stageLinuxModule); final linking happens
  in-guest via gcc+insmod driven over serial.
- Instructor answers: m7 = 128 (__NR_init_module i386) / kf-lkm-hello;
  m8 = 11 (__NR_execve i386) / kf-trace-ok; m9 = 3 hidden tasks /
  kf-detector-ok. Seeds single-sourced in packages/v86-lab/src/seeds.mjs.

### Ghidra decompiler pane (module 10)
- `packages/ghidra-decompiler`: deterministic x64 prologue boundary scan,
  E9/E8 resolution, analyzeExtent helper, byte-stable function-grid writer
  for scenario worlds; real pseudocode via Ghidra's native decompiler
  compiled to wasm once vendored (loud DecompilerUnavailableError until then).
- debugger commands: !funcs <module> (static recovery listing + rel32 sites),
  !decomp <addr> (wasm path + static fallback info).
- api-hook world extended with a byte-stable 128-function grid inside
  kfhook.sys (evidence strings moved to a dedicated page).
- Instructor answers: m10 = 128 functions / 0xfffff8055a601010 /
  0xfffff8055a601000.

### Integration checklist status
- [x] catalog.version = 3; chain m1.l1 -> ... -> m10.l1 (linear).
- [x] Lessons ship as markdown-in-JS under packages/course-content/src/lessons/.
- [x] Unit tests per package (world constants, console flows, serial harness,
      ELF staging, boundary scanner); lab-flow tests drive the real scenario +
      command surface headless (labs-m2m4 pattern, labs-m10 added).
- [x] npm test + tsc --build green at every commit.
- Pending vendors: sogen wasm core, v86 bundle + bzImage artifact, ghidra
  decompiler wasm (each documented in its package's vendor/README.md).


## Catalog v4 — blog-labs modules m11-m16 (feat/internals-blog-modules)

Status: implemented 2026-08. Branch base: main @ 60e052a. Worktree:
`../advanced_Cheat_Dev-wt4`. Sources scraped & cited in lesson bodies:
revers.engineering, secret.club, windows-internals.com (System Informer),
security-auditing.com, everdox.blogspot.com, momo5502.com, 0xdbgman
(CrowdStrike teardown), ssno.cc TAC, kernel-internals.org, ridpath
gamehacking cheatsheet, UnknownCheats TryBypassMe series.

### Engine additions
- ntsim/paging.mjs: 4-level walker + PageTableSpace; per-path self-map
  alias windows (mirrored pages); large pages; CR3-shuffle scan. Debugger:
  !cr3/!pte/!vtop.
- ntsim/notify.mjs: callback INVOCATION engine (Ex vs legacy tracking),
  PS_CREATE_NOTIFY_INFO materialization (+0x40 CreationStatus), thread/
  image fire helpers. Debugger: !notifyroutines/!notifytest.
- ntsim/ssdt.mjs: ServiceTable over real thunk bytes; !ssdt scan/repair.
- debugger !pseudocode: fixture-shaped decompilation (sensor idiom).
- sogen-runtime ac.mjs: tbm-ac world (5 ring-3 AC vectors).
- v86-lab: syscall-hook world seeds + kfhooksy.c villain (GPL-2.0).

### Backend parity (hard requirement)
All new worlds boot via LOW_BASES (< bit 47) so JsInterpreter and
Unicorn/QEMU execute identical flows; apps/web/test/backend-parity.test.mjs
gates each world under both engines (loud skip when wasm absent).

### Instructor answers (v4)
m11: 0x0000000003005000 / 0x0000078250e65218 / kf-pt-healed
m12: STATUS_ACCESS_DENIED / 0x0000000050101000 / kf-edr-blindspot
m13: NtOpenProcess / 0x0000000005201000 / kf-ssdt-clean
m14: 5 / 0x00600100 / kf-tbm-godmode
m15: 37 / kf-hookspotted / kf-syscall-clean
m16: 64 / 0x0000000050101000 / 64

Follow-on candidates: HWID spoofing lab, TBM-Kernel vectors, ept-sim.
