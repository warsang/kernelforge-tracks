# KERNELFORGE

Browser-native red-team / EDR-bypass / game-hacking course platform. Every lab runs
client-side: an emulated x64 Windows kernel anchored in real per-build struct tables,
a fake-but-faithful WinDbg, in-browser compilation of real drivers, and CTF-style
flag progression. Static hosting only — no nested virtualization, no accounts.

## Architecture

```
apps/web                     zero-build web shell (import maps) + dev/serve server
packages/
  ntsim                      emulated x64 Windows kernel
    memory.mjs               sparse 64-bit page store (BigInt addresses)
    cpu.mjs                  deterministic x86-64 interpreter (Win64 ABI)
    structs.mjs              Vergilius-table-driven struct access (no hardcoded offsets)
    pe.mjs / pebuilder.mjs   PE32+ manual mapper + image builder
    kernel.mjs               process list, pool, API hooks, DbgPrint, DriverEntry
  ntsim-assets               VergiliusProject scraper -> per-build offset JSON (CC0)
  windbg-web                 kd> engine: dt/!process/lm/r/bp over live ntsim state
  compiler-worker            COFF parser + x64 linker: clang .obj -> runnable .sys
  course-content             module catalog, flag hashes, progression graph
  lab-runtime                flag checker, progress reducer, IndexedDB persistence
```

## The pipeline (all verified by tests)

```
student C source
  -> clang --target=x86_64-pc-windows-msvc -c        (dev bridge; browsercc WASM later)
  -> COFF .obj                                        (real compiler output)
  -> compiler-worker: linkDriver()                    (sections, relocs, extern resolve)
  -> PE32+ .sys                                       (pebuilder)
  -> ntsim mapPe(): manual-map into emulated kernel   (relocations, IAT -> API thunks)
  -> JsInterpreter executes DriverEntry               (Win64 ABI)
  -> DbgPrint captured; inspected via kd> dt/!process
  -> flags checked (sha256), progress persisted       (IndexedDB)
```

## Quick start

```bash
npm install
npm test                 # unit tests across packages
node apps/web/server.mjs # serve on :8080 (+ /api/compile dev bridge)
# open http://localhost:8080 — WinDbg tab: `!process 0 0`, `dt nt!_EPROCESS`
# IDE tab: Compile driver; Lab tab: submit lab answers
cd apps/web && node test/e2e.mjs   # headless browser integration test (legacy branch)
```

## Regenerating struct tables

```bash
cd packages/ntsim-assets
node scripts/scrape-vergilius.mjs --family windows-10 --build 22h2
node scripts/scrape-vergilius.mjs --family windows-7 --build sp1
```

Data source: VergiliusProject (CC0 — see their terms.html). Tables drive every
offset in ntsim and the debugger; switching build = swapping the table dir.

## Shipped modules (windows-kernel track)

Answers are plain question responses (names, PIDs, hex addresses, symbolic
NTSTATUS) normalized trim+lowercase then sha256-checked; no FLAG{} wrapper.
Ground truth lives with instructors; see docs/plan.md for the build-out plan.

**Module 1 — Windows Kernel Fundamentals & Manual Mapping**
1. Kernel landscape — `lm` reveals `kfprobe.sys`; `!process 0 0` finds
   `kfsample.exe` PID 312
2. DKOM process hiding — unlink `kftarget.exe` from `PsActiveProcessHead`
3. Kernel manual mapping — fix a loader driver's import resolution; capture
   the mapped payload's secret `DbgPrint`

**Module 2 — IRQL & Deferred Procedures** (`irql-dpc`)
`kfdpc.sys` pins the CPU above DISPATCH_LEVEL and strands a DPC. Read the
stuck level (`!irql`), record the DeferredRoutine (`!dpcs`), lower and drain
(`!irql 2`, `!dpcdrain`) to release the secret.

**Module 3 — Inline Hooks & Control Flow** (`api-hook`)
`kfhook.sys` detoured `PsLookupProcessByProcessId` so PID 666 vanishes from
lookup. Find it (`!hookscan`), probe it (`!hooktest`), repair the prologue
with `eb`, prove the lookup succeeds again.

**Module 4 — Pool Internals & Corruption** (`pool-corrupt`)
An upstream overflow smashed one of `kfpooler.sys`'s trailing pool guards.
Locate the block (`!poolfind KfPb`), rewrite the guard with `eb`, verify
(`!poolverify`), capture the checksum secret.

**Module 5 — Tracing & Anti-Tracing** (`anti-trace`)
`kftrace.sys` arms CPU trap-flag tripwires: passive TF reads
(`pushfq`/`test 100h`), TF injection into a vectored handler, and the
mov-ss stall. Map them (`!traceinfo`), attach a simulated tracer and watch
it starve the driver's VEH (`!trace on`, `!selftest` — count swallowed
INT 1s), then clear the gate byte with `eb` to release the secret.

## Roadmap (see docs/plan.md)

- Phase 2: Sogen fork (Windows userland track, real ntdll) + Sauerbraten headless target
- Phase 3: v86 Linux track (i386 Buildroot, LKM labs)
- Phase 4: shadow-EPT hypervisor module (ept-sim)
- Phase 5: UEFI bootkit simulator
- Phase 6: BYOVD/misconfiguration labs (RACEAC-style TOCTOU, mhyprot2 pattern)
- Infra: browsercc WASM fork (X86+BPF LLVM backends) to move compilation fully client-side;
  real kernel-dump carve (kdmp-parser) to anchor ntoskrnl pages with genuine bytes

## Legal notes

- No AssaultCube anywhere (license prohibits commercial use + cheat-content redistribution).
- Sauerbraten engine is ZLIB (commercial OK); ship ZERO stock media — link official installer.
- Sogen fork will be GPL-2.0, protocol-isolated from proprietary content.
- Vergilius tables: CC0. Dumps: vendor links only.
- Educational/defensive framing; responsible-use policy ships with the platform.
