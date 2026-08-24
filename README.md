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
npm test                 # 36 unit tests across packages
node apps/web/server.mjs # serve on :8080 (+ /api/compile dev bridge)
# open http://localhost:8080 — WinDbg tab: `!process 0 0`, `dt nt!_EPROCESS`
# IDE tab: Compile driver; Lab tab: submit FLAG{312}
cd apps/web && node test/e2e.mjs   # headless browser integration test
```

## Regenerating struct tables

```bash
cd packages/ntsim-assets
node scripts/scrape-vergilius.mjs --family windows-10 --build 22h2
node scripts/scrape-vergilius.mjs --family windows-7 --build sp1
```

Data source: VergiliusProject (CC0 — see their terms.html). Tables drive every
offset in ntsim and the debugger; switching build = swapping the table dir.

## Module 1 (shipped)

1. Kernel landscape — `lm` reveals `kfbootkit.sys` (`FLAG{kfbootkit.sys}`),
   `!process 0 0` finds `kfsample.exe` PID 312 (`FLAG{312}`)
2. DKOM process hiding — unlink `kftarget.exe` from `PsActiveProcessHead`
3. Kernel manual mapping — fix a loader driver's import resolution; capture the
   mapped payload's secret `DbgPrint`

## Roadmap (per docs/plan)

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
