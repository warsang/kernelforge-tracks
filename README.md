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
    devices.mjs              DRIVER_OBJECT/DEVICE_OBJECT/IRP model + scripted IRP engine
    seh.mjs                  x64 table-SEH: .pdata lookup + __C_specific_handler scopes
    kernel.mjs               process list, pool, API thunks, tracing, SEH-aware calls,
                             deferred drains (DPC/work/APC), IRQL violation tracking
    winapi.mjs + winapi-ext  249 modeled ntoskrnl exports (registry, virtual FS, sections,
                             interlocked, events, Se/Ob/Mm/Po/Etw/WMI/FsRtl)
  ntsim-analyzer             run-any-.sys harness: map -> DriverEntry -> IOCTLs -> report
  ntsim-assets               VergiliusProject scraper -> per-build offset JSON (CC0);
                             kdmp.mjs (crash-dump parser) + carve-dump.mjs (genuine pages)
  ntsim-unicorn              Unicorn/QEMU-TCG wasm CPU backend + HybridCpuBackend
                             (JS interpreter front end, automatic one-way handoff to
                             QEMU on any instruction the interpreter refuses)
  windbg-web                 kd> engine: dt/!process/lm/r/bp over live ntsim state
  compiler-worker            COFF parser + x64 linker: clang .obj -> runnable .sys
  course-content             module catalog, flag hashes, progression graph
  lab-runtime                flag checker, progress reducer, IndexedDB persistence
```

## The pipeline (all verified by tests)

```
student C source
  -> clang --target=x86_64-pc-windows-msvc -c        (wasm in-browser; dev bridge fallback)
  -> COFF .obj                                        (real compiler output)
  -> compiler-worker: linkDriver()                    (sections, relocs, extern resolve)
  -> PE32+ .sys                                       (pebuilder)
  -> ntsim mapPe(): manual-map into emulated kernel   (relocations, IAT -> API thunks)
  -> JsInterpreter / HybridBackend executes DriverEntry (Win64 ABI, table-SEH on fault)
  -> deferred drains (DPCs / work items / APCs)       (kernel.drainDeferred)
  -> scripted IRPs: MajorFunction[DEVICE_CONTROL]     (sendIrp/sendIoctl)
  -> DbgPrint + API trace captured; inspected via kd> dt/!process
  -> flags checked (sha256), progress persisted       (IndexedDB)
```

## Driver Analyzer

Upload any x64 `.sys` in the **Driver Analyzer** tab (sidebar → Tools):

1. Manual-mapped; every import resolves — modeled APIs behave faithfully,
   unknown exports become traced stubs returning STATUS_SUCCESS
   (`report.load.unmodeledExports` keeps it honest).
2. `DriverEntry` runs through the SEH path: faults are dispatched via the
   image's `.pdata` scope tables (__try/__except funclets re-entered as ABI
   calls); unhandled faults surface as bugcheck reports.
3. Queued DPCs / work items / APCs drain through the CPU.
4. Scripted IOCTLs drive `MajorFunction[IRP_MJ_DEVICE_CONTROL]`: craft an
   ioctl code + input hex, watch the handler run, read back
   IoStatus/SystemBuffer.
5. Zw/Nt calls above APC_LEVEL are recorded as IRQL violations.

Node API: `analyzeDriver(bytes, opts)` from `@kernelforge/ntsim-analyzer`.

## Genuine kernel bytes (optional)

```bash
npm run carve -- <mem.dmp> --out apps/web/public/dumps --build win10-19041
cp apps/web/public/dumps/ntsim-state-win10-19041.json \
   apps/web/public/dumps/ntsim-state.json   # deployed asset name
```

Labs and the analyzer both fetch `/dumps/ntsim-state.json` at boot when
present: resident ntoskrnl/CI/cng pages land at their true VAs under the
synthetic overlay. Without it everything runs on synthetic bytes.

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
  deeper API harness breadth (speakeasy-class), IRP/IOCTL-driven malware labs

## Legal notes

- No AssaultCube anywhere (license prohibits commercial use + cheat-content redistribution).
- Sauerbraten engine is ZLIB (commercial OK); ship ZERO stock media — link official installer.
- Sogen fork will be GPL-2.0, protocol-isolated from proprietary content.
- Vergilius tables: CC0. Dumps: vendor links only.
- Educational/defensive framing; responsible-use policy ships with the platform.
