/**
 * ntsim-analyzer — run any uploaded .sys through the emulated kernel.
 *
 * Pipeline:
 *   bytes -> mapPe (provisioned import resolution: every import resolves)
 *         -> DriverEntry via SEH-aware call
 *         -> deferred drains (DPC / work items / APCs)
 *         -> scripted IRPs (DeviceIoControl + optional read/write/create)
 *         -> optional DriverUnload
 *         -> report {load, entry, dbgLog, apiTrace, exceptions, ioctls, ...}
 *
 * The same code runs in Node tests and in the browser (no fs, no Buffer).
 */

import {
  NtKernel,
  mapPe,
  parsePe,
  createDriverObject,
  initDriverObjectName,
  createDeviceObject,
  sendIrp,
  callDriverUnload,
  IRP_MJ,
} from "@kernelforge/ntsim/src/index.mjs";

const DEFAULT_DRIVER_BASE = 0xfffff80300000000n;

/** "C:\Windows\mhyprot2.SYS" -> service key basename "mhyprot2" (no extension). */
function serviceKeyOf(name) {
  const base = String(name ?? "uploaded.sys").split(/[\\/]/).pop() || "uploaded.sys";
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(0, dot) : base;
}

function hexToBytes(hex) {
  const hx = String(hex ?? "").replace(/[^0-9a-fA-F]/g, "");
  if (!hx) return new Uint8Array(0);
  const pairs = hx.match(/.{2}/g) ?? [];
  return new Uint8Array(pairs.map((x) => parseInt(x, 16)));
}

/**
 * @param {Uint8Array} imageBytes raw PE32+ (.sys) file content
 * @param {object} [opts]
 *   name           driver name for DRIVER_OBJECT.DriverName + service RegistryPath
 *                  (default "uploaded.sys"; basename w/o ext seeds Services\<key>)
 *   backend        "js" | "unicorn" | "hybrid" | CpuBackend instance
 *   tables         StructTables instance
 *   bases          NtKernel base overrides
 *   carvedState    carve-dump.mjs JSON (genuine ntoskrnl pages) — loaded pre-boot
 *   registry       {path: {valueName: data}} seeds
 *   maxSteps       per-call instruction budget (default 20M)
 *   ioctls         [{code:number|string, input?:Uint8Array|hex, outputLen?, major?}]
 *   autoIrp        true | {maxCodes?, inputPatterns?, outputLen?} — lifecycle
 *                  majors + harvested CTL_CODEs driven automatically post-entry
 *   runUnload      invoke DriverUnload after IOCTLs when present
 *   makeBackend    async (mem)=>CpuBackend factory override (browser unicorn path)
 * @returns {Promise<object>} report
 */
export async function analyzeDriver(imageBytes, opts = {}) {
  // One address space for guest + kernel model + CPU: adopt whatever backend
  // we get (or NtKernel's default JsInterpreter) and reuse its SparseMemory.
  let cpu;
  if (typeof opts.makeBackend === "function") cpu = await opts.makeBackend(null);
  else if (opts.cpu) cpu = opts.cpu;

  const kernel = new NtKernel({
    cpu,
    tables: opts.tables,
    bases: opts.bases,
  });
  const mem = kernel.mem;
  kernel.bootstrap();

  // genuine dump pages under the synthetic world (optional)
  if (opts.carvedState?.pages) {
    const { loadDumpState } = await import("@kernelforge/ntsim/src/dumpstate.mjs");
    const info = loadDumpState(mem, opts.carvedState);
    kernel.dumpSource = "carved";
    kernel.carvedModules = info.modules;
  }
  // makeBackend factories that need the real memory object get it now
  if (cpu && typeof cpu.attachMemory === "function") cpu.attachMemory(mem);

  if (opts.registry) {
    for (const [p, values] of Object.entries(opts.registry)) {
      kernel.registrySeed(p, values);
    }
  }

  const report = {
    meta: {
      size: imageBytes.length,
      engine: opts.backendName ?? (kernel.cpu.constructor.name),
      at: new Date().toISOString(),
    },
    load: null,
    entry: null,
    ioctls: [],
    autoIrps: null,
    harvestedIoctls: null,
    deferred: null,
    unload: null,
    dbgLog: [],
    apiTraceSummary: null,
    exceptions: [],
    irqlViolations: [],
    bugcheck: null,
  };

  // ------------------------------------------------------------- map
  const drvRec = createDriverObject(kernel, opts.name ?? "uploaded.sys");
  const pe = parsePe(imageBytes); // throws PeError on non-x64/non-PE32+
  const mapped = mapPe(imageBytes, mem, DEFAULT_DRIVER_BASE, (qualified) =>
    kernel.resolveImportProvisioned(qualified));
  const image = { base: mapped.base, bytes: imageBytes };
  initDriverObjectName(kernel, drvRec, opts.name ?? "uploaded.sys", mapped.base, mapped.imageSize);
  drvRec.image = image; // enable SEH dispatch for IOCTL/unload calls

  report.load = {
    base: `0x${mapped.base.toString(16)}`,
    imageSize: mapped.imageSize,
    entryRva: pe.entryRva,
    relocated: mapped.relocated,
    imports: mapped.imports,
    unmodeledExports: [...kernel.unmodeledExports],
    sections: pe.sections.map((s) => ({
      name: s.name, rva: s.rva, vsize: s.virtualSize,
    })),
  };

  const driverName = opts.name ?? "uploaded.sys";
  const regPath = `\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\${serviceKeyOf(driverName)}`;
  report.load.registryPath = regPath;
  report.load.driverName = driverName;

  const regPathBuf = kernel.allocPool(0x100);
  mem.writeUtf16(regPathBuf, regPath);

  // ------------------------------------------------------ DriverEntry
  const entryResult = kernel.callFunctionSeh(mapped.entry, [drvRec.va, regPathBuf], image);
  report.entry = summarizeCall(entryResult);
  report.dbgLog.push(...kernel.dbgLog.splice(0));
  report.exceptions.push(...kernel.exceptionTrace.splice(0));
  report.irqlViolations.push(...kernel.irqlViolations.splice(0));

  if (kernel.bugcheck || kernel.crash) report.bugcheck = kernel.bugcheck ?? kernel.crash;

  // ------------------------------------------------------- deferred work
  if (entryResult.status === "ok" && !report.bugcheck) {
    report.deferred = kernel.drainDeferred();
    report.dbgLog.push(...kernel.dbgLog.splice(0));
    report.exceptions.push(...kernel.exceptionTrace.splice(0));
  }

  // ------------------------------------------------------------ IOCTLs
  // Drivers that never call IoCreateDevice still get a synthetic device so
  // scripted IOCTLs can reach MajorFunction — speakeasy-style harnessing.
  const device = drvRec.deviceList[0] ?? createDeviceObject(kernel, drvRec, {});
  if (device && entryResult.status === "ok" && !report.bugcheck) {
    // automatic driving first (lifecycle majors + harvested CTL_CODEs)
    if (opts.autoIrp) {
      const { harvestCtlCodes, autoDriveIrps } = await import("./autoirp.mjs");
      const cfg = typeof opts.autoIrp === "object" ? opts.autoIrp : {};
      const harvested = harvestCtlCodes(imageBytes, pe, {
        maxCodes: cfg.maxCodes ?? 32,
        maxScanBytes: cfg.maxScanBytes,
      });
      report.harvestedIoctls = harvested.map((h) => ({
        value: h.value,
        hex: `0x${h.value.toString(16).padStart(8, "0")}`,
        rva: `0x${h.rva.toString(16)}`,
      }));
      report.autoIrps = await autoDriveIrps(kernel, device, {
        sendIrp,
        harvested,
        maxCodes: cfg.maxCodes ?? 32,
        inputPatterns: cfg.inputPatterns,
        outputLen: cfg.outputLen ?? 64,
      });
      report.dbgLog.push(...kernel.dbgLog.splice(0));
      report.exceptions.push(...kernel.exceptionTrace.splice(0));
      report.irqlViolations.push(...kernel.irqlViolations.splice(0));
      if (kernel.bugcheck || kernel.crash) report.bugcheck = kernel.bugcheck ?? kernel.crash;
    }

    for (const spec of opts.ioctls ?? []) {
      if (report.bugcheck) break;
      const r = await sendIrp(kernel, device, {
        major: spec.major ?? IRP_MJ.DEVICE_CONTROL,
        ioctl: typeof spec.code === "string"
          ? BigInt(spec.code.replace(/^0x/i, ""))
          : BigInt(spec.code ?? 0),
        input: spec.input instanceof Uint8Array ? spec.input : hexToBytes(spec.inputHex ?? spec.input),
        outputLen: spec.outputLen ?? 0,
        minor: spec.minor,
      });
      report.ioctls.push({
        ...r,
        outputHex: r.outputHex ?? "",
        error: r.error ? String(r.error.message ?? r.error) : undefined,
      });
      report.dbgLog.push(...kernel.dbgLog.splice(0));
      report.exceptions.push(...kernel.exceptionTrace.splice(0));
      report.irqlViolations.push(...kernel.irqlViolations.splice(0));
      if (r.status !== "ok") break; // stop driving after first hard failure
    }
  }

  // ------------------------------------------------------------ unload
  if (opts.runUnload && entryResult.status === "ok" && !report.bugcheck) {
    report.unload = summarizeCall(await callDriverUnload(kernel, drvRec));
    report.dbgLog.push(...kernel.dbgLog.splice(0));
    report.exceptions.push(...kernel.exceptionTrace.splice(0));
  }

  // ------------------------------------------------------------ summary
  report.apiTraceSummary = summarizeApiTrace(kernel.apiTrace);
  report.symbolicLinks = kernel.symbolicLinks ?? [];
  report.registryWrites = summarizeRegistryWrites(kernel);
  report.filesWritten = [...(kernel.fs ?? new Map()).entries()]
    .filter(([, b]) => b.length > 0)
    .map(([p, b]) => ({ path: p, size: b.length }));
  report.notifyRoutines = Object.fromEntries(
    Object.entries(kernel.notifyRoutines).map(([k2, arr]) => [k2, arr.length]),
  );
  // live session for interactive follow-ups (UI IOCTLs / unload). Not JSON.
  report.__session = {
    kernel,
    drvRec,
    device,
    image,
  };
  return report;
}

function summarizeCall(r) {
  if (!r) return null;
  const out = { status: r.status };
  if ("retval" in r) out.retval = `0x${BigInt.asUintN(32, r.retval).toString(16).padStart(8, "0")}`;
  if (r.sehHandled) out.sehHandled = true;
  if (r.sehDetail) out.sehDetail = r.sehDetail;
  if (r.error) out.error = String(r.error.message ?? r.error);
  if (r.rip !== undefined) out.rip = `0x${r.rip.toString(16)}`;
  return out;
}

function summarizeApiTrace(trace) {
  if (!trace.length) return null;
  const byName = new Map();
  for (const e of trace) {
    const rec = byName.get(e.name) ?? { count: 0, args: [] };
    rec.count++;
    if (rec.args.length < 3) {
      rec.args.push({
        args: e.args.slice(0, 4).map((a) => `0x${a.toString(16)}`),
        ret: `0x${e.ret.toString(16)}`,
      });
    }
    byName.set(e.name, rec);
  }
  return {
    totalCalls: trace.length,
    distinct: byName.size,
    byName: Object.fromEntries([...byName.entries()].slice(0, 256)),
  };
}

function summarizeRegistryWrites(kernel) {
  const out = [];
  for (const [path, values] of kernel.registry ?? []) {
    for (const [name, entry] of values) {
      out.push({ path, value: name, type: entry.type, bytes: entry.data.length });
    }
  }
  return out;
}
