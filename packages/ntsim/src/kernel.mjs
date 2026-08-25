/**
 * ntsim kernel model: emulated x64 Windows kernel over SparseMemory + pluggable CPU.
 *
 * Realism rules:
 * - Every struct access goes through Vergilius tables for the active build.
 * - Process list is genuine _EPROCESS chain walkable by student drivers.
 * - Kernel APIs are hooked at fixed thunk addresses; student imports resolve there.
 */

import { SparseMemory } from "./memory.mjs";
import { StructTables, StructRef } from "./structs.mjs";
import { JsInterpreter, M64 } from "./cpu.mjs";
import { installWinApi } from "./winapi.mjs";
import { SymbolEngine } from "./symbols.mjs";
import { tryDispatchException } from "./seh.mjs";

const DEFAULT_BASES = {
  kva: 0xfffff80000000000n,
  pool: 0xfffff90000000000n, // synthetic "NonPaged" pool region
  thunk: 0xfffff80100000000n, // kernel API thunks
  eproc: 0xffffb80000000000n, // synthesized EPROCESS blocks
  driver: 0xfffff80200000000n, // DRIVER_OBJECT / analyzer scratch
};

const DEFAULT_PROCESSES = [
  { pid: 4, name: "System", ppl: null },
  { pid: 84, name: "wininit.exe", ppl: null },
  { pid: 96, name: "services.exe", ppl: null },
  { pid: 108, name: "lsass.exe", ppl: { type: "Light", signer: "WinTcb" } }, // PPL!
  { pid: 116, name: "winlogon.exe", ppl: null },
  { pid: 312, name: "kfsample.exe", ppl: null },
  { pid: 666, name: "kftarget.exe", ppl: null },
];

export class NtKernel {
  /**
   * @param {{tables?: object, tablesDir?: string, buildName?: string,
   *          cpu?: import("./cpu.mjs").CpuBackend,
   *          bases?: {kva?: bigint, pool?: bigint, thunk?: bigint, eproc?: bigint}}} opts
   *   `cpu`: inject a pre-built backend (e.g. UnicornCpuBackend bound to the
   *   same SparseMemory). Defaults to the deterministic JsInterpreter.
   *   `bases`: override synthetic VA regions (tests use low-memory layouts;
   *   defaults mirror real Windows kernel VAs).
   */
  constructor(opts = {}) {
    // Adopt the injected backend's memory so guest, kernel model, and CPU
    // all share ONE address space (JsInterpreter default binds its own).
    this.mem = opts.cpu?.mem ?? new SparseMemory();
    this.tables = opts.tables ?? new StructTables();
    this.cpu = opts.cpu ?? new JsInterpreter(this.mem);
    this.cpu.mem = this.mem;
    // Unified register surface: expose `rip` on backends whose regfile lacks
    // it (JsInterpreter tracks RIP separately from the GPR dict).
    if (this.cpu.regs && !("rip" in this.cpu.regs)) {
      const cpuRef = this.cpu;
      Object.defineProperty(cpuRef.regs, "rip", {
        get() { return cpuRef.rip ?? 0n; },
        set(v) { cpuRef.rip = BigInt.asUintN(64, BigInt(v)); },
        configurable: true,
      });
    }
    const B = opts.bases ?? {};
    /** @type {typeof DEFAULT_BASES} */
    this.bases = {
      kva: B.kva ?? DEFAULT_BASES.kva,
      pool: B.pool ?? DEFAULT_BASES.pool,
      thunk: B.thunk ?? DEFAULT_BASES.thunk,
      eproc: B.eproc ?? DEFAULT_BASES.eproc,
      driver: B.driver ?? DEFAULT_BASES.driver,
    };
    this.buildName = opts.buildName ?? "synthetic-22h2";

    /** @type {Map<string, bigint>} export name -> thunk VA */
    this.apiThunks = new Map();
    this.nextThunk = this.bases.thunk;
    /** @type {Map<string, Function>} export name -> js impl */
    this.apiImpls = new Map();

    // analyzer state -----------------------------------------------------
    /** @type {Array<{name:string,args:bigint[],ret:bigint,retAddr:bigint}>} */
    this.apiTrace = [];
    this.apiTraceLimit = 8192;
    /** exports auto-provisioned as traced stubs (run-any-*.sys mode) */
    this.unmodeledExports = [];
    /** IRQL violations (Zw or Nt exports called above APC_LEVEL) */
    this.irqlViolations = [];
    /** exception dispatch log */
    this.exceptionTrace = [];
    /** queued DPCs / work items / APCs awaiting drainDpcs() */
    this.pendingDpcs = [];
    this.pendingWorkItems = [];
    this.pendingApcs = [];

    // pool
    this.nextPool = this.bases.pool;
    /** @type {Array<{addr:bigint,size:number,tag:string}>} */
    this.poolAllocs = [];

    /** @type {Map<string, bigint>} name -> EPROCESS va */
    this.processesByName = new Map();

    /** captured DbgPrint lines */
    this.dbgLog = [];

    /** bugcheck state */
    this.crash = null;

    /** @type {Array<{driverObj:bigint, name:string}>} */
    this.loadedDrivers = [];

    // Tier 2 Micro-Symbol Service
    this.symbolEngine = new SymbolEngine();
    if (this.tables) this.symbolEngine.loadFromTables(this.tables);

    this._wireApiHooks();
    installWinApi(this);

    // Seed a tiny demo hive (Qiling-style virtual registry)
    this.registrySeed("\\Registry\\Machine\\SOFTWARE\\KernelForge", {
      Version: "1.0.0",
    });
    this.registrySeed(
      "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\kfprobe",
      { Start: "\u0003\u0000\u0000\u0000" });

    this._installCpuHook();
  }

  // ------------------------------------------------------------------ boot

  /** Wire dump-derived globals into the SymbolEngine (call after bootstrap). */
  loadDumpGlobals(headerFields = {}) {
    if (!this.symbolEngine) return;
    this.symbolEngine.loadDumpGlobals({
      psActiveProcessHead: "0x" + this.PsActiveProcessHead?.toString(16),
      ...headerFields,
    });
  }

  async loadTablesFromDir(dir) {
    const names = [
      "_EPROCESS", "_ETHREAD", "_KPROCESS", "_KTHREAD", "_LIST_ENTRY",
      "_UNICODE_STRING", "_OBJECT_TYPE", "_OBJECT_HEADER", "_HANDLE_TABLE",
      "_PS_PROTECTION", "_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY",
    ];
    this.tables = await StructTables.loadDir(dir, names);
  }

  /** Synthesize the process environment with real per-build offsets. */
  bootstrap() {
    const t = this.tables;
    if (!t.has("_EPROCESS")) throw new Error("EPROCESS table not loaded");

    const eprocSize = Number(t.sizeOf("_EPROCESS"));
    const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");

    // layout: [head LIST_ENTRY][eproc0][eproc1]...
    const headAddr = this.bases.eproc;
    let nextEproc = headAddr + 16n;

    const linkAddrs = [];
    for (const p of DEFAULT_PROCESSES) {
      const addr = nextEproc;
      nextEproc += BigInt(eprocSize);
      const e = new StructRef(this.mem, this.tables, addr, "_EPROCESS");
      e.w64("UniqueProcessId", BigInt(p.pid));
      e.writeAnsiField("ImageFileName", p.name, 15);
      if (p.ppl && t.has("_PS_PROTECTION")) {
        // _PS_PROTECTION bit pack: Type(4b) | Audit(2b) | Signer(4b)
        // Light type=2, WinTcb signer=6 => 0x62
        e.w8("Protection", (2 << 4) | 6);
      }
      this.processesByName.set(p.name, addr);
      linkAddrs.push(addr + linksOff);
    }

    // circular doubly-linked list through head
    this.PsActiveProcessHead = headAddr;
    for (let i = 0; i < linkAddrs.length; i++) {
      const prevLinks = i === 0 ? headAddr : linkAddrs[i - 1];
      const nextLinks = i === linkAddrs.length - 1 ? headAddr : linkAddrs[i + 1];
      this.mem.w64(linkAddrs[i], nextLinks);     // Flink
      this.mem.w64(linkAddrs[i] + 8n, prevLinks); // Blink
    }
    this.mem.w64(headAddr, linkAddrs[0]);
    this.mem.w64(headAddr + 8n, linkAddrs[linkAddrs.length - 1]);

    // scenario modules visible via `lm` — kfbootkit.sys is the L1 flag target
    this.loadedDrivers.push(
      { name: "ntoskrnl.exe", base: 0xfffff8052b800000n, imageSize: 0x800000 },
      { name: "HAL.dll", base: 0xfffff8052b000000n, imageSize: 0x40000 },
      { name: "kfbootkit.sys", base: 0xfffff80539000000n, imageSize: 0x8000 },
    );
  }

  // -------------------------------------------------------------- pool

  allocPool(size, tag = "ntsm") {
    const aligned = (size + 15) & ~15;
    const addr = this.nextPool;
    this.nextPool += BigInt(aligned + 16); // header-ish spacing
    this.poolAllocs.push({ addr, size, tag });
    return addr;
  }

  freePool(_addr) {
    // bump allocator: frees are no-ops tracked for realism stats only
    return true;
  }

  // ------------------------------------------------------------ API surface

  defineApi(name, impl) {
    if (!this.apiThunks.has(name)) {
      const thunk = this.nextThunk;
      this.nextThunk += 16n;
      this.mem.write(thunk, [0xf4]); // hlt marker (hook intercepts first)
      this.apiThunks.set(name, thunk);
    }
    this.apiImpls.set(name, impl.bind(this));
    return this.apiThunks.get(name);
  }

  /**
   * Auto-provision an export we have no model for: a traced thunk returning
   * STATUS_SUCCESS. Used when running arbitrary uploaded drivers — unknown
   * imports must not abort the map; they stay visible in unmodeledExports.
   */
  provisionUnknownApi(name) {
    if (this.apiThunks.has(name)) return this.apiThunks.get(name);
    this.unmodeledExports.push(name);
    this.dbgLog.push(`[analyzer] provisioned unmodeled export ${name} -> SUCCESS`);
    return this.defineApi(name, () => 0n);
  }

  /** Resolve "ntdll!Name"-style import; provisions when unknown. */
  resolveImportProvisioned(qualified) {
    const name = qualified.includes("!") ? qualified.split("!").pop() : qualified;
    const known = this.apiThunks.get(name);
    if (known) return known;
    // WDF/FLTMGR/ndis-style prefixed names still get generic stubs
    return this.provisionUnknownApi(name);
  }

  _wireApiHooks() {
    const k = this;
    this.defineApi("DbgPrint", function (fmtAddr, ...args) {
      k.dbgPrint(fmtAddr, args);
      return 0n;
    });
    this.defineApi("ExAllocatePoolWithTag", function (poolType, size, tag) {
      const tagStr = String.fromCharCode(
        Number(tag & 0xffn), Number((tag >> 8n) & 0xffn),
        Number((tag >> 16n) & 0xffn), Number((tag >> 24n) & 0xffn),
      );
      return k.allocPool(Number(size), tagStr);
    });
    this.defineApi("ExFreePoolWithTag", function (addr, _tag) {
      k.freePool(addr);
      return undefined;
    });
    this.defineApi("PsLookupProcessByProcessId", function (pid, outPtr) {
      const found = k.findEprocessByPid(pid);
      if (found === null) return 0xc000000bn; // STATUS_INVALID_PARAMETER-ish
      k.mem.w64(outPtr, found);
      return 0n;
    });
    this.defineApi("KeGetCurrentIrql", function () {
      return BigInt(k.currentIrql ?? 2); // DISPATCH_LEVEL default in our labs
    });
  }

  dbgPrint(fmtAddr, args) {
    const fmt = this.mem.readAnsi(fmtAddr, 512);
    let ai = 0;
    const out = fmt.replace(/%(-?\d+)?(?:\.(\d+))?([wsdIxXpuZgsc])/g, (_m, _w, _p, conv) => {
      const v = args[ai++] ?? 0n;
      switch (conv) {
        case "d": return BigInt.asIntN(64, v).toString();
        case "u": return v.toString();
        case "x": case "X": return v.toString(16).padStart(conv === "X" ? 8 : 8, conv === "X" ? "XXXXXXXXXXXXXXXX".slice(0, 8) : "00000000");
        case "p": return `ffff${v.toString(16).padStart(12, "0")}`;
        case "w": case "Z": {
          // %wZ = UNICODE_STRING*
          const usLen = this.mem.u16(v);
          const buf = this.mem.u64(v + 8n);
          return this.mem.readUtf16(buf, usLen / 2);
        }
        case "s": return this.mem.readAnsi(v);
        default: return `%${conv}`;
      }
    });
    this.dbgLog.push(out);
    return out;
  }

  findEprocessByPid(pid) {
    const t = this.tables;
    let cur = this.mem.u64(this.PsActiveProcessHead); // first LINKS
    const head = this.PsActiveProcessHead;
    while (cur !== head && cur !== 0n) {
      const eproc = cur - t.offsetOf("_EPROCESS", "ActiveProcessLinks");
      if (this.mem.u64(eproc + t.offsetOf("_EPROCESS", "UniqueProcessId")) === pid) {
        return eproc;
      }
      cur = this.mem.u64(cur);
    }
    return null;
  }

  // ------------------------------------------------------------ driver exec

  _installCpuHook() {
    const handler = (rip) => {
      const T = this.bases.thunk;
      if (rip < T || rip >= T + 0x10000000n) return false;
      // find which api
      for (const [name, addr] of this.apiThunks) {
        if (addr === rip) {
          // windows x64 ABI: rcx rdx r8 r9, then stack args above the
          // return address + 32-byte shadow space ([rsp+0x28..]) — needed
          // for varargs (DbgPrintEx, sprintf) and >4-arg exports.
          const rsp = this.cpu.regs.rsp;
          const args = [
            this.cpu.regs.rcx, this.cpu.regs.rdx,
            this.cpu.regs.r8, this.cpu.regs.r9,
          ];
          for (let j = 0; j < 7; j++) {
            try { args.push(this.cpu.mem.u64(rsp + 0x28n + BigInt(8 * j))); } catch { args.push(0n); }
          }
          const retAddr = this.cpu.mem.u64(rsp);
          // IRQL contract: Zw*/Nt* require PASSIVE_LEVEL; log violations
          if ((name.startsWith("Zw") || name.startsWith("Nt")) && (this.currentIrql ?? 0) > 1) {
            this.irqlViolations.push({ name, irql: this.currentIrql });
            this.dbgLog.push(`[irql] ${name} called at IRQL ${this.currentIrql} (> APC_LEVEL)`);
          }
          const ret = this.apiImpls.get(name)(...args);
          // emulate ret
          this.cpu.regs.rax = typeof ret === "bigint" ? (ret & M64) : (ret === undefined ? 0n : BigInt(ret));
          this.cpu.regs.rsp = (rsp + 8n) & M64; // pop return address slot
          this.cpu.rip = retAddr;
          if (this.apiTrace.length < this.apiTraceLimit) {
            this.apiTrace.push({
              name,
              args: args.map((a) => a & M64),
              ret: this.cpu.regs.rax,
              retAddr,
            });
          }
          return true;
        }
      }
      return false;
    };
    if (typeof this.cpu.addCodeHook === "function") {
      this.cpu.addCodeHook(handler, this.bases.thunk, this.bases.thunk + 0x10000000n);
    } else {
      this.cpu.onCodeHook = handler;
    }
  }

  /** Invoke DriverEntry(driverObj, registryPath) on a mapped driver image. */
  callDriverEntry(entryAddr, driverObjectAddr = 0n, regPathAddr = 0n) {
    this.currentIrql = 2;
    const r = this.callFunctionSeh
      ? this.callFunctionSeh(entryAddr, [driverObjectAddr, regPathAddr])
      : this.cpu.callFunction(entryAddr, [driverObjectAddr, regPathAddr]);
    return r;
  }

  /**
   * callFunction with table-SEH fallback: on backend fault, attempt scope-
   * table dispatch for the given image; a handled exception re-enters the
   * __except handler as its own ABI call. Requires `image` {base, bytes}.
   */
  callFunctionSeh(addr, args = [], image = null) {
    const r = this.cpu.callFunction(addr, args);
    if (r.status !== "fault" || !image) return r;
    let dispatch;
    try {
      dispatch = tryDispatchException(this, image, r.error);
    } catch {
      return r; // malformed unwind data -> report the raw fault
    }
    this.exceptionTrace.push({
      faultRip: "0x" + (r.error?.rip ?? 0n).toString(16),
      handled: !!dispatch.handled,
      detail: dispatch.detail,
    });
    if (!dispatch.handled) return r;
    return {
      status: "ok",
      retval: dispatch.ntstatus ?? dispatch.result?.retval ?? 0n,
      sehHandled: true,
      sehDetail: dispatch.detail,
    };
  }

  // ------------------------------------------------------- deferred phases

  /**
   * Drain queued DPCs / work items / APCs left behind by the driver.
   * Each routine is invoked through the same SEH-aware call path. Bounded:
   * at most `maxPasses` sweeps so requeueing drivers can't spin forever.
   * @returns {{dpcs:number, workItems:number, apcs:number}}
   */
  drainDeferred(maxPasses = 8) {
    const counts = { dpcs: 0, workItems: 0, apcs: 0 };
    for (let pass = 0; pass < maxPasses; pass++) {
      const dpcs = this.pendingDpcs.splice(0);
      const work = this.pendingWorkItems.splice(0);
      const apcs = this.pendingApcs.splice(0);
      if (!dpcs.length && !work.length && !apcs.length) break;

      for (const d of dpcs) {
        counts.dpcs++;
        const r = this.cpu.callFunction(d.routine, [d.dpc ?? 0n, d.context ?? 0n, 0n, 0n]);
        this.dbgLog.push(`[dpc] routine 0x${d.routine.toString(16)} -> ${r.status}`);
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "dpc", detail: r.status });
      }
      for (const w of work) {
        counts.workItems++;
        const r = this.cpu.callFunction(w.worker, [w.device ?? 0n, w.context ?? 0n]);
        this.dbgLog.push(`[work] worker 0x${w.worker.toString(16)} -> ${r.status}`);
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "work", detail: r.status });
      }
      for (const a of apcs) {
        counts.apcs++;
        const r = this.cpu.callFunction(a.normalRoutine, [a.normalContext ?? 0n, a.systemArgument1 ?? 0n, a.systemArgument2 ?? 0n]);
        this.dbgLog.push(`[apc] normalRoutine 0x${a.normalRoutine.toString(16)} -> ${r.status}`);
        if (r.status !== "ok") this.exceptionTrace.push({ kind: "apc", detail: r.status });
      }
    }
    this.deferredDrain = counts;
    return counts;
  }

  // ------------------------------------------------------------ introspection

  listProcesses() {
    const t = this.tables;
    const out = [];
    let cur = this.mem.u64(this.PsActiveProcessHead);
    const head = this.PsActiveProcessHead;
    while (cur !== head && cur !== 0n) {
      const eproc = cur - t.offsetOf("_EPROCESS", "ActiveProcessLinks");
      const pid = this.mem.u64(eproc + t.offsetOf("_EPROCESS", "UniqueProcessId"));
      const nameOff = eproc + t.offsetOf("_EPROCESS", "ImageFileName");
      const name = this.mem.readAnsi(nameOff, 15);
      out.push({ pid, name, eprocess: eproc });
      cur = this.mem.u64(cur);
    }
    return out;
  }
}
