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
import { Mmu, TranslatedMemory } from "./paging.mjs";

const DEFAULT_BASES = {
  kva: 0xfffff80000000000n,
  pool: 0xfffff90000000000n, // synthetic "NonPaged" pool region
  thunk: 0xfffff80100000000n, // kernel API thunks
  eproc: 0xffffb80000000000n, // synthesized EPROCESS blocks
  driver: 0xfffff80200000000n, // DRIVER_OBJECT / analyzer scratch
};

/** Software-visible IRQL names (x64). Levels >= 3 are device/clock/IPI/high;
 *  precise sub-naming varies by platform so we label the band generically. */
export const IRQL_NAMES = {
  0: "PASSIVE_LEVEL",
  1: "APC_LEVEL",
  2: "DISPATCH_LEVEL",
};

export function irqlName(level) {
  return IRQL_NAMES[level] ?? (level > 2 ? "DEVICE_OR_HIGHER" : "?");
}

const POOL_MAGIC = 0x4b46454c52505352n; // 'RSPLRFEK'-ish sentinel (LE)
const POOL_GUARD_BYTE = 0xa5;
const POOL_GUARD_LEN = 16;

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
    const raw = opts.cpu?.mem ?? new SparseMemory();
    this.rawMem = raw;
    this.cpu = opts.cpu;

    // Guest paging: the raw store becomes physically addressed, and the
    // kernel-facing `mem` is a translating facade. Only the JS interpreter
    // executes through translation today; injected backends keep raw memory
    // and must program their own CRs (see backend contract).
    this.paging = !!opts.paging && !opts.cpu;
    if (this.paging) {
      const tm = new TranslatedMemory();
      this.mmu = new Mmu(raw, { demandMap: opts.demandMap ?? true });
      tm.attach(this.mmu);
      this.mem = tm;
      this.cr3 = this.mmu.newAddressSpace();
      this.mmu.enablePaging(this.cr3);
    } else {
      this.mmu = null;
      this.mem = raw;
    }

    this.tables = opts.tables ?? new StructTables();
    if (!this.cpu) this.cpu = new JsInterpreter(this.mem);
    this.cpu.mem = opts.cpu ? raw : this.mem;
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
    /** @type {Map<string, Uint8Array>} export name -> pristine prologue bytes */
    this.pristineThunks = new Map();
    /** @type {Array<{api:string, thunk:bigint, target:bigint, module:string}>} */
    this.inlineHooks = [];

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
    /** @type {Array<{addr:bigint,size:number,tag:string,freed:boolean}>} */
    this.poolAllocs = [];

    /** interrupt state: current processor IRQL (0=PASSIVE .. 31) */
    this.currentIrql = 2; // DISPATCH_LEVEL default in our labs
    /** @type {Array<{dpcVa:bigint, routine:bigint, context:bigint, drained:boolean}>} */
    this.pendingDpcs = [];
    /** scenario hook invoked when a queued DPC finally drains */
    this.onDpcDrain = null;
    /** scenario hook invoked when pool verification passes after corruption */
    this.onPoolHealed = null;
    /** when true, double-free raises a modeled BAD_POOL_CALLER bugcheck */
    this.poolStrict = false;

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
      "_MMVAD", "_MMVAD_SHORT",
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

    // ------------------------------------------------------- guest paging
    if (this.paging) {
      // DirectoryTableBase in every EPROCESS (KPROCESS is embedded at offset 0)
      let dtbOff = 0n;
      try { dtbOff = BigInt(this.tables.offsetOf("_KPROCESS", "DirectoryTableBase")); } catch { /* best effort */ }
      if (dtbOff > 0n) {
        for (const addr of this.processesByName.values()) {
          this.mem.w64(addr + dtbOff, this.cr3 & ~0xfffn);
        }
      }

      // KUSER_SHARED_DATA: one physical frame, two VA views — the classic
      // user 0x7FFE0000 and the kernel alias 0xFFFFF780`00000000.
      const kuserFrame = this.mmu.frameAlloc();
      const kuser = new Uint8Array(4096);
      const w32at = (off, v) => {
        kuser[off] = v & 0xff; kuser[off+1] = (v>>>8)&0xff; kuser[off+2] = (v>>>16)&0xff; kuser[off+3] = (v>>>24)&0xff;
      };
      w32at(0x000, 1);            // modeled TickCountLowDeprecated
      w32at(0x2c4, 10);           // NtMajorVersion 10
      w32at(0x2c8, 0);            // NtMinorVersion 0
      w32at(0x300, 2);            // SuiteMask ~ Server
      kuser[0x304] = 1;           // KdDebuggerEnabled
      this.rawMem.write(kuserFrame, kuser);
      for (const va of [0x7ffe0000n, 0xfffff78000000000n]) {
        this.mmu.mapPage(va, kuserFrame, { write: false, nx: true });
      }
      this.kuserSharedData = 0x7ffe0000n;
    }
  }

  /** Guest-VA -> guest-PA via the MMU (null when unmapped / paging off). */
  vtop(va) {
    return this.paging ? (this.mmu.lookup(va)?.pa ?? null) : BigInt(va);
  }

  /** Raw leaf PTE for a guest VA under paging (null otherwise). */
  readPte(va) {
    return this.paging ? this.mmu.readPte(va) : null;
  }

  // -------------------------------------------------------------- pool

  /**
   * Layout per allocation (32 bytes of bookkeeping around the payload):
   *   [hdr magic u64 @ addr-16][pad 8][payload size bytes @ addr][guard 16B]
   * The guard lets !poolverify catch out-of-bounds writes before they turn
   * into distant, unrelated bugchecks.
   */
  allocPool(size, tag = "ntsm") {
    const aligned = (size + 15) & ~15;
    const hdr = this.nextPool;
    const addr = hdr + 16n;
    this.nextPool += BigInt(aligned) + 32n; // header(16) + guard(16) + payload
    this.mem.w64(hdr, POOL_MAGIC);
    this._writeGuard(addr, size);
    this.poolAllocs.push({ addr, size, tag, freed: false });
    return addr;
  }

  /** Register a scenario-seeded block at a fixed VA (deterministic labs). */
  registerPoolBlock(addr, size, tag = "ntsm") {
    this.mem.w64(addr - 16n, POOL_MAGIC);
    this._writeGuard(addr, size);
    this.poolAllocs.push({ addr, size, tag, freed: false, fixed: true });
    return { addr, size, tag };
  }

  _writeGuard(addr, size) {
    this.mem.write(
      addr + BigInt(size),
      new Uint8Array(POOL_GUARD_LEN).fill(POOL_GUARD_BYTE),
    );
  }

  freePool(addr) {
    const entry = this.poolAllocs.find((a) => a.addr === BigInt(addr));
    if (!entry) {
      this.dbgLog.push(`[pool] ExFreePoolWithTag: unknown address — ignored`);
      return false;
    }
    if (entry.freed) {
      if (this.poolStrict) {
        // modeled BAD_POOL_CALLER (0xC2): P1=0x7 double free-ish, P2=addr
        this.bugcheck = { code: 0xc2n, params: [0x7n, BigInt(addr), 0n, 0n] };
        this.crash = { code: "0xc2" };
        this.cpu.halted = true;
      } else {
        this.dbgLog.push(`[pool] double free at ${addr.toString(16)} detected`);
      }
      return false;
    }
    entry.freed = true;
    return true;
  }

  /** Sweep all allocation guards. Returns the corrupted entries. */
  verifyGuards() {
    return this.poolAllocs.filter((a) => {
      if (a.freed) return false;
      for (let i = 0; i < POOL_GUARD_LEN; i++) {
        if (this.mem.u8(a.addr + BigInt(a.size) + BigInt(i)) !== POOL_GUARD_BYTE) return true;
      }
      return false;
    });
  }

  guardBytes(addr) {
    const entry = this.poolAllocs.find((a) => a.addr === BigInt(addr));
    if (!entry) return null;
    return new Uint8Array(POOL_GUARD_LEN).fill(POOL_GUARD_BYTE);
  }

  // ------------------------------------------------------------ IRQL / DPC

  raiseIrql(level) {
    if (level < this.currentIrql) {
      // real Windows: KeRaiseIrql below current = bugcheck IRQL_NOT_LESS_OR_EQUAL
      this.bugcheck = { code: 0xan, params: [BigInt(level), 0n, 0n, 0n] };
      this.crash = { code: "0xa" };
      this.cpu.halted = true;
      throw new Error(`KeRaiseIrql: cannot raise to ${level} below current ${this.currentIrql}`);
    }
    const old = this.currentIrql;
    this.currentIrql = level;
    return old;
  }

  lowerIrql(level) {
    if (level > this.currentIrql) {
      this.bugcheck = { code: 0xan, params: [BigInt(level), 1n, 0n, 0n] };
      this.crash = { code: "0xa" };
      this.cpu.halted = true;
      throw new Error(`KeLowerIrql: cannot raise IRQL ${this.currentIrql} -> ${level}`);
    }
    this.currentIrql = level;
  }

  queueDpc(dpcVa, routine, context = 0n) {
    if (this.pendingDpcs.some((d) => d.dpcVa === dpcVa && !d.drained)) return false;
    this.pendingDpcs.push({ dpcVa, routine, context, drained: false });
    return true;
  }

  /** Fire every queued DPC (caller must be <= DISPATCH_LEVEL). */
  drainDpcs() {
    const fired = [];
    for (const d of this.pendingDpcs) {
      if (d.drained) continue;
      d.drained = true;
      fired.push(d);
      this.dbgLog.push(`nt: KiRetireDpcList: DPC @ ${d.dpcVa.toString(16)} fired`);
      try { this.onDpcDrain?.(d); } catch (e) { this.dbgLog.push(`[dpc] callback threw: ${e.message}`); }
    }
    return fired;
  }

  // ------------------------------------------------------------ API surface

  defineApi(name, impl) {
    if (!this.apiThunks.has(name)) {
      const thunk = this.nextThunk;
      this.nextThunk += 16n;
      this.mem.write(thunk, [0xf4]); // hlt marker (hook intercepts first)
      this.apiThunks.set(name, thunk);
      this.pristineThunks.set(name, this.mem.read(thunk, 8));
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

  /** Write an E9 rel32 detour over an export's prologue (hook modeling). */
  installDetour(apiName, targetVa) {
    const thunk = this.apiThunks.get(apiName);
    if (!thunk) throw new Error(`installDetour: unknown api "${apiName}"`);
    const rel = Number(BigInt.asIntN(32, targetVa - (thunk + 5n)));
    this.mem.write(thunk, [
      0xe9,
      rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >> 24) & 0xff,
    ]);
  }

  isDetoured(apiName) {
    const thunk = this.apiThunks.get(apiName);
    return !!thunk && this.mem.u8(thunk) === 0xe9;
  }

  /** Restore pristine prologue bytes recorded at defineApi time. */
  restorePrologue(apiName) {
    const thunk = this.apiThunks.get(apiName);
    const orig = this.pristineThunks.get(apiName);
    if (!thunk || !orig) return false;
    this.mem.write(thunk, [...orig]);
    return true;
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
        case "p": return v === 0n ? "0000000000000000" : v.toString(16).padStart(16, "0");
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
   * DPCs use the queueDpc record model (drained flag + onDpcDrain callback,
   * fired once per record); every routine is ALSO invoked through the CPU —
   * the analyzer needs real execution, not just retirement. Bounded:
   * at most `maxPasses` sweeps so requeueing drivers can't spin forever.
   * @returns {{dpcs:number, workItems:number, apcs:number}}
   */
  drainDeferred(maxPasses = 8) {
    const counts = { dpcs: 0, workItems: 0, apcs: 0 };
    for (let pass = 0; pass < maxPasses; pass++) {
      const dpcs = this.pendingDpcs.filter((d) => !d.drained);
      this.pendingDpcs.forEach((d) => { d.drained = true; });
      const work = this.pendingWorkItems.splice(0);
      const apcs = this.pendingApcs.splice(0);
      if (!dpcs.length && !work.length && !apcs.length) break;

      for (const d of dpcs) {
        counts.dpcs++;
        this.dbgLog.push(`nt: KiRetireDpcList: DPC @ ${d.dpcVa.toString(16)} fired`);
        try { this.onDpcDrain?.(d); } catch (e) { this.dbgLog.push(`[dpc] callback threw: ${e.message}`); }
        if (!d.routine) continue;
        const r = this.cpu.callFunction(d.routine, [d.dpcVa ?? 0n, d.context ?? 0n, 0n, 0n]);
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

  /**
   * Materialize zero-filled backing for the module image range
   * [base, base+size) so debugger reads (db/dq/s/!dh/u) and guest fetches
   * see a fully mapped region instead of "unmapped" holes between the few
   * evidence pages a scenario wrote. Idempotent per page. When the CPU
   * backend exposes mapRange() (Unicorn), the same span is pre-mapped in
   * the emulator's address space so `lm`-listed modules are executable and
   * readable without waiting for a run's demand sync.
   *
   * Callers should invoke this whenever a module is appended to
   * loadedModules. Real dump modules are deliberately NOT materialized —
   * their non-resident ranges are pedagogically meaningful.
   * @returns {number} pages materialized (0 when everything was backed)
   */
  materializeModuleRange(base, size) {
    const start = BigInt(base) & ~0xfffn;
    const end = BigInt(base) + BigInt(size);
    if (end <= start) return 0;
    let fresh = 0;
    for (let p = start; p < end; p += 0x1000n) {
      if (!this.mem.hasPage(p)) {
        // int3 padding rather than zeros: real .text alignment padding is
        // 0xCC-filled, static analysis treats CC as a boundary edge, and
        // stray execution of an unmapped-in-reality page halts loudly
        this.mem.write(p, new Uint8Array(0x1000).fill(0xcc));
        fresh++;
      }
    }
    if (typeof this.cpu?.mapRange === "function") {
      try { this.cpu.mapRange(start, end - start); } catch { /* optional */ }
    }
    return fresh;
  }

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
