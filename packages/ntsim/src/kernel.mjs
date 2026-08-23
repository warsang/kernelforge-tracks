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

const KVA_BASE = 0xfffff80000000000n;
const POOL_BASE = 0xfffff90000000000n; // synthetic "NonPaged" pool region
const THUNK_BASE = 0xfffff80100000000n; // kernel API thunks
const EPROC_BASE = 0xffffb80000000000n; // synthesized EPROCESS blocks

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
   *          cpu?: import("./cpu.mjs").CpuBackend}} opts
   *   `cpu`: inject a pre-built backend (e.g. UnicornCpuBackend bound to the
   *   same SparseMemory). Defaults to the deterministic JsInterpreter.
   */
  constructor(opts = {}) {
    this.mem = new SparseMemory();
    this.tables = opts.tables ?? new StructTables();
    this.cpu = opts.cpu ?? new JsInterpreter(this.mem);
    if (!this.cpu.mem) this.cpu.mem = this.mem;
    this.buildName = opts.buildName ?? "synthetic-22h2";

    /** @type {Map<string, bigint>} export name -> thunk VA */
    this.apiThunks = new Map();
    this.nextThunk = THUNK_BASE;
    /** @type {Map<string, Function>} export name -> js impl */
    this.apiImpls = new Map();

    // pool
    this.nextPool = POOL_BASE;
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

    this._wireApiHooks();
    this._installCpuHook();
  }

  // ------------------------------------------------------------------ boot

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
    const headAddr = EPROC_BASE;
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
      if (rip < THUNK_BASE || rip >= THUNK_BASE + 0x10000000n) return false;
      // find which api
      for (const [name, addr] of this.apiThunks) {
        if (addr === rip) {
          // windows x64 ABI: rcx rdx r8 r9 (+ stack)
          const args = [
            this.cpu.regs.rcx, this.cpu.regs.rdx,
            this.cpu.regs.r8, this.cpu.regs.r9,
          ];
          const ret = this.apiImpls.get(name)(...args);
          // emulate ret
          this.cpu.regs.rax = typeof ret === "bigint" ? (ret & M64) : (ret === undefined ? 0n : BigInt(ret));
          this.cpu.rip = this.cpu.popVal();
          return true;
        }
      }
      return false;
    };
    if (typeof this.cpu.addCodeHook === "function") {
      this.cpu.addCodeHook(handler, THUNK_BASE, THUNK_BASE + 0x10000000n);
    } else {
      this.cpu.onCodeHook = handler;
    }
  }

  /** Invoke DriverEntry(driverObj, registryPath) on a mapped driver image. */
  callDriverEntry(entryAddr, driverObjectAddr = 0n, regPathAddr = 0n) {
    this.currentIrql = 2;
    const r = this.cpu.callFunction(entryAddr, [driverObjectAddr, regPathAddr]);
    return r;
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
