/**
 * UnicornCpuBackend — high-fidelity CPU backend for ntsim over a WASM build of
 * the Unicorn engine (QEMU TCG). Implements the CpuBackend contract documented
 * in packages/ntsim/src/cpu.mjs; JsInterpreter remains the reference/default.
 *
 * Design notes (validated in spike, see docs/spike-unicorn.md):
 * - The upstream JS wrapper marshals 64-bit addresses through f64 ("number"),
 *   which silently corrupts values > 2^53. Every address-bearing API here goes
 *   through raw ccall with Emscripten 'i64' types instead (BigInt-safe).
 * - Registers are exposed through a Proxy so `cpu.regs.rcx = v` keeps working;
 *   only BigInt ever crosses the boundary.
 * - SparseMemory stays the source of truth: pages sync IN before execution and
 *   OUT after it. Reads of never-touched memory behave as zeros on both
 *   backends because drivers only touch mapped regions in our labs.
 * - Kernel API thunks are intercepted with range-limited UC_HOOK_CODE hooks;
 *   the handler mutates regs/RIP and stops emulation, and the outer loop
 *   resumes from the synthetic `ret` target.
 *
 * Kernel-space VAs (>= 2^63, real Windows kernel addresses) execute correctly:
 * the engine's TLB is switched to UC_TLB_VIRTUAL so softmmu does a clean 1:1
 * VA mapping instead of truncating through the 52-bit physical space (upstream
 * issue #2010). Hook callbacks observe architectural RIPs even there.
 *
 * Fallback for vendored builds whose ctl() path is unavailable: pass
 * {execAliasTruncate:true} to createUnicornBackend() — pages at or above
 * bit 52 are then mapped at their low-52-bit alias (the address executed
 * accesses resolve to when paging is off), mirroring the KUSER_SHARED_DATA
 * trick proven in speakeasy. Off by default; alias collisions throw.
 */

import { CpuError } from "@kernelforge/ntsim/src/cpu.mjs";

// Single shared wasm module instance; initialization is async and idempotent.
let modulePromise = null;
async function loadModule() {
  if (!modulePromise) {
    modulePromise = (async () => {
      // The bundle is ESM now; its emscripten glue would pick the NODE branch
      // under Node and die on require(). Hide node-ness during eval+init so
      // it always takes the browser branch (WebAssembly works everywhere).
      const procRef = globalThis.process;
      const savedVersions = procRef?.versions;
      let masked = false;
      if (typeof document === "undefined" && savedVersions) {
        Object.defineProperty(procRef, "versions", { value: {}, configurable: true });
        masked = true;
      }
      try {
        const m = await import("../vendor/unicorn_x86.mjs");
        return (m.default ?? m)();
      } finally {
        if (masked) {
          Object.defineProperty(procRef, "versions", { value: savedVersions, configurable: true });
        }
      }
    })();
  }
  return modulePromise;
}

const M64 = 0xffffffffffffffffn;
/** x86-64 guest physical address width (vendored QEMU TARGET_PHYS_ADDR_SPACE_BITS). */
const PHYS_MASK52 = (1n << 52n) - 1n;
// Low sentinel: hooks over >2^53 ranges don't fire in unicorn<=2.1 wasm
// (same softmmu limit as upstream issue #2010), so the ABI return marker
// lives at a mapped low address instead of JsInterpreter's high magic.
// must stay below 2^31: wrapper marshals hook ranges through signed i32
const RET_MARKER = 0x0badf00dn;
const CHUNK_INSTRUCTIONS = 200_000;

/** u64 <-> signed i64 helpers for the wasm ABI. */
const toI64 = (v) => BigInt.asIntN(64, BigInt(v));
const toU64 = (v) => BigInt.asUintN(64, BigInt(v));

export class UnicornCpuBackend {
  /**
   * Use createUnicornBackend(); the constructor is sync-internal.
   * @param {object} mem SparseMemory-like (read/write pages as Uint8Array ops)
   * @param {object} uc initialized unicorn module namespace
   */
  #dirty = new Set();
  /** pages that are backend-internal (ABI sentinels) — never pulled into sparse */
  #internal = new Set();
  #arenaEnd = null;
  #pendingRip = null;
  /** alias base -> original base (execAliasTruncate collision detection) */
  #aliasOwner = new Map();
  /** low-52-bit truncation fallback for builds without working ctl() TLB switch */
  #execAliasTruncate = false;

  constructor(mem, uc, opts = {}) {
    this.#execAliasTruncate = !!opts.execAliasTruncate;
    this.mem = mem;
    this.uc = uc;
    this.engine = new uc.Unicorn(uc.ARCH_X86, uc.MODE_64);
    this.handle = uc.getValue(this.engine.handle_ptr, "*");
    this.steps = 0;
    this.fault = null;
    this.halted = false;

    /** @type {Set<string>} page bases mapped inside unicorn (hex strings) */
    this.#mapped = new Set();
    /**
     * Flat low arena so guests can touch never-materialized memory without
     * faulting (SparseMemory reads-as-zeros semantics). Lab layouts live here;
     * real kernel VAs stay unsupported until the paging bootstrap lands.
     */
    // Full 64-bit guest VA support: unicorn's default softmmu masks physical
    // addresses to x86_64's 52-bit PA space, breaking canonical kernel-half
    // VAs when paging is off (upstream issue #2010). The VIRTUAL tlb does a
    // clean 1:1 mapping instead. MUST go through the wrapper's ctl() which
    // builds a proper va_list buffer — raw fixed-arity ccalls silently no-op.
    // Skipped under execAliasTruncate: that fallback NEEDS the physical TLB
    // so executed accesses resolve into the low-52-bit alias space.
    if (!this.#execAliasTruncate) {
      const UC_CTL_TLB_TYPE = 12;
      const ctlWord = (type, nr, rw) => ((type | (nr << 26) | (rw << 30)) >>> 0);
      this.engine.ctl(ctlWord(UC_CTL_TLB_TYPE, 1, 1), [{ type: "i32", value: 1 /* UC_TLB_VIRTUAL */ }]);
    }

    const arenaSize = Number(opts?.arenaSize ?? 0x2000000);
    if (arenaSize > 0) {
      const rc = this.#rawMap(0n, BigInt(arenaSize), uc.PROT_ALL);
      if (rc === 0) {
        this.#arenaEnd = BigInt(arenaSize);
        // arena is managed wholesale: never per-page map/write it in syncIn,
        // but DO record writes inside it as dirty for pull-back.
      }
    }
    engine_hook_init(this);

    function engine_hook_init(self) {
      // dirty-page tracker: record every written page during execution.
      self.engine.hook_add(uc.HOOK_MEM_WRITE, (_h, _type, address) => {
        // page base only: syncOut pulls whole pages back into SparseMemory
        self.#dirty.add((toU64(address) & ~0xfffn).toString(16));
      }, 0, 1, 0);
    }

    this.regs = new Proxy({}, {
      get: (_t, prop) => {
        if (prop === "rip") {
          if (this.#pendingRip !== null) return this.#pendingRip;
          return toU64(this.engine.reg_read_i64(uc.X86_REG_RIP));
        }
        const id = GPR_IDS.get(prop);
        if (id === undefined) return undefined;
        return toU64(this.engine.reg_read_i64(id));
      },
      set: (_t, prop, v) => {
        if (typeof v !== "bigint") throw new TypeError("registers are BigInt-only");
        if (prop === "rip") {
          // QEMU resyncs its internal IP on emu_stop, clobbering reg writes
          // made from inside hook callbacks — remember our intent instead.
          this.#pendingRip = toU64(v);
          this.engine.reg_write_i64(uc.X86_REG_RIP, toI64(v));
          return true;
        }
        const id = GPR_IDS.get(prop);
        if (id === undefined) throw new TypeError(`unknown register ${String(prop)}`);
        this.engine.reg_write_i64(id, toI64(v));
        return true;
      },
    });
  }

  #mapped;
  /** rip lives in the proxy-friendly register file too. */
  get rip() { return this.regs.rip; }
  set rip(v) { this.regs.rip = v; }

  // ------------------------------------------------------------- raw ccalls

  #rawMap(base, size, perms) {
    return this.uc.ccall("uc_mem_map", "number",
      ["pointer", "i64", "i64", "number"],
      [this.handle, toI64(base), toI64(size), perms]);
  }
  #rawWrite(addr, bytes) {
    const p = this.uc._malloc(bytes.length);
    this.uc.writeArrayToMemory(bytes, p);
    const r = this.uc.ccall("uc_mem_write", "number",
      ["pointer", "i64", "pointer", "i64"],
      [this.handle, toI64(addr), p, toI64(bytes.length)]);
    this.uc._free(p);
    if (r !== 0) throw new CpuError(`uc_mem_write failed (${r})`, addr);
  }
  #rawRead(addr, len) {
    const p = this.uc._malloc(len);
    try {
      const r = this.uc.ccall("uc_mem_read", "number",
        ["pointer", "i64", "pointer", "i64"],
        [this.handle, toI64(addr), p, toI64(len)]);
      if (r !== 0) throw new CpuError(`uc_mem_read failed (${r})`, addr);
      return this.uc.HEAPU8.slice(p, p + len);
    } finally {
      this.uc._free(p);
    }
  }
  #rawStart(begin, count) {
    return this.uc.ccall("uc_emu_start", "number",
      ["pointer", "i64", "i64", "i64", "number"],
      [this.handle, toI64(begin), 0n, 0n, count]);
  }

  // ---------------------------------------------------------- memory bridge

  PAGE = 4096;

  /**
   * Address inside unicorn's (physical) space for a guest page base.
   * Default: identity — the UC_TLB_VIRTUAL switch handles canonical VAs.
   * execAliasTruncate: fold everything at or above bit 52 down into the
   * 52-bit physical space executed accesses actually resolve to.
   */
  #ucAddrFor(base) {
    if (this.#execAliasTruncate && base >= (1n << 52n)) {
      const alias = base & PHYS_MASK52;
      const key = alias.toString(16);
      const owner = this.#aliasOwner.get(key);
      if (owner !== undefined && owner !== base) {
        throw new CpuError(
          `exec-alias collision: 0x${base.toString(16)} and 0x${owner.toString(16)} share low-52 bits`,
          base,
        );
      }
      this.#aliasOwner.set(key, base);
      return alias;
    }
    return base;
  }

  #ensurePageMapped(base) {
    base = toU64(BigInt(base)) & ~0xfffn;
    const ucBase = this.#ucAddrFor(base);
    const key = base.toString(16);
    if (!this.#mapped.has(key)) {
      if (this.#arenaEnd !== null && ucBase < this.#arenaEnd) {
        this.#mapped.add(key); // covered by the flat arena already
      } else {
        const rc = this.#rawMap(ucBase, BigInt(this.PAGE), this.uc.PROT_ALL);
        if (rc !== 0) throw new CpuError(`uc_mem_map failed (${rc}) @ ${base.toString(16)}`, base);
        this.#mapped.add(key);
      }
    }
    return base;
  }

  /** Pull every guest-visible unicorn page into SparseMemory. */
  #pullAll() {
    for (const key of this.#mapped) {
      if (this.#internal.has(key)) continue;
      const base = BigInt("0x" + key);
      this.mem.write(base, this.#rawRead(this.#ucAddrFor(base), this.PAGE));
    }
  }

  /** Push every materialized SparseMemory page into unicorn. */
  #syncIn() {
    for (const [key, page] of this.mem.pages) {
      const base = BigInt("0x" + key);
      this.#ensurePageMapped(base);
      this.#rawWrite(this.#ucAddrFor(base), page);
    }
  }
  /** Pull guest-written pages (plus anything sparse tracks) into SparseMemory. */
  #syncOut() {
    for (const key of this.#dirty) {
      const base = BigInt("0x" + key);
      this.mem.write(base, this.#rawRead(this.#ucAddrFor(base), this.PAGE));
    }
    this.#dirty.clear();
  }

  // ----------------------------------------------------------- stack access

  #takePendingRip() {
    const v = this.#pendingRip;
    this.#pendingRip = null;
    return v;
  }

  popVal() {
    const v = this.mem.u64(this.regs.rsp);
    this.regs.rsp = (this.regs.rsp + 8n) & M64;
    return v;
  }
  pushVal(v) {
    this.regs.rsp = (this.regs.rsp - 8n) & M64;
    this.mem.w64(this.regs.rsp, v & M64);
  }

  // ------------------------------------------------------------------ hooks

  /** Guest HLT == backend halt (mirrors JsInterpreter.halted). */
  hookHlt(rip) {
    this.engine.hook_add(this.uc.HOOK_CODE, () => {
      this.halted = true;
      this.engine.emu_stop();
    }, 0, toI64(rip), toI64(rip));
  }

  /**
   * Range-limited code hook (CpuBackend contract). Handlers return true when
   * they rewired state themselves; emulation then resumes from the new RIP.
   *
   * Uses the wrapper-managed hook path (fire → mutate state → emu_stop →
   * outer loop restarts at the rewritten RIP). Hook callbacks observe
   * architectural guest addresses even at kernel VAs (spike-verified);
   * range endpoints still marshal through f64 in the wrapper, which is why
   * callFunction keeps its return marker at a LOW sentinel address.
   * @param {(addr: bigint) => boolean|null} fn
   * @param {bigint} [begin] inclusive
   * @param {bigint} [end] inclusive
   */
  addCodeHook(fn, begin = 1n, end = 0n) {
    const engine = this.engine;
    const wrapped = (u, address) => {
      // uc holds the live state mid-run; surface it to the JS handler, then
      // push any handler writes back so the guest observes side effects.
      this.#pullAll();
      if (fn(toU64(address)) === true) {
        this.#syncIn();
        engine.emu_stop();
      }
    };
    // default open range matches JsInterpreter.addCodeHook semantics
    const b = begin === 1n && end === 0n ? 0n : toI64(begin);
    const e = begin === 1n && end === 0n ? 0n : toI64(end);
    return engine.hook_add(this.uc.HOOK_CODE, wrapped, 0, b, e);
  }

  /** Delete a previously registered hook (wrapper handle object). */
  hook_del(handle) {
    try {
      this.engine.hook_del(handle);
    } catch {
      /* already removed */
    }
  }

  reset() {
    for (const [name] of GPR_IDS) this.regs[name] = 0n;
    this.steps = 0;
    this.fault = null;
    this.halted = false;
  }

  // -------------------------------------------------------------- exec loop

  /**
   * Shared execution pump. Runs until isDone() (a hook completed the mission),
   * an error, or the step budget.
   * @param {number} maxSteps
   * @param {() => boolean} isDone
   * @returns {"ok"|"fault"|"timeout"} and sets this.fault on fault
   */
  #pump(maxSteps, isDone) {
    while (!isDone() && this.steps < maxSteps && !this.fault) {
      const chunk = Math.min(CHUNK_INSTRUCTIONS, maxSteps - this.steps);
      const pending = this.#takePendingRip();
      const begin = pending ?? toU64(this.regs.rip);
      const rc = this.#rawStart(begin, chunk);
      if (process.env.KF_DEBUG_PUMP) console.error(`[pump] iter rip=${toU64(this.regs.rip).toString(16)} rc=${rc} steps=${this.steps}`);
      // hook-stopped runs exit early: charge nothing (count is a cap, not actual)
      const stoppedByHook = rc === 0 && isDone();
      if (!stoppedByHook) this.steps += chunk;
      if (rc === 0) continue;
      this.fault = this.#classify(rc);
      return this.fault ? "fault" : "ok";
    }
    return !isDone() && this.steps >= maxSteps ? "timeout" : "ok";
  }

  #classify(rc) {
    const names = {
      1: "UC_ERR_NOMEM", 2: "UC_ERR_ARCH", 3: "UC_ERR_HANDLE", 4: "UC_ERR_MODE",
      6: "read of unmapped memory", 7: "write to unmapped memory",
      8: "fetch from unmapped memory", 9: "hook error", 11: "bad mapping",
      21: "unhandled CPU exception",
    };
    const what = names[rc] ?? `unicorn error ${rc}`;
    return new CpuError(`${what} @ rip=0x${toU64(this.regs.rip).toString(16)}`, toU64(this.regs.rip));
  }

  /** Run until halted/budget — mirrors JsInterpreter.run() semantics. */
  run(maxSteps = 10_000_000) {
    this.#ensureDefaultStack();
    this.#syncIn();
    const outcome = this.#pump(maxSteps, () => this.halted);
    this.#syncOut();
    if (outcome === "fault") return "error";
    if (outcome === "timeout") return "timeout";
    return this.halted ? "halted" : "ok";
  }

  /** JsInterpreter lets the stack wrap below address 0; unicorn needs real pages. */
  #ensureDefaultStack() {
    const rsp = toU64(this.regs.rsp);
    if (rsp > 0x1000n && rsp < M64 - 0x1000n) return;
    const base = 0x70000n;
    this.#ensurePageMapped(base);
    this.#ensurePageMapped(base + 0x1000n);
    this.regs.rsp = 0x7ff00n;
  }

  /**
   * Call a function using the Windows x64 ABI — prologue byte-for-byte
   * equivalent to JsInterpreter.callFunction().
   */
  callFunction(funcAddr, args = [], shadowSpace = 32) {
    this.#ensureDefaultStack();

    this.regs.rsp = (this.regs.rsp & ~0xfn) - 8n;
    const regsOrder = ["rcx", "rdx", "r8", "r9"];
    args.slice(0, 4).forEach((a, i) => { this.regs[regsOrder[i]] = a & M64; });
    if (args.length > 4) {
      for (let i = args.length - 1; i >= 4; i--) this.pushVal(args[i]);
    }
    for (let i = 0; i < shadowSpace; i += 8) this.pushVal(0n);
    this.pushVal(RET_MARKER);

    // native sentinel: hook fires exactly at the marker address
    let returned = false;
    const markerHook = this.addCodeHook(() => { returned = true; return true; }, RET_MARKER, RET_MARKER);
    // the marker page must be mapped/translatable for the hook to ever fire;
    // fill happens UC-side only so SparseMemory stays free of backend internals
    const mpage = this.#ensurePageMapped(RET_MARKER & ~0xfffn);
    this.#internal.add(mpage.toString(16));
    this.#rawWrite(mpage, new Uint8Array(this.PAGE).fill(0xf4));

    this.#syncIn(); // AFTER prologue so pushed frames exist inside unicorn

    this.rip = funcAddr & M64;
    const outcome = this.#pump(10_000_000, () => returned);
    this.hook_del(markerHook);

    this.#syncOut();

    if (outcome === "fault") return { status: "fault", error: this.fault };
    if (outcome === "timeout") return { status: "timeout" };
    if (!returned) return { status: "halted", rip: this.regs.rip };
    return { status: "ok", retval: this.regs.rax };
  }
}

// GPR name -> unicorn register id, resolved once per module instance.
let GPR_IDS = new Map();
const NAMES = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];
function bindRegisterIds(uc) {
  GPR_IDS = new Map(NAMES.map((n) => [n, uc[`X86_REG_${n.toUpperCase()}`]]));
}

/**
 * Async factory — wasm init + register binding.
 * @param {object} mem SparseMemory-like instance
 * @param {object} [opts] backend options ({execAliasTruncate, arenaSize})
 */
export async function createUnicornBackend(mem, opts = {}) {
  const uc = await loadModule();
  if (GPR_IDS.size === 0) bindRegisterIds(uc);
  return new UnicornCpuBackend(mem, uc, opts);
}
