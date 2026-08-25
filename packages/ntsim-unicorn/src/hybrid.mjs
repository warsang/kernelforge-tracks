/**
 * HybridCpuBackend — JsInterpreter front end with automatic Unicorn rescue.
 *
 * Contract: identical to CpuBackend (see packages/ntsim/src/cpu.mjs). The
 * deterministic interpreter executes everything it knows; when it hits an
 * instruction it refuses (unknown opcode / bad grp forms), execution hands
 * off ONE-WAY to the Unicorn wasm engine at the exact faulting RIP with a
 * full GPR transfer. Everything after the switch runs with full x86-64 ISA
 * coverage.
 *
 * Why one-way: copying QEMU state back into the interpreter is lossy (flags,
 * partial-register latches). Forward-only handoff keeps semantics honest.
 *
 * Kernel hooks (API thunks) are registered on BOTH engines up-front so the
 * switch is invisible above the CpuBackend boundary.
 */

import { JsInterpreter, CpuError } from "@kernelforge/ntsim/src/cpu.mjs";
import { createUnicornBackend } from "./backend.mjs";

const R64 = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

const UNSUPPORTED_RE =
  /unimplemented opcode|unimplemented 0f opcode|invalid alu form|unimplemented grp/;

export class HybridCpuBackend {
  /** @type {"js"|"unicorn"} */
  active = "js";

  constructor(mem, js, uc) {
    this.mem = mem;
    this.js = js;
    this.uc = uc;
    /** @type {Array<{rip:string, opcode:string}>} */
    this.handoffs = [];
  }

  static async create(mem) {
    return new HybridCpuBackend(mem, new JsInterpreter(mem), await createUnicornBackend(mem));
  }

  // ------------------------------------------------------------- identity

  get activeEngine() {
    return this.active === "js" ? this.js : this.uc;
  }

  /** Live proxy: reads/writes always hit the ACTIVE engine's register file. */
  get regs() {
    const self = this;
    return new Proxy({}, {
      get(_t, prop) {
        if (prop === "rip") return self.activeEngine.rip;
        return self.activeEngine.regs[prop];
      },
      set(_t, prop, v) {
        if (prop === "rip") { self.activeEngine.rip = v; return true; }
        self.activeEngine.regs[prop] = v;
        return true;
      },
      has(_t, prop) { return prop === "rip" || prop in self.activeEngine.regs; },
    });
  }

  get rip() { return this.activeEngine.rip; }
  set rip(v) { this.activeEngine.rip = v; }
  get steps() { return this.js.steps + this.uc.steps; }
  get fault() { return this.activeEngine.fault; }
  get halted() { return this.activeEngine.halted; }
  set halted(v) { this.activeEngine.halted = v; }

  // ----------------------------------------------------------- handoff

  #isUnsupported(error) {
    return error instanceof CpuError && UNSUPPORTED_RE.test(String(error?.message ?? ""));
  }

  #copyJsToUc() {
    // Rewind to the START of the faulting instruction: the interpreter may
    // have consumed prefixes/opcodes before refusing it.
    const startRip = this.js.opcodeStart ?? this.js.rip;
    for (const name of R64) this.uc.regs[name] = this.js.regs[name];
    this.js.rip = startRip;
    this.uc.rip = startRip;
    this.uc.halted = false;
    this.uc.fault = null;
  }

  #maybeHandoff(error) {
    if (this.active !== "js" || !this.#isUnsupported(error)) return false;
    this.#copyJsToUc();
    this.handoffs.push({
      rip: "0x" + this.js.rip.toString(16),
      opcode: String(error.message),
    });
    this.active = "uc";
    return true;
  }

  // -------------------------------------------------------------- hooks

  addCodeHook(fn, begin, end) {
    // register on BOTH engines so thunk interception survives a handoff
    this.js.addCodeHook(fn, begin, end);
    this.uc.addCodeHook(fn, begin ?? 1n, end ?? 0n);
  }

  hook_del(handle) {
    void handle;
    throw new Error("HybridCpuBackend: selective hook_del unsupported");
  }

  /** HLT parity for the unicorn side (JsInterpreter halts natively). */
  hookHlt(rip) {
    this.uc.hookHlt(rip);
  }

  // ---------------------------------------------------------- stack ops

  pushVal(v) { this.activeEngine.pushVal?.(v); }
  popVal() {
    const eng = this.activeEngine;
    if (typeof eng.popVal === "function") return eng.popVal();
    // JsInterpreter has no public popVal; emulate over shared memory
    const v = this.mem.u64(eng.regs.rsp);
    eng.regs.rsp = (eng.regs.rsp + 8n) & 0xffffffffffffffffn;
    return v;
  }

  // ------------------------------------------------------------ control

  reset(rip) {
    this.js.reset(rip);
    this.uc.reset(rip);
    this.active = "js";
  }

  run(maxSteps = 10_000_000) {
    for (;;) {
      const budgetLeft = maxSteps - this.steps;
      const reason = this.activeEngine.run(budgetLeft > 0 ? budgetLeft : 0);
      if (reason === "error" && this.#maybeHandoff(this.activeEngine.fault)) continue;
      return reason;
    }
  }

  callFunction(funcAddr, args = [], shadowSpace = 32) {
    let r = this.activeEngine.callFunction(funcAddr, args, shadowSpace);
    if (r.status === "fault" && this.#maybeHandoff(r.error)) {
      // retry once on unicorn from the transferred state
      r = this.uc.callFunction(funcAddr, args, shadowSpace);
    }
    return r;
  }
}

export { createUnicornBackend };
export default HybridCpuBackend;
