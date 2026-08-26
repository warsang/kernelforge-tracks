/**
 * MockSession — deterministic in-memory DebugSession for tests and demos.
 *
 * Implements the full contract from session.mjs over a toy x86-64-ish
 * program: a fixed instruction stream, one thread, canned modules, and a
 * byte-map memory with two mapped regions (code @ 0x1000, stack @ 0x7f00).
 * No disassembler dependency: the instruction list is hand-written.
 */

import { fmtAddr } from "./session.mjs";

const PROGRAM = [
  { mnemonic: "push", operands: "rbp", size: 1 },
  { mnemonic: "mov", operands: "rbp, rsp", size: 3 },
  { mnemonic: "sub", operands: "rsp, 0x20", size: 4 },
  { mnemonic: "mov", operands: "dword [rsp], 0x2a", size: 7 },
  { mnemonic: "call", operands: "helper", size: 5, branch: "1040" },
  { mnemonic: "add", operands: "rsp, 0x20", size: 4 },
  { mnemonic: "pop", operands: "rbp", size: 1 },
  { mnemonic: "ret", operands: "", size: 1 },
];

const HELPER = [
  { mnemonic: "xor", operands: "eax, eax", size: 2 },
  { mnemonic: "inc", operands: "eax", size: 1 },
  { mnemonic: "ret", operands: "", size: 1 },
];

function buildStream() {
  const insns = [];
  let addr = 0x1000n;
  for (const p of PROGRAM) {
    insns.push({ ...p, address: fmtAddr(addr), bytes: new Array(p.size).fill(0x90) });
    addr += BigInt(p.size);
  }
  let hAddr = 0x1040n; // branch target above
  for (const p of HELPER) {
    insns.push({ ...p, address: fmtAddr(hAddr) });
    hAddr += BigInt(p.size);
  }
  return insns;
}

export class MockSession {
  constructor() {
    this.insns = buildStream();
    this.regFile = {
      rip: this.insns[0].address,
      rax: "0000000000000000",
      rbx: "0000000000000001",
      rcx: "0000000000000002",
      rdx: "0000000000000003",
      rsp: "00007fff0000",
      rbp: "00007fff0100",
    };
    this.memBytes = new Map(); // Number(addr) -> byte
    for (let i = 0; i < 0x100; i++) this.memBytes.set(0x1000 + i, i % 256);
    for (let i = 0; i < 0x100; i++) this.memBytes.set(0x7f00 + i, 0xcc);

    this.breakpoints = new Map(); // hex -> BreakpointInfo
    this.paused = true;
    this.pauseCount = 1;
    /** @type {Set<() => void>} */
    this.listeners = new Set();
    this.stepsTaken = 0;
  }

  // ---- lifecycle -----------------------------------------------------------

  #stop(reason = "pause") {
    this.lastStopReason = reason;
    if (!this.paused) {
      this.paused = true;
      this.pauseCount++;
    }
    for (const l of this.listeners) l();
  }

  onStateChange(cb) {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  // ---- introspection -------------------------------------------------------

  async getRegisters() {
    return Object.entries(this.regFile).map(([name, value]) => ({
      name,
      value,
      size: name === "rip" || name === "rsp" ? 8 : 8,
    }));
  }

  async disassemble(address, count) {
    const start = BigInt("0x" + String(address).replace(/^0x/i, ""));
    const idx = this.insns.findIndex((i) => BigInt("0x" + i.address) === start);
    const out = [];
    if (idx >= 0) {
      for (let i = idx; i < this.insns.length && out.length < count; i++) {
        out.push(this.insns[i]);
      }
      return out;
    }
    // unmapped/mid-insn: synthesize bad bytes so the view still renders
    for (let i = 0; i < count; i++) {
      out.push({
        address: fmtAddr(start + BigInt(i)),
        size: 1,
        mnemonic: "db",
        operands: "0xcc",
      });
    }
    return out;
  }

  async readMemory(address, size) {
    const base = BigInt("0x" + String(address).replace(/^0x/i, ""));
    const out = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      out[i] = this.memBytes.get(Number((base + BigInt(i)) & 0xffffffffffffn)) ?? 0;
    }
    return out;
  }

  async writeMemory(address, bytes) {
    const base = BigInt("0x" + String(address).replace(/^0x/i, ""));
    for (let i = 0; i < bytes.length; i++) {
      this.memBytes.set(Number(base + BigInt(i)), bytes[i]);
    }
  }

  async getModules() {
    return [
      { name: "mock.exe", base: "1000", size: 0x2000, entry: "1000" },
    ];
  }

  async getThreads() {
    return [{ id: 1, ip: this.regFile.rip, active: true }];
  }

  async getCallStack() {
    return [
      { ip: this.regFile.rip, sp: this.regFile.rsp, module: "mock.exe" },
      { ip: "1078", sp: "00007fff0200", module: "mock.exe" },
    ];
  }

  // ---- breakpoints ---------------------------------------------------------

  async setBreakpoint(address) {
    const hex = fmtAddr(BigInt("0x" + String(address).replace(/^0x/i, "")));
    if (!this.breakpoints.has(hex)) {
      this.breakpoints.set(hex, { address: hex, type: 0, enabled: true, hitCount: 0 });
    }
    return [...this.breakpoints.values()];
  }

  async clearBreakpoint(address) {
    this.breakpoints.delete(fmtAddr(BigInt("0x" + String(address).replace(/^0x/i, ""))));
    return [...this.breakpoints.values()];
  }

  async listBreakpoints() {
    return [...this.breakpoints.values()];
  }

  // ---- control -------------------------------------------------------------

  #idxAtRip() {
    return this.insns.findIndex((i) => i.address === this.regFile.rip);
  }

  async stepInto() {
    if (!this.paused) throw new Error("not paused");
    const i = this.#idxAtRip();
    if (i >= 0 && i + 1 < this.insns.length) {
      this.regFile.rip = this.insns[i + 1].address;
    }
    this.stepsTaken++;
    this.#stop("step");
  }

  async stepOver() {
    await this.stepInto();
  }

  async stepOut() {
    await this.stepInto();
  }

  async runTo(_address) {
    await this.continueExecution();
  }

  async continueExecution() {
    this.paused = false;
    // run until a registered breakpoint (or program end)
    let i = this.#idxAtRip();
    while (this.paused === false) {
      if (i >= 0 && i + 1 < this.insns.length) {
        i++;
        this.regFile.rip = this.insns[i].address;
        this.stepsTaken++;
        const bp = this.breakpoints.get(this.regFile.rip.replace(/^0x/i, ""));
        if (bp) {
          bp.hitCount++;
          this.#stop("breakpoint");
          break;
        }
      } else {
        this.#stop("exited");
        break;
      }
    }
  }

  pause() {
    this.#stop("interrupt");
  }

  resume() {
    return this.continueExecution();
  }
}

export function createMockSession() {
  return new MockSession();
}
