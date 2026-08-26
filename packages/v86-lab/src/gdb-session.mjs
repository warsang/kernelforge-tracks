/**
 * gdb-session.mjs — DebugSession adapter over the RSP client.
 *
 * Implements the @kernelforge/debugger-ui contract for a live v86 guest
 * process under gdbserver: real software breakpoints, single-stepping,
 * register/memory introspection — all over the emulated serial line.
 *
 * Architecture is i386 (v86): registers come from the 'g' packet in x86
 * order (eax..edi, eip, eflags, cs, ss, ds, es, fs, gs), 4 bytes each,
 * little-endian hex. Disassembly is client-side capstone in 32-bit mode.
 */

import { RspClient } from "./rsp.mjs";

const X86_REGS = [
  "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
  "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
];

async function loadCapstone32() {
  const mod = await import("capstone-wasm");
  await mod.loadCapstone();
  return mod;
}

/** Parse the g-packet blob into {name: hexValue}. */
export function parseGPacket(blob) {
  const regs = {};
  for (let i = 0; i < X86_REGS.length; i++) {
    const off = i * 8;
    if (off + 8 > blob.length) break;
    const raw = blob.slice(off, off + 8); // little-endian dword
    const le = "";
    void le;
    let value = 0n;
    for (let b = 3; b >= 0; b--) {
      value = (value << 8n) | BigInt(parseInt(raw.slice(b * 2, b * 2 + 2), 16) || 0);
    }
    regs[X86_REGS[i]] = value;
  }
  return regs;
}

export class GdbSession {
  /** @type {RspClient} */
  rsp;
  /** @type {Map<string, {enabled:boolean}>} bp addrHex -> rec */
  breakpoints = new Map();
  paused = true;
  pauseCount = 1;
  lastStop = null;
  exited = false;

  #listeners = new Set();

  constructor(rsp) {
    this.rsp = rsp;
  }

  /**
   * Attach to a guest-side gdbserver listening on ttyS1.
   * @param {object} transport { send(bytes), onReceive(cb) }
   */
  static async attach(transport) {
    const rsp = new RspClient(transport);
    const session = new GdbSession(rsp);
    await rsp.connect();
    return session;
  }

  #stop() {
    this.paused = true;
    this.pauseCount++;
    for (const cb of this.#listeners) {
      try { cb(); } catch { /* listener bug */ }
    }
  }

  onStateChange(cb) {
    this.#listeners.add(cb);
    return () => this.#listeners.delete(cb);
  }

  // ---- introspection -------------------------------------------------------

  async getRegisters() {
    if (!this.paused) return [];
    const blob = await this.rsp.readRegisters().catch(() => "");
    const regs = parseGPacket(blob);
    return Object.entries(regs).map(([name, value]) => ({
      name,
      value: value.toString(16).padStart(8, "0"),
      size: name === "eip" || name === "esp" ? 4 : 4,
    }));
  }

  async disassemble(address, count) {
    const start = BigInt("0x" + String(address).replace(/^0x/i, ""));
    const out = [];
    try {
      const cs = await loadCapstone32();
      const engine = new cs.Capstone(cs.Const.CS_ARCH_X86, cs.Const.CS_MODE_32);
      try {
        let va = start;
        while (out.length < count) {
          let bytes;
          try {
            bytes = await this.rsp.readMemory(va.toString(16), Math.min(64, (count - out.length) * 8));
          } catch {
            break; // unmapped
          }
          if (!bytes.length) break;
          const insns = engine.disasm(bytes, { address: Number(va & 0xffffffffn) });
          if (!insns?.length) break;
          for (const insn of insns) {
            if (out.length >= count) break;
            const size = insn.bytes?.length ?? 1;
            const branch = /^j|^call/i.test(insn.mnemonic)
              ? extractBranch(insn.opStr, va)
              : null;
            out.push({
              address: va.toString(16).padStart(8, "0"),
              size,
              mnemonic: String(insn.mnemonic ?? ""),
              operands: String(insn.opStr ?? insn.op_str ?? ""),
              bytes: [...(insn.bytes ?? [])],
              branch,
            });
            va += BigInt(size);
          }
          if (!insns.length) break;
        }
      } finally {
        try { engine.close(); } catch { /* optional */ }
      }
    } catch { /* capstone unavailable */ }
    return out;
  }

  async readMemory(addrHex, size) {
    return this.rsp.readMemory(normalizeAddr(addrHex), size);
  }

  async writeMemory(addrHex, bytes) {
    await this.rsp.writeMemory(normalizeAddr(addrHex), bytes);
  }

  async getMemoryRegions() { return []; }

  async getModules() { return []; }

  async getThreads() {
    const stop = this.lastStop;
    const tid = stop?.thread ?? "1";
    return [{ id: Number.parseInt(tid, 16) || 1, ip: this.#cachedEip(), active: true }];
  }

  async getCallStack() {
    const frames = [{ ip: this.#cachedEip(), sp: this.#cachedEsp() }];
    // naive ebp chain walk (frame pointers only — no unwind data over RSP)
    try {
      let ebp = BigInt("0x" + (await this.#regHex("ebp")));
      for (let i = 0; i < 7; i++) {
        if (ebp === 0n || ebp <= 4n) break;
        const savedEipBytes = await this.rsp.readMemory((ebp + 4n).toString(16), 4).catch(() => null);
        const savedEbpBytes = await this.rsp.readMemory(ebp.toString(16), 4).catch(() => null);
        if (!savedEipBytes || !savedEbpBytes) break;
        const eip = [...savedEipBytes].reduce((a, b, j) => a | (b << (8 * j)), 0);
        if (!eip) break;
        frames.push({ ip: eip.toString(16).padStart(8, "0"), sp: ebp.toString(16) });
        ebp = [...savedEbpBytes].reduce((a, b, j) => a | (b << (8 * j)), 0);
      }
    } catch { /* chain unreadable */ }
    return frames;
  }

  async #regHex(name) {
    const regs = await this.getRegisters();
    return regs.find((r) => r.name === name)?.value ?? "0";
  }

  #cachedEip() {
    return this.lastStop?.regs?.eip ?? "00000000";
  }

  #cachedEsp() {
    return this.lastStop?.regs?.esp ?? "00000000";
  }

  // ---- breakpoints ---------------------------------------------------------

  async setBreakpoint(address) {
    const hex = normalizeAddr(address);
    if (!this.breakpoints.has(hex)) {
      this.breakpoints.set(hex, { enabled: true });
      await this.rsp.insertBreakpoint(hex);
    }
    return [...this.breakpoints.entries()].map(([a, r]) => ({ address: a, type: 0, enabled: r.enabled }));
  }

  async clearBreakpoint(address) {
    const hex = normalizeAddr(address);
    if (this.breakpoints.has(hex)) {
      this.breakpoints.delete(hex);
      await this.rsp.removeBreakpoint(hex).catch(() => {});
    }
    return [...this.breakpoints.entries()].map(([a, r]) => ({ address: a, type: 0, enabled: r.enabled }));
  }

  async listBreakpoints() {
    return [...this.breakpoints.entries()].map(([a, r]) => ({ address: a, type: 0, enabled: r.enabled }));
  }

  // ---- control -------------------------------------------------------------

  /** Step one instruction. Resolves after the stop reply arrives. */
  async stepInto() {
    if (!this.paused) throw new Error("target running");
    this.paused = false;
    const pkt = await this.rsp.step();
    this.#absorbStop(pkt);
    this.#stop();
    return pkt;
  }

  /** Step over calls: temp Z0 at next insn, continue, remove. */
  async stepOver() {
    if (!this.paused) throw new Error("target running");
    const eip = normalizeAddr(this.#cachedEip());
    let next = null;
    let isCall = false;
    const [insn] = await this.disassemble(eip, 1);
    if (insn) {
      next = (BigInt("0x" + insn.address) + BigInt(insn.size)).toString(16);
      isCall = /^call/i.test(insn.mnemonic);
    }
    if (!next || !isCall) return this.stepInto();
    await this.rsp.insertBreakpoint(next);
    try {
      await this.continueRunInternal();
    } finally {
      await this.rsp.removeBreakpoint(next).catch(() => {});
    }
  }

  /** Continue until current frame returns: temp Z0 at [esp], continue. */
  async stepOut() {
    if (!this.paused) throw new Error("target running");
    const esp = this.#cachedEsp();
    const retBytes = await this.rsp.readMemory(esp, 4).catch(() => null);
    if (!retBytes) throw new Error("unreadable stack");
    const ret = [...retBytes].reduce((a, b, j) => a | (b << (8 * j)), 0);
    const hex = ret.toString(16);
    await this.rsp.insertBreakpoint(hex);
    try {
      await this.continueRunInternal();
    } finally {
      await this.rsp.removeBreakpoint(hex).catch(() => {});
    }
  }

  async runTo(address) {
    const hex = normalizeAddr(address);
    await this.rsp.insertBreakpoint(hex);
    try {
      await this.continueRunInternal();
    } finally {
      await this.rsp.removeBreakpoint(hex).catch(() => {});
    }
  }

  /** Internal continue that resolves when the target stops again. */
  async continueRunInternal() {
    this.paused = false;
    const pkt = await this.rsp.continueRun();
    this.#absorbStop(pkt);
    this.#stop();
    return pkt;
  }

  async pause() {
    this.rsp.interrupt();
    try {
      const pkt = await this.rsp.awaitStop(10_000);
      this.#absorbStop(pkt);
      this.#stop();
    } catch { /* target may have exited */ }
  }

  resume() { return this.continueRunInternal(); }
  async continueExecution() { return this.resume(); }

  #absorbStop(pkt) {
    const parsed = this.rsp.parseStop(pkt);
    this.lastStop = parsed;
    if (parsed.exited) this.exited = true;
    else this.paused = true;
  }

  async detach() {
    await this.rsp.detach();
  }
}

function normalizeAddr(v) {
  return BigInt("0x" + String(v).replace(/^0x/i, "").replace(/[`_]/g, ""))
    .toString(16);
}

function extractBranch(opStr, _va) {
  const m = /0x([0-9a-f]+)/i.exec(opStr);
  return m ? m[1] : null;
}
