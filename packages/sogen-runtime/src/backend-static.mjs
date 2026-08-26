/**
 * backend-static.mjs — interim DebugSession over the JS reference world.
 *
 * The reference backend models memory/modules but executes nothing, so this
 * adapter surfaces exactly what exists honestly: disassembly (capstone),
 * memory R/W, module list, visual breakpoints. Registers/stack/threads stay
 * empty until the vendored sogen WASM core provides real CPU state
 * (backend-wasm.mjs replaces this file behind resolveBackend()).
 */

import { fmtAddr } from "@kernelforge/debugger-ui";

async function loadCapstone() {
  const mod = await import("capstone-wasm");
  await mod.loadCapstone();
  return mod;
}

export function createStaticDebugSession(world) {
  const breakpoints = new Map(); // padded-hex -> info

  return {
    // introspection is always legal against the static world
    paused: true,
    pauseCount: 1,
    canExecute: false, // static backend cannot execute - needs WASM core
    onStateChange() { return () => {}; },

    async getRegisters() { return []; },

    async disassemble(address, count) {
      const start = BigInt("0x" + String(address).replace(/^0x/i, "").replace(/[`_]/g, ""));
      if (!world.mem.canRead(start, 1)) return [];
      try {
        const cs = await loadCapstone();
        const engine = new cs.Capstone(cs.Const.CS_ARCH_X86, cs.Const.CS_MODE_64);
        try {
          const bytes = world.mem.read(start, Math.min(count * 16, 4096));
          const out = [];
          let off = 0;
          for (const insn of engine.disasm(bytes, { address: Number(start) })) {
            const size = insn.bytes?.length ?? insn.size ?? 1;
            out.push({
              address: (start + BigInt(off)).toString(16).padStart(12, "0"),
              size,
              mnemonic: String(insn.mnemonic ?? ""),
              operands: String(insn.opStr ?? insn.op_str ?? ""),
              bytes: [...(insn.bytes ?? [])],
            });
            off += size;
            if (out.length >= count) break;
          }
          return out;
        } finally {
          try { engine.close(); } catch { /* optional */ }
        }
      } catch {
        return [];
      }
    },

    async readMemory(address, size) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      const out = new Uint8Array(size);
      for (let i = 0; i < size; i++) {
        const a = addr + BigInt(i);
        out[i] = world.mem.canRead(a, 1) ? world.mem.u8(a) : 0;
      }
      return out;
    },

    async writeMemory(address, bytes) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      world.mem.write(addr, [...bytes]);
    },

    async getModules() {
      return (world.modules ?? []).map((m) => ({
        name: m.name,
        base: m.base.toString(16).padStart(12, "0"),
        size: Number(m.size ?? 0),
        entry: m.base.toString(16).padStart(12, "0"),
      }));
    },

    async getThreads() { return []; },
    async getCallStack() { return []; },
    async getMemoryRegions() {
      return (world.modules ?? []).map((m) => ({
        base: m.base.toString(16).padStart(12, "0"),
        size: Number(m.size ?? 0),
        label: m.name,
      }));
    },

    // Visual-only breakpoints until real execution arrives (kept so the UI
    // flow is identical across backends).
    async setBreakpoint(address) {
      const key = fmtAddr(BigInt("0x" + String(address).replace(/^0x/i, "")));
      if (!breakpoints.has(key)) {
        breakpoints.set(key, { address: key, type: 0, enabled: true });
      }
      return [...breakpoints.values()];
    },
    async clearBreakpoint(address) {
      breakpoints.delete(fmtAddr(BigInt("0x" + String(address).replace(/^0x/i, ""))));
      return [...breakpoints.values()];
    },
    async listBreakpoints() { return [...breakpoints.values()]; },

    async stepInto() { throw new Error("Execution requires the sogen WASM core — upload a target binary to enable stepping"); },
    stepOver() { return this.stepInto(); },
    stepOut() { return this.stepInto(); },
    runTo() { return this.stepInto(); },
    resume() { return this.stepInto(); },
    pause() {},
  };
}
