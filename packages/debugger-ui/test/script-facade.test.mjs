/**
 * Script console: emu facade maps DebugSession verbs correctly and the
 * cooperative-cancel guard fires between calls.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createEmuFacade } from "../src/views/script.js";

function fakeSession() {
  return {
    paused: true,
    pauseCount: 3,
    async getRegisters() {
      return [{ name: "rip", value: "401000", size: 8 },
        { name: "rax", value: "2a", size: 8 }];
    },
    async disassemble(address, count) {
      assert.equal(address, "401000");
      assert.equal(count, 4);
      return [
        { address: "000000401000", size: 5, mnemonic: "mov", operands: "eax, 0x2a" },
        { address: "000000401005", size: 1, mnemonic: "ret", operands: "" },
      ];
    },
    async getModules() { return [{ name: "game.exe", base: "00400000", size: 4096, entry: "00400000" }]; },
    async getThreads() { return []; },
    async getCallStack() { return []; },
    async listBreakpoints() { return [{ address: "00401005", type: 0, enabled: true }]; },
    async setBreakpoint(address) { return [{ address, type: 0, enabled: true }]; },
    async clearBreakpoint() { return []; },
    async readMemory(address, size) {
      assert.equal(address, "401000");
      const out = new Uint8Array(Number(size));
      out[0] = 0xb8; out[1] = 0x2a;
      return out;
    },
    stepInto() { throw new Error("cannot step"); },
  };
}

test("emu facade: registers/disassemble/modules/memory round-trip", async () => {
  const lines = [];
  const emu = createEmuFacade(fakeSession(), (t) => lines.push(t), null);

  const regs = await emu.debug.registers();
  assert.equal(regs.rip, 0x401000n);
  assert.equal(regs.rax, 0x2an);

  const insns = await emu.debug.disassemble(0x401000n, 4);
  assert.equal(insns[1].mnemonic, "ret");

  const mods = await emu.debug.modules();
  assert.equal(mods[0].name, "game.exe");

  const bytes = await emu.memory.read(0x401000n, 2);
  assert.deepEqual([...bytes], [0xb8, 0x2a]);

  assert.equal(emu.state.paused, true);
  assert.equal(emu.state.pauseCount, 3);
});

test("emu facade: cancelled handle stops before each call", async () => {
  const handle = { cancelled: true };
  const emu = createEmuFacade(fakeSession(), () => {}, handle);
  await assert.rejects(() => emu.debug.modules(), /script cancelled/);
});

test("emu facade: refuses introspection while running", async () => {
  const s = fakeSession();
  s.paused = false;
  const emu = createEmuFacade(s, () => {}, null);
  await assert.rejects(() => emu.debug.registers(), /running — pause/);
});
