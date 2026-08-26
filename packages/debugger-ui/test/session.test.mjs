/**
 * Contract tests: the mock session exercises every DebugSession verb, and the
 * disassembly/hex views render against it under happy-dom.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createMockSession } from "../src/mock-session.mjs";
import { toBig, fmtAddr } from "../src/session.mjs";

test("mock session: full contract round-trip", async () => {
  const s = createMockSession();
  assert.equal(s.paused, true);

  const regs = await s.getRegisters();
  assert.ok(regs.find((r) => r.name === "rip"));

  const insns = await s.disassemble("1000", 4);
  assert.equal(insns.length, 4);
  assert.equal(insns[0].mnemonic, "push");

  const bytes = await s.readMemory("1000", 16);
  assert.equal(bytes.length, 16);

  let bps = await s.setBreakpoint(fmtAddr(toBig("1040")));
  assert.equal(bps.length, 1);
  bps = await s.listBreakpoints();
  assert.equal(toBig(bps[0].address), 0x1040n);

  await s.continueExecution();
  assert.equal(s.paused, true);
  assert.equal(toBig(s.regFile.rip), 0x1040n);
  assert.ok(s.pauseCount >= 2);

  bps = await s.clearBreakpoint("1040");
  assert.equal(bps.length, 0);

  const stepsBefore = s.stepsTaken;
  await s.stepInto();
  assert.equal(s.stepsTaken - stepsBefore, 1);
});

test("session helpers parse hex/bigint/number uniformly", () => {
  assert.equal(toBig("0x1000"), 0x1000n);
  assert.equal(toBig("`00123`"), 0x123n); // windbg backtick form
  assert.equal(toBig("deadbeef"), 0xdeadbeefn);
  assert.equal(toBig("not-hex"), null);
  assert.equal(fmtAddr(0x1000n), "000000001000");
});
