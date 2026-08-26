/**
 * CFG pure core: block partitioning + BFS layout. No DOM involved.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBlocks, layoutBlocks } from "../src/views/cfg.js";

const insn = (addr, size, mnemonic, operands = "", branch) => ({
  address: addr.toString(16).padStart(12, "0"),
  size,
  mnemonic,
  operands,
  ...(branch !== undefined ? { branch: branch.toString(16).padStart(12, "0") } : {}),
});

test("buildBlocks: branches and rets split blocks with successors", () => {
  // 1000: test eax,eax      ; leader
  // 1002: jz 1010           -> cond: target 1010 leader, fallthrough 1004 leader
  // 1004: mov eax,1
  // 1007: jmp 1015          -> uncond target leader; after-jmp 1009 leader
  // 1009: xor eax,eax
  // 100b: ret               -> terminator
  // 1010: mov eax,2
  // 1013: ??? falls to 1015 (leader already)
  // 1015: ret                -> terminator
  const insns = [
    insn(0x1000n, 2, "test", "eax, eax"),
    insn(0x1002n, 2, "jz", "0x1010", 0x1010n),
    insn(0x1004n, 3, "mov", "eax, 1"),
    insn(0x1007n, 2, "jmp", "0x1015", 0x1015n),
    insn(0x1009n, 2, "xor", "eax, eax"),
    insn(0x100bn, 1, "ret"),
    insn(0x1010n, 3, "mov", "eax, 2"),
    insn(0x1013n, 2, "nop"),
    insn(0x1015n, 1, "ret"),
  ];
  const blocks = buildBlocks(insns);
  const starts = [...blocks.keys()].sort((a, b) => (a < b ? -1 : 1));
  assert.deepEqual(starts.map((s) => Number(s)),
    [0x1000, 0x1004, 0x1009, 0x1010, 0x1015]);

  assert.deepEqual(blocks.get(0x1000n).succs.map(Number), [0x1010, 0x1004]);
  assert.deepEqual(blocks.get(0x1004n).succs.map(Number), [0x1015]); // uncond
  assert.deepEqual(blocks.get(0x1009n).succs.map(Number), []);       // ret
  assert.deepEqual(blocks.get(0x1010n).succs.map(Number), [0x1015]); // fallthrough
  assert.deepEqual(blocks.get(0x1015n).succs.map(Number), []);
});

test("layoutBlocks BFS layers from entry", () => {
  const insns = [
    insn(0x2000n, 2, "jz", "0x2010", 0x2010n),
    insn(0x2002n, 1, "ret"),                    // fallthrough block
    insn(0x2010n, 1, "ret"),
  ];
  const blocks = buildBlocks(insns);
  const { nodes } = layoutBlocks(blocks, 0x2000n);
  const depthOf = Object.fromEntries(
    nodes.map((n) => [Number(n.start), Math.round(n.y / 250)]));
  assert.equal(depthOf[0x2000], 0, "entry at layer 0");
  assert.equal(depthOf[0x2002], 1);
  assert.equal(depthOf[0x2010], 1);
});
