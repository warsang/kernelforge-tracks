import { test } from "node:test";
import assert from "node:assert/strict";

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import {
  findFunctions, resolveRel32, writeFunctionGrid, analyzeExtent,
  decompile, DecompilerUnavailableError,
} from "../src/index.mjs";

const BASE = 0xfffff8055a601000n;

function gridWorld(len = 0x800) {
  const mem = new SparseMemory();
  writeFunctionGrid(mem, BASE, len);
  return mem;
}

test("writeFunctionGrid + findFunctions recover exactly len/16 functions", () => {
  const mem = gridWorld(0x800);
  const funcs = findFunctions(mem, BASE, 0x800);
  assert.equal(funcs.length, 128); // every 16-byte block starts with a prologue
  assert.equal(funcs[0].start, BASE);
  assert.equal(funcs[1].start, BASE + 0x10n);
});

test("boundary scan ignores zero pages and data blobs", () => {
  const mem = new SparseMemory();
  // nothing materialized -> no functions
  assert.equal(findFunctions(mem, BASE, 0x400).length, 0);
  // ascii blob is not a prologue
  mem.write(BASE, new TextEncoder().encode("kfhook: not code at all"));
  assert.equal(findFunctions(mem, BASE, 0x40).length, 0);
});

test("resolveRel32 sign-extends negative displacements", () => {
  const mem = new SparseMemory();
  const site = BASE + 0x100n;
  const target = BASE + 0x40n;                       // backwards jump
  const rel = Number(target - (site + 5n)) | 0;      // negative rel32
  mem.write(site, [0xe9,
    rel & 0xff, (rel >>> 8) & 0xff, (rel >>> 16) & 0xff, (rel >>> 24) & 0xff]);
  assert.equal(resolveRel32(mem, site), target);

  // forward
  const site2 = BASE + 0x200n;
  const target2 = site2 + 0x300n;
  const rel2 = Number(target2 - (site2 + 5n));
  mem.write(site2, [0xe9,
    rel2 & 0xff, (rel2 >>> 8) & 0xff, (rel2 >>> 16) & 0xff, (rel2 >>> 24) & 0xff]);
  assert.equal(resolveRel32(mem, site2), target2);

  // not a rel32
  mem.write(BASE, [0x48, 0x89, 0x5c, 0x24, 0x08]);
  assert.equal(resolveRel32(mem, BASE), null);
});

test("analyzeExtent reports boundaries plus rel32 sites", () => {
  const mem = gridWorld(0x100);
  // overwrite block #3's first byte with an E9 into block #7
  const site = BASE + 0x30n;
  const target = BASE + 0x70n;
  const rel = Number(target - (site + 5n)) | 0;
  mem.write(site, [0xe9, rel & 0xff, (rel >>> 8) & 0xff, (rel >>> 16) & 0xff, (rel >>> 24) & 0xff]);

  const res = analyzeExtent(mem, BASE, 0x100);
  // 16 grid blocks; #3 lost its prologue to the E9 patch -> 15 recoverable
  assert.equal(res.count, 15);
  assert.deepEqual(res.rel32.map((r) => r.site), [site]);
  assert.deepEqual(res.rel32.map((r) => r.target), [target]);
});

test("decompile degrades loudly without the vendored wasm", async () => {
  await assert.rejects(
    () => decompile(new Uint8Array(64), BASE, BASE),
    DecompilerUnavailableError,
  );
});
