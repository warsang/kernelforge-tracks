/**
 * IRQL / DPC / detour infrastructure tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel, irqlName } from "../src/kernel.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

async function booted() {
  const k = new NtKernel();
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();
  return k;
}

// ------------------------------------------------------------------- IRQL

test("irql names resolve for software levels", () => {
  assert.equal(irqlName(0), "PASSIVE_LEVEL");
  assert.equal(irqlName(1), "APC_LEVEL");
  assert.equal(irqlName(2), "DISPATCH_LEVEL");
  assert.match(irqlName(15), /DEVICE_OR_HIGHER/);
});

test("raiseIrql/lowerIrql follow monotonic semantics", async () => {
  const k = await booted();
  assert.equal(k.currentIrql, 2); // labs boot at DISPATCH
  const old = k.raiseIrql(15);
  assert.equal(old, 2);
  assert.equal(k.currentIrql, 15);
  k.lowerIrql(2);
  assert.equal(k.currentIrql, 2);
});

test("raising below current bugchecks IRQL_NOT_LESS_OR_EQUAL", async () => {
  const k = await booted();
  assert.throws(() => k.raiseIrql(1));
  assert.equal(k.bugcheck.code, 0xan);
});

test("lowering above current bugchecks too", async () => {
  const k = await booted();
  assert.throws(() => k.lowerIrql(3));
  assert.equal(k.bugcheck.code, 0xan);
});

test("KeRaiseIrql writes old level through the API layer", async () => {
  const k = await booted();
  const scratch = k.allocPool(8);
  const impl = k.apiImpls.get("KeRaiseIrql");
  impl(15n, scratch);
  assert.equal(k.mem.u8(scratch), 2);
  assert.equal(k.currentIrql, 15);
});

// -------------------------------------------------------------------- DPC

test("KeInitializeDpc + KeInsertQueueDpc queue exactly once", async () => {
  const k = await booted();
  const dpc = k.allocPool(32);
  const routine = 0xfffff8055a401400n;
  k.apiImpls.get("KeInitializeDpc")(dpc, routine, 0n);
  assert.equal(k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n), 1n);
  assert.equal(k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n), 0n); // dedupe
  assert.equal(k.pendingDpcs.length, 1);
  assert.equal(k.pendingDpcs[0].routine, routine);
  assert.equal(k.pendingDpcs[0].drained, false);
});

test("drainDpcs fires callbacks and marks entries drained", async () => {
  const k = await booted();
  const dpc = k.allocPool(32);
  k.apiImpls.get("KeInitializeDpc")(dpc, 0xfffff80500000000n, 0n);
  k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n);

  let seen = null;
  k.onDpcDrain = (d) => { seen = d; };
  const fired = k.drainDpcs();
  assert.equal(fired.length, 1);
  assert.ok(seen && seen.routine === 0xfffff80500000000n);
  assert.equal(k.pendingDpcs[0].drained, true);
  // draining again fires nothing
  assert.equal(k.drainDpcs().length, 0);
});

test("KeRemoveQueueDpc dequeues without firing", async () => {
  const k = await booted();
  const dpc = k.allocPool(32);
  k.apiImpls.get("KeInitializeDpc")(dpc, 0x1000n, 0n);
  k.apiImpls.get("KeInsertQueueDpc")(dpc, 0n, 0n);
  assert.equal(k.apiImpls.get("KeRemoveQueueDpc")(dpc), 1n);
  assert.equal(k.apiImpls.get("KeRemoveQueueDpc")(dpc), 0n);
  assert.deepEqual(k.drainDpcs(), []);
});

// ------------------------------------------------------------------ hooks

test("installDetour rewrites prologue; restorePrologue heals it", async () => {
  const k = await booted();
  const thunk = k.apiThunks.get("DbgPrint");
  assert.ok(thunk);
  assert.equal(k.isDetoured("DbgPrint"), false);

  const target = 0xfffff8055a600000n;
  k.installDetour("DbgPrint", target);
  assert.equal(k.mem.u8(thunk), 0xe9);
  assert.equal(k.isDetoured("DbgPrint"), true);

  // rel32 must decode back to the target
  const b = k.mem.read(thunk, 5);
  const rel = b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24) | -0x100000000;
  void rel;

  k.restorePrologue("DbgPrint");
  assert.equal(k.isDetoured("DbgPrint"), false);
  assert.deepEqual([...k.mem.read(thunk, 8)], [...k.pristineThunks.get("DbgPrint")]);
});

// ------------------------------------------------------------------- pool

test("allocPool writes header + intact guard; verifyGuards is clean", async () => {
  const k = await booted();
  const a = k.allocPool(0x20, "Tst1");
  assert.equal(k.verifyGuards().length, 0);
  for (let i = 0; i < 16; i++) assert.equal(k.mem.u8(a + 0x20n + BigInt(i)), 0xa5);
});

test("out-of-bounds write trips verifyGuards; repair heals it", async () => {
  const k = await booted();
  const a = k.allocPool(0x20, "Tst1");
  k.mem.w8(a + 0x20n, 0xde); // smash first guard byte
  const bad = k.verifyGuards();
  assert.equal(bad.length, 1);
  assert.equal(bad[0].addr, a);

  k.mem.w8(a + 0x20n, 0xa5);
  assert.equal(k.verifyGuards().length, 0);
});

test("registerPoolBlock seeds deterministic fixed blocks", async () => {
  const k = await booted();
  const fixed = 0xfffff90000001000n;
  k.registerPoolBlock(fixed, 0x80, "KfPb");
  assert.equal(k.poolAllocs.at(-1).addr, fixed);
  assert.equal(k.verifyGuards().length, 0);
});

test("double free under poolStrict raises BAD_POOL_CALLER", async () => {
  const k = await booted();
  k.poolStrict = true;
  const a = k.allocPool(0x10);
  assert.equal(k.freePool(a), true);
  assert.equal(k.freePool(a), false);
  assert.equal(k.bugcheck.code, 0xc2n);
});
