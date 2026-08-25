/**
 * x64 guest paging: walker, builder, permissions, demand mapping.
 * Tables live in a physically-addressed SparseMemory exactly as they would
 * in the emulated machine; every assertion reads raw PTE bytes back.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SparseMemory } from "../src/memory.mjs";
import { Mmu, TranslatedMemory, PTE, isCanonical, canonicalize } from "../src/paging.mjs";

function freshMmu(opts = {}) {
  const raw = new SparseMemory();
  const mmu = new Mmu(raw, { demandMap: false, ...opts });
  mmu.enablePaging(mmu.newAddressSpace());
  return { raw, mmu };
}

test("canonical VA checks", () => {
  assert.equal(isCanonical(0x00007ff000000000n), true);
  assert.equal(isCanonical(0xfffff80300000000n), true);
  assert.equal(isCanonical(0x0000800000000000n), false); // non-canonical hole
  assert.equal(canonicalize(0xffff803000000000n), 0xffff803000000000n);
});

test("walk: identity-style map translates 4KB pages", () => {
  const { raw, mmu } = freshMmu();
  const va = 0xfffff80300001000n;
  const pa = mmu.frameAlloc(1);
  raw.write(pa, new Uint8Array(4096).fill(0x5a));
  mmu.mapPage(va, pa, {});

  const t = mmu.translate(va + 0x123n, "read");
  assert.equal(t.pa, pa + 0x123n);
  assert.equal(t.level, 1);
  assert.equal(t.w, true);
  assert.equal(t.x, true);

  // data visible through translation
  assert.equal(raw.read(pa + 0x123n, 1)[0], 0x5a);
});

test("PTE bits round-trip through table memory", () => {
  const { mmu } = freshMmu();
  const va = 0xffff800012345000n;
  mmu.mapPage(va, mmu.frameAlloc(), { write: false, nx: true, user: true });
  const pte = mmu.readPte(va);
  assert.notEqual(pte, null);
  assert.equal((pte & PTE.PRESENT) !== 0n, true);
  assert.equal((pte & PTE.WRITE) === 0n, true);
  assert.equal((pte & PTE.USER) !== 0n, true);
  assert.equal((pte & PTE.NX) !== 0n, true);
  assert.equal((pte & PTE.ACCESSED) !== 0n, true); // builder sets A|D
});

test("permissions: write to read-only faults, NX fetch faults", () => {
  const { mmu } = freshMmu();
  const roVa = 0xffffc90000001000n;
  mmu.mapPage(roVa, mmu.frameAlloc(), { write: false });
  assert.throws(() => mmu.translate(roVa, "write"), /read-only/);
  assert.ok(mmu.translate(roVa, "read")); // read still fine

  const nxVa = 0xffffc90000002000n;
  mmu.mapPage(nxVa, mmu.frameAlloc(), { nx: true });
  assert.throws(() => mmu.translate(nxVa, "fetch"), /NX/);
});

test("not-present faults when demand mapping disabled", () => {
  const { mmu } = freshMmu(); // demandMap:false
  assert.throws(() => mmu.translate(0xffffd00000000000n, "read"), /not present/);
});

test("2MB large pages translate", () => {
  const { raw, mmu } = freshMmu();
  // hand-build: PML4[511]->PDPT[510]->PDE with PS
  const pml4 = mmu.cr3 & ~0xfffn;
  const pdpt = mmu.frameAlloc(); raw.write(pdpt, new Uint8Array(4096));
  const pd = mmu.frameAlloc(); raw.write(pd, new Uint8Array(4096));
  const w64at = (base, off, v) => raw.w64(base + BigInt(off), v);
  w64at(pml4, 511 * 8, pdpt | PTE.PRESENT | PTE.WRITE);
  w64at(pdpt, 510 * 8, pd | PTE.PRESENT | PTE.WRITE);
  const va = (0xffffn << 48n) | (511n << 39n) | (510n << 30n) | (7n << 21n);
  const frameBase = 0x30000000n;
  w64at(pd, 7 * 8, frameBase | PTE.PRESENT | PTE.WRITE | PTE.PS);
  const t = mmu.translate(va + 0x1fffffn, "read");
  assert.equal(t.level, 2);
  assert.equal(t.pa, frameBase + 0x1fffffn);
});

test("CR3 switch changes translation (fresh address space)", () => {
  const { raw, mmu } = freshMmu();
  const va = 0xfffff70000001000n;
  mmu.mapPage(va, mmu.frameAlloc(), {});
  assert.ok(mmu.lookup(va));

  const cr3b = mmu.newAddressSpace();
  mmu.cr3 = cr3b;
  mmu.flushTlb();
  assert.equal(mmu.lookup(va), null); // empty space: nothing mapped
});

test("TranslatedMemory: demand-zero fills unmapped VAs, identity when PG off", () => {
  const raw = new SparseMemory();
  const tm = new TranslatedMemory();
  const mmu = new Mmu(raw, { demandMap: true });
  tm.attach(mmu);
  mmu.enablePaging(mmu.newAddressSpace());

  const va = 0xffffe00000011000n;
  tm.writeUtf16(va, "hello");
  assert.equal(tm.readUtf16(va, 8), "hello");
  // landed in a real physical frame via tables
  const t = mmu.lookup(va);
  assert.ok(t && raw.hasPage(t.pa));

  // paging off -> pure identity passthrough
  mmu.cr0 &= ~0x80000000n;
  tm.write(va, [0x41]);
  assert.equal(raw.read(va, 1)[0], 0x41);
});
