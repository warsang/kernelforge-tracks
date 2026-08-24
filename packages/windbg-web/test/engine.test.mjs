import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "@kernelforge/ntsim";
import { KdEngine, dbgAddr } from "../src/engine.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../ntsim-assets/data/vergilius/windows-10/22h2"
);

async function booted() {
  const k = new NtKernel();
  await k.loadTablesFromDir(tablesDir);
  k.bootstrap();
  return new KdEngine(k);
}

test("dbgAddr formats with windbg backtick", () => {
  assert.equal(dbgAddr(0xfffff8052b9d1000n), "fffff805`2b9d1000");
});

test("!process 0 0 lists all processes", async (t) => {
  const kd = await booted();
  const out = kd.execute("!process 0 0");
  assert.match(out, /lsass\.exe/);
  assert.match(out, /kftarget\.exe/);
  assert.match(out, /ffffb800`/); // synthetic eproc region
});

test("dt nt!_EPROCESS shows real 22h2 layout", async () => {
  const kd = await booted();
  const out = kd.execute("dt nt!_EPROCESS");
  assert.match(out, /\+0x440\s+UniqueProcessId/);
  assert.match(out, /\+0x448\s+ActiveProcessLinks/);
  assert.match(out, /\+0x87a\s+Protection/);
});

test("dt nt!_EPROCESS <addr> renders live instance", async () => {
  const kd = await booted();
  const lsass = kd.k.processesByName.get("lsass.exe");
  const out = kd.execute(`dt nt!_EPROCESS 0x${lsass.toString(16)}`);
  assert.match(out, /ImageFileName\s+: "lsass\.exe"/);
  assert.match(out, /UniqueProcessId\s+: 00000000`0000006c/);
  if (kd.k.tables.has("_PS_PROTECTION")) {
    assert.match(out, /Protection\s+: ProtectedLight \(Signer: WinTcb\)/);
  }
});

test("lm shows ntoskrnl", async () => {
  const kd = await booted();
  const out = kd.execute("lm");
  assert.match(out, /nt\s+\(export symbols\).*ntoskrnl\.exe/);
});

test("!process <pid> resolves kftarget", async () => {
  const kd = await booted();
  const out = kd.execute("!process 666");
  assert.match(out, /kftarget\.exe/);
  assert.match(out, /UniqueProcessId: 666/);
});

test("unknown command errors like windbg", async () => {
  const kd = await booted();
  const out = kd.execute("frobnicate");
  assert.match(out, /Couldn't resolve error/);
});

test("DKOM hide then verify via !process 0 0 (lab flow)", async () => {
  const kd = await booted();
  const k = kd.k;
  const target = k.processesByName.get("kftarget.exe");
  const linksOff = k.tables.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const links = target + linksOff;
  const flink = k.mem.u64(links), blink = k.mem.u64(links + 8n);
  k.mem.w64(blink, flink);
  k.mem.w64(flink + 8n, blink);

  const out = kd.execute("!process 0 0");
  assert.doesNotMatch(out, /kftarget\.exe/);

  // but the memory is still there — dt on hidden address still works (like real KD)
  const hidden = kd.execute(`dt nt!_EPROCESS 0x${target.toString(16)}`);
  assert.match(hidden, /kftarget\.exe/);
});
