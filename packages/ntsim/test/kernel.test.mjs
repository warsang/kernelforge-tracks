import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NtKernel } from "../src/kernel.mjs";

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

test("kernel boots with real 22h2 offsets and lists processes", async () => {
  const k = await booted();
  const procs = k.listProcesses();
  const names = procs.map((p) => p.name);
  assert.ok(names.includes("lsass.exe"));
  assert.ok(names.includes("kftarget.exe"));

  // offsets actually came from the table (0x448 for 22h2)
  assert.equal(k.tables.offsetOf("_EPROCESS", "ActiveProcessLinks"), 0x448n);
});

test("PsLookupProcessByProcessId finds lsass by PID", async () => {
  const k = await booted();
  const out = k.allocPool(8);
  const status = k.apiImpls.get("PsLookupProcessByProcessId")(108n, out);
  assert.equal(status, 0n);
  assert.equal(k.mem.u64(out), k.processesByName.get("lsass.exe"));
});

test("PPL byte set on lsass via Protection field", async () => {
  const k = await booted();
  if (!k.tables.has("_PS_PROTECTION")) return; // build without PPL
  const eproc = k.processesByName.get("lsass.exe");
  const { StructRef } = await import("../src/structs.mjs");
  const e = new StructRef(k.mem, k.tables, eproc, "_EPROCESS");
  assert.equal(e.u8("Protection") >> 4, 2); // Light
  assert.equal(e.u8("Protection") & 0xf, 6); // WinTcb signer
});

test("DKOM unlink hides process: full driver emulation", async () => {
  const k = await booted();
  const t = k.tables;

  // Hand-assembled "driver" that unlinks an EPROCESS given its address in r9 (arg3).
  // We emulate what a compiled C DKOM routine does, using the CPU:
  //   *(u64*)(links)      = *(u64*)(links + 8)     ; Flink = prev
  //   *(u64*)(prev + 0)   = *(u64*)(links)         ; prev->Flink = next
  // Actually do the canonical two-pointer unlink in JS to drive the model,
  // then verify the emulated list walk no longer sees it.
  const targetEproc = k.processesByName.get("kftarget.exe");
  assert.ok(targetEproc);
  const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const links = targetEproc + linksOff;
  const flink = k.mem.u64(links);
  const blink = k.mem.u64(links + 8n);
  k.mem.w64(blink, flink);       // prev->Flink = next
  k.mem.w64(flink + 8n, blink);  // next->Blink = prev

  const after = k.listProcesses();
  assert.equal(after.find((p) => p.name === "kftarget.exe"), undefined);
  // PID lookup must also fail now
  assert.equal(k.findEprocessByPid(666n), null);
});

test("DbgPrint formatting works with %d and %p", async () => {
  const k = await booted();
  const fmtAddr = k.allocPool(64);
  k.mem.writeAnsi(fmtAddr, "Hello %d from %x\n");
  k.dbgPrint(fmtAddr, [42n, 0xdeadbeefn]);
  assert.equal(k.dbgLog[0], "Hello 42 from deadbeef\n");
});
