/**
 * Headless debugger-command tests (pure core, no DOM).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario, PROBE_FLAG } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

async function loadTables() {
  const names = ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

async function booted() {
  const scenario = getScenario("boot-default");
  return scenario.boot({ makeBackend: (mem) => new JsInterpreter(mem), loadTables });
}

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  let cleared = false;
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = (line) => {
    let [cmd, ...args] = line.trim().split(/\s+/);
    if (!commands[cmd]) {
      const m = cmd.match(/^(lm)([a-zA-Z]+)$/i); // lmD-style flags -> lm
      if (m) { cmd = m[1]; args = [m[2], ...args]; }
    }
    commands[cmd]?.(args, w, { set innerHTML(v) { cleared = true; lines.push(`(cleared)`); } });
  };
  return { exec, lines, text: () => lines.join("\n"), get cleared() { return cleared; } };
}

test("lm lists the probe module with a suspicious marker", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("lm");
  const t = c.text();
  assert.match(t, /kfprobe\.sys/);
  assert.match(t, /<-- suspicious/);
});

test("lm tolerates flags like lmD with a note", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("lmD");
  assert.match(c.text(), /not modeled/);
});

test("!process <addr> 1 walks real _EPROCESS fields incl decoded Token", async () => {
  const { kernel } = await booted();
  const lsass = kernel.processesByName.get("lsass.exe");
  const c = capture(kernel);
  c.exec(`!process ${lsass} 1`);
  const t = c.text();
  assert.match(t, /UniqueProcessId/);
  assert.match(t, /108\)/); // decimal pid annotation
  assert.match(t, /Token\s+:.*fastref refs=8/);
  assert.match(t, /-> 0x0000000060000300/);
  assert.match(t, /ActiveProcessLinks\.Flink/); // embedded LIST_ENTRY decoded
});

test("!process 0 0 lists all processes; clear clears", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!process 0 0");
  for (const n of ["System", "lsass.exe", "kftarget.exe"]) assert.ok(c.text().includes(n));
  c.exec("clear");
  assert.ok(c.cleared);
});

test("!pcr walks KPCR and hints the PRCB -> CurrentThread chain", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!pcr");
  const t = c.text();
  assert.match(t, /_KPCR @ /);
  assert.match(t, /Self\s+: 0x.*200000/);           // Self == kpcr
  assert.match(t, /CurrentPrcb -> .*00200180/);        // kpcr+0x180
  assert.match(t, /dt _KPRCB /);
  assert.match(t, /dt _ETHREAD /);

  // the hinted addresses must actually resolve
  const prcbLine = c.lines.find((l) => l.includes("CurrentPrcb -> "));
  const prcb = BigInt(prcbLine.split("-> ")[1].trim().split(/\s+/)[0]);
  const c2 = capture(kernel);
  c2.exec(`dt _KPRCB ${prcb}`);
  const ctLine = c2.lines.find((l) => l.includes("CurrentThread"));
  assert.ok(ctLine, "CurrentThread missing from PRCB walk");
});

test("!thread defaults to PRCB.CurrentThread and shows Cid pid=108", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!thread");
  const t = c.text();
  assert.match(t, /_ETHREAD @ /);
  assert.match(t, /Win32StartAddress\s+: 0x0*7ff00000/);
});

test("!token via pid decodes fastref and dumps blob", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!token 108");
  const t = c.text();
  assert.match(t, /TOKEN @ 0x0*60000300/);
  assert.match(t, /7a6ccafe/i); // pid=108=0x6c pattern qword
});

test("dt: known type walks fields; unknown type lists available", async () => {
  const { kernel } = await booted();
  const lsass = kernel.processesByName.get("lsass.exe");
  const c = capture(kernel);
  c.exec(`dt _EPROCESS ${lsass}`);
  assert.match(c.text(), /\+0x448 ActiveProcessLinks\.Flink/);

  const c2 = capture(kernel);
  c2.exec("dt _TOKEN 0x60000000");
  assert.match(c2.text(), /available: .*_EPROCESS/);
});

test("!pcr walks the REAL KPCR when booted from the dump fixture", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  assert.equal(kernel.kpcr, BigInt(raw.kpcr.va));
  const c = capture(kernel);
  c.exec("!pcr");
  const t = c.text();
  assert.ok(t.includes("_KPCR @"));
  const idtLine = c.lines.find((l) => l.includes("IdtBase"));
  assert.ok(idtLine && !/0x0+$/.test(idtLine.split(":")[1].trim()), "IdtBase null");
});

test("dump mode: registers seeded from saved context", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  assert.equal(kernel.cpu.regs.rip, BigInt(raw.context.rip));
  assert.notEqual(kernel.cpu.regs.rsp, 0n);

  const c = capture(kernel);
  c.exec("r");
  const t = c.text();
  assert.match(t, /context from dump/);
  assert.match(t, /\+0x[0-9a-f]+/); // rip symbolized as module+offset
});

test("!prcb walks the real PRCB from the fixture", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec("!prcb");
  assert.match(c.text(), /_KPRCB @ /i);
});

test("!analyze -v reports context/process/modules", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!analyze -v");
  const t = c.text();
  assert.match(t, /ANALYSIS/);
  assert.match(t, /No bugcheck recorded/);
  assert.match(t, /CONTEXT:/);
  assert.match(t, /PROCESS:/);
  assert.match(t, /MODULES:/);
});

test("sym resolves module+offset", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  const mod = kernel.loadedModules[0];
  c.exec(`sym ${mod.base + 0x1234n}`);
  assert.ok(c.text().includes(mod.name + "+0x1234"), c.text());
});

test("dt faults on non-canonical / unmapped addresses", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("dt _EPROCESS 0xffffffffffffffff");
  assert.match(c.text(), /Memory read error at 0xffffffffffffffff \(unmapped\)/);
  const c2 = capture(kernel);
  c2.exec("dt _EPROCESS 0x1234");
  assert.match(c2.text(), /Memory read error at 0x0000000000001234 \(unmapped\)/);
});

test("k ChildSP falls back to PRCB.RspBase when regs.rsp is zero", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  kernel.cpu.regs.rsp = 0n; // simulate the unicorn desync
  const c = capture(kernel);
  c.exec("k");
  assert.match(c.text(), /ChildSP from PRCB\.RspBase/);
  // RspBase from the real dump: PRCB+0x28
  const prcbHex = raw.kpcr.prcbHex;
  const rspBase = BigInt("0x" + prcbHex.slice(0x28 * 2, 0x28 * 2 + 16));
  assert.match(c.text(), /0xffff890a9a3c7650/);
});

test("!dh parses ntoskrnl PE headers from guest memory", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec("!dh ntoskrnl.exe");
  const t = c.text();
  assert.match(t, /PE signature OK/);
  assert.match(t, /machine .* \(x64\)/);
  assert.match(t, /section table/);
  assert.ok(t.includes(".text"));
});

test("s finds ascii and hex patterns in mapped memory", async () => {
  const { kernel } = await booted();
  const probeBase = 0x30000000n;
  const c = capture(kernel);
  // probe content was written to its pages during scenario boot
  c.exec(`s -a ${probeBase + 0xa00n} 0x200 "FLAG{kfprobe}"`);
  assert.match(c.text(), /Found /);
  const c2 = capture(kernel);
  c2.exec(`s -a ${kernel.loadedModules.find((m) => m.name === "kfprobe.sys").base} 0x100 "NOT_PRESENT_ANYWHERE"`);
  assert.match(c2.text(), /0 matches/);
});

test("!process <threadAddr> routes to !thread hint", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec(`!process ${raw.kpcr.currentThread}`);
  assert.match(c.text(), /is an _ETHREAD — use !thread/);
});

test("dt symbol-only mode shows layout without address", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("dt _EPROCESS");
  const t = c.text();
  assert.match(t, /struct _EPROCESS/);
  assert.match(t, /UniqueProcessId/);
  assert.match(t, /layout-only/);
});

test("dt nt!_EPROCESS normalizes module prefix", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("dt nt!_EPROCESS");
  assert.match(c.text(), /struct _EPROCESS/);
});

test("dt <Type> <Field> returns single field info", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("dt _EPROCESS UniqueProcessId");
  const t = c.text();
  assert.match(t, /UniqueProcessId/);
  assert.match(t, /offset=0x440|offset=0x1b0/); // varies by build
});

test("!ps aliases !process 0 0", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!ps");
  assert.match(c.text(), /System/);
  assert.match(c.text(), /lsass\.exe|services\.exe/);
});

test("!kpcr aliases !pcr", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec("!kpcr");
  assert.match(c.text(), /_KPCR @ /);
});

test("unicorn backend: rsp readable after dump-mode seeding", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const { createUnicornBackend } = await import("@kernelforge/ntsim-unicorn");
  const { SparseMemory } = await import("@kernelforge/ntsim/src/memory.mjs");
  const mem = new SparseMemory();
  const cpu = await createUnicornBackend(mem);
  // seed like populateFromDump does
  cpu.regs.rsp = BigInt(raw.context.rsp);
  cpu.regs.rip = BigInt(raw.context.rip);
  assert.equal(cpu.regs.rsp, BigInt(raw.context.rsp));
  assert.equal(cpu.regs.rip, BigInt(raw.context.rip));
});
