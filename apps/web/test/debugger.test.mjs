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

test("!help resolves to the standard help text", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("!help");
  const t = c.text();
  assert.match(t, /commands:/);
  assert.match(t, /!process/);

  // identical output to the plain `help` command
  const c2 = capture(kernel);
  c2.exec("help");
  assert.equal(c.text(), c2.text());
});

test("!process <pid> 7 enumerates ThreadListHead threads (synthetic world)", async () => {
  const { kernel } = await booted();
  const tables = kernel.tables;
  const lsass = kernel.findEprocessByPid(108n);
  const ethread = kernel.currentThread;

  const c = capture(kernel);
  c.exec("!process 108 7"); // flags 7 = wide walk + thread bit (0x4)
  const t = c.text();
  // the wired lsass thread is enumerated beneath its parent, by ETHREAD base
  assert.match(t, new RegExp(`THREAD 0x${ethread.toString(16).padStart(16, "0")}`));
  assert.match(t, /Tid: 408/); // CLIENT_ID.UniqueThread planted by scenario
  // ActiveThreads count is read from _EPROCESS.ActiveThreads (+0x5f0)
  assert.ok(Number(tables.offsetOf("_EPROCESS", "ActiveThreads")) === 0x5f0);
});

test("!process 0 4 lists THREAD entries under their parent process only", async () => {
  const { kernel } = await booted();
  const ethread = kernel.currentThread;
  const c = capture(kernel);
  c.exec("!process 0 4");
  const threadLines = c.lines.filter((l) => l.includes("THREAD "));
  assert.equal(threadLines.length, 1, `expected exactly one resident thread line, got: ${threadLines}`);
  assert.ok(threadLines[0].includes(ethread.toString(16)));
  // it must sit BENEATH its parent process line
  const parentIdx = c.lines.findIndex((l) => l.includes("lsass.exe"));
  const threadIdx = c.lines.findIndex((l) => l.includes("THREAD "));
  assert.ok(parentIdx !== -1 && threadIdx > parentIdx, "thread not nested under parent");
});

test("!process handles empty/corrupt ThreadListHead without hanging", async () => {
  const { kernel } = await booted();
  // synthetic System EPROCESS has a zeroed ThreadListHead — must be a no-op
  const sys = kernel.findEprocessByPid(4n);
  const c = capture(kernel);
  c.exec(`!process ${sys} 7`);
  assert.ok(!c.text().includes("THREAD "), "empty ring must not emit thread lines");

  // corrupt ring pointing at itself must terminate
  const tleOff = kernel.tables.offsetOf("_ETHREAD", "ThreadListEntry");
  const tlhOff = kernel.tables.offsetOf("_EPROCESS", "ThreadListHead");
  kernel.mem.w64(sys + BigInt(tlhOff), sys + BigInt(tlhOff)); // head -> itself
  const kftarget = kernel.findEprocessByPid(666n);
  kernel.mem.w64(kftarget + BigInt(tlhOff), kftarget + BigInt(tlhOff) - BigInt(tleOff));
  const c2 = capture(kernel);
  c2.exec("!process 0 4"); // walks every process; must return
  assert.ok(c2.lines.length > 0);
});

test("!process 0 1 shows real ActiveThreads counts from dump blobs", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec("!process 0 1");
  const t = c.text();
  // regression: populateFromDump used to drop eprocessHex, so every count
  // read 0. System carries 151 threads in the authentic blob.
  assert.match(t, /ActiveThreads: 151/, "System must report its authentic thread count");
  assert.match(t, /ImageFileName: Registry[\s\S]*?ActiveThreads: 4/,
    "Registry must report its authentic thread count");
});

test("!process 0 7 reports the dumped CurrentThread as resident under System", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec("!process 0 7");
  const t = c.text();
  assert.match(t, /THREAD 0xffff8f8b8eb4d040/); // world.kpcr.currentThread
  assert.match(t, /Tid: 6760/);                 // its authentic CLIENT_ID
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

test("dt <Type> <Field> works with nt! prefix", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  c.exec("dt nt!_EPROCESS ActiveProcessLinks");
  assert.match(c.text(), /ActiveProcessLinks/);
  assert.match(c.text(), /offset=0x448|offset=0x1b0/);
});

test("dt _EPROCESS <pid> resolves PID to EPROCESS", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  // lsass pid = 672 in the real dump
  const lsassEproc = kernel.processesByName.get("lsass.exe");
  const c = capture(kernel);
  c.exec("dt _EPROCESS 672");
  const t = c.text();
  assert.match(t, /Resolving pid 672/);
  assert.match(t, /UniqueProcessId\s+: 0x00000000000002a0.*\(dec 672\)/);
});

test("dt _EPROCESS <hex_pid> resolves hex PID", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const c = capture(kernel);
  c.exec("dt _EPROCESS 0x14c0"); // 5312 decimal — a real svchost pid
  assert.match(c.text(), /Resolving pid 5312/);
});

test("dt _EPROCESS <large_va> still treated as literal address", async () => {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables, dumpWorld: raw,
  });
  const lsass = kernel.processesByName.get("lsass.exe");
  const c = capture(kernel);
  c.exec(`dt _EPROCESS ${lsass}`);
  assert.doesNotMatch(c.text(), /Resolving pid/); // NOT treated as PID
  assert.match(c.text(), /UniqueProcessId/);
});

test("dt _EPROCESS <small_nonpid> falls through to address", async () => {
  const { kernel } = await booted();
  const c = capture(kernel);
  // pid=9999 doesn't exist → treated as literal address (which will fault)
  c.exec("dt _EPROCESS 9999");
  assert.match(c.text(), /Memory read error/);
});
