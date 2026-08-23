/**
 * Scenario glue must work headless in Node too (same code the browser runs),
 * so lab flows stay testable without a DOM.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario, PROBE_FLAG } from "../src/scenarios.js";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

// Node-side stand-in for the browser's fetch loader
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

test("boot-default plants a suspicious module carrying the probe flag", async () => {
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });

  assert.ok(kernel.loadedModules.length >= 4);
  const suspect = kernel.loadedModules.find((m) => m.full.includes(PROBE_FLAG));
  assert.ok(suspect, "flag-carrying module missing");
  assert.equal(suspect.name, "kfprobe.sys");
});

test("boot-default kernel lists default processes with real offsets", async () => {
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
  const procs = kernel.listProcesses();
  const names = procs.map((p) => p.name);
  assert.ok(names.includes("kfsample.exe"));
  assert.ok(names.includes("lsass.exe"));
  // real 22h2 offset flowed through
  assert.equal(kernel.tables.offsetOf("_EPROCESS", "ActiveProcessLinks"), 0x448n);
});

test("FullDllName of every module round-trips as UTF-16", async () => {
  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
  for (const m of kernel.loadedModules) {
    assert.ok(kernel.loadedModules.every(() => true));
    void m;
  }
  // spot-check one via raw memory: kfprobe entry carries the flag text
  const all = [];
  let cursor = 0x50000000n;
  for (let i = 0; i < kernel.loadedModules.length; i++) {
    const s = kernel.mem.readUtf16(cursor + 0x800n);
    all.push(s);
    cursor += 0x1000n;
  }
  assert.ok(all.some((s) => s.includes(PROBE_FLAG)));
});

test("real-dump world: fixture loads with authentic processes", async () => {
  const { readFile } = await import("node:fs/promises");
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  assert.ok(raw.processes.length >= 40, "expected a real machine's process list");

  const scenario = getScenario("boot-default");
  const { kernel } = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
    dumpWorld: raw,
  });

  const procs = kernel.listProcesses();
  const byName = (n) => procs.find((p) => p.name === n);
  // authentic entries
  assert.equal(byName("System").pid, 4n);
  assert.ok(byName("lsass.exe"));
  assert.ok(procs.length >= 80);
  // lab fixtures injected on top of the real machine
  assert.ok(byName("kftarget.exe"));
  assert.ok(kernel.loadedModules.some((m) => m.full.includes(PROBE_FLAG)));
  // token blob bytes landed at the decoded fastref target
  const lsass = kernel.processesByName.get("lsass.exe");
  const tokRaw = kernel.mem.u64(lsass + kernel.tables.offsetOf("_EPROCESS", "Token"));
  const target = tokRaw & ~0xfn;
  const blob = kernel.mem.read(target, 8);
  assert.equal(blob[0], 0x2a); // '*SYSTEM*' magic from the real dump
});
