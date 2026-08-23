/**
 * Lab scenario registry: maps lab.scenario ids to boot procedures.
 *
 * A boot procedure is backend-agnostic — it receives a factory that turns a
 * SparseMemory into a CpuBackend (js or unicorn) plus a table loader, so the
 * same scenario runs in the browser (fetch loader) and in Node tests (fs).
 */

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import { StructRef } from "@kernelforge/ntsim/src/structs.mjs";

/** Dev flag planted by boot-default; index.html overrides via process.env. */
export const PROBE_FLAG = "FLAG{kfprobe}";

/**
 * @param {object} io
 * @param {(mem: object) => Promise<object>|object} io.makeBackend
 * @param {() => Promise<object>} io.loadTables StructTables provider
 */
async function bootDefault({ makeBackend, loadTables }) {
  const mem = new SparseMemory();
  const cpu = await makeBackend(mem);
  const tables = await loadTables();

  const kernel = new NtKernel({ cpu, tables });
  kernel.bootstrap();

  // Synthesize a loaded-module list (what `lm` walks). One entry is not a
  // real Windows module — its FullImageName carries this lab's flag.
  const ldrOff = tables.offsetOf("_KLDR_DATA_TABLE_ENTRY", "FullDllName");
  const modules = [
    { base: 0x10000000n, name: "ntoskrnl.exe", full: "\\SystemRoot\\system32\\ntoskrnl.exe" },
    { base: 0x20000000n, name: "hal.dll", full: "\\SystemRoot\\system32\\hal.dll" },
    { base: 0x30000000n, name: "kfprobe.sys", full: `\\SystemRoot\\system32\\drivers\\${PROBE_FLAG}.sys` },
    { base: 0x40000000n, name: "dxgkrnl.sys", full: "\\SystemRoot\\system32\\drivers\\dxgkrnl.sys" },
  ];
  let cursor = 0x50000000n;
  for (const m of modules) {
    const e = new StructRef(mem, tables, cursor, "_KLDR_DATA_TABLE_ENTRY");
    e.w64("DllBase", m.base);
    // FullImageName is a UNICODE_STRING embedded by offset; write length
    // fields + buffer pointer, then the UTF-16 body in pool space.
    mem.w16(cursor + ldrOff, m.full.length * 2);
    mem.w16(cursor + ldrOff + 2n, (m.full.length + 1) * 2);
    mem.w64(cursor + ldrOff + 8n, cursor + 0x800n); // UNICODE_STRING.Buffer
    mem.writeUtf16(cursor + 0x800n, m.full);
    cursor += 0x1000n;
  }
  kernel.loadedModules = modules;

  return { kernel, kind: "boot-default" };
}

export const scenarios = {
  "boot-default": {
    title: "Boot ntsim (Win10 22H2 layout)",
    description:
      "Boots the emulated kernel with real 22h2 struct offsets and a small " +
      "loaded-module list. Inspect it with the debugger console.",
    boot: bootDefault,
  },
};

export function getScenario(id) {
  const s = scenarios[id];
  if (!s) throw new Error(`unknown scenario "${id}"`);
  return s;
}
