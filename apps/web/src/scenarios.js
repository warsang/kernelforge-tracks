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
async function bootDefault({ makeBackend, loadTables, dumpWorld = null }) {
  const mem = new SparseMemory();
  const cpu = await makeBackend(mem);
  const tables = await loadTables();

  const kernel = new NtKernel({ cpu, tables });
  kernel.bootstrap();

  if (dumpWorld) populateFromDump(kernel, tables, dumpWorld);
  if (!dumpWorld) {
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

  // Synthesize EX_FAST_REF tokens so !process <addr> 1 / !token have a live
  // target. Blobs are recognizable pattern data, NOT a real _TOKEN layout
  // (no Vergilius _TOKEN table is loaded — see debugger note).
  const tokOff = tables.offsetOf("_EPROCESS", "Token");
  const tokens = {};
  let tokBlob = 0x60000000n;
  for (const p of kernel.listProcesses()) {
    mem.w64(tokBlob, BigInt(`0x7A${p.pid.toString(16)}CAFE`)); // recognizable
    const encoded = tokBlob | 0x8n; // pretend 8 fastrefs held on the pointer
    mem.w64(p.eprocess + tokOff, encoded);
    tokens[p.pid.toString()] = { blob: tokBlob, raw: encoded };
    tokBlob += 0x100n;
  }
  kernel.tokens = tokens;
  }

  // Synthesize the processor control chain: KPCR -> PRCB -> CurrentThread.
  // Offsets come from the active build's tables; only CLIENT_ID's stable
  // {UniqueProcess; UniqueThread} pair is written by fixed sub-offsets.
  const kpcr = kernel.bases.kva + 0x200000n;   // one page, page-aligned
  const prcb = kpcr + 0x180n;                  // classic embedded-PRCB spot
  const ethread = kernel.bases.kva + 0x210000n;
  const lsassPid = 108n;

  mem.w64(kpcr + tables.offsetOf("_KPCR", "Self"), kpcr);
  mem.w64(kpcr + tables.offsetOf("_KPCR", "CurrentPrcb"), prcb);
  mem.w64(kpcr + tables.offsetOf("_KPCR", "IdtBase"), kernel.bases.kva + 0x220000n);
  mem.w64(kpcr + tables.offsetOf("_KPCR", "GdtBase"), kernel.bases.kva + 0x230000n);

  mem.w64(prcb + tables.offsetOf("_KPRCB", "CurrentThread"), ethread);
  mem.w32(prcb + tables.offsetOf("_KPRCB", "InitialApicId"), 0);

  const cidOff = tables.offsetOf("_ETHREAD", "Cid");
  mem.w64(ethread + cidOff, lsassPid);          // CLIENT_ID.UniqueProcess
  mem.w64(ethread + cidOff + 8n, 408n);         // CLIENT_ID.UniqueThread
  mem.w64(ethread + tables.offsetOf("_ETHREAD", "Win32StartAddress"), 0x7ff00000n);
  mem.w64(ethread + tables.offsetOf("_ETHREAD", "StartAddress"), 0x7ff01000n);
  // mark lsass EPROCESS so explorers can correlate: stamp StartAddress too
  mem.w64(ethread + tables.offsetOf("_ETHREAD", "StartAddress"), 0x7ff01000n);

  kernel.kpcr = kpcr;
  kernel.prcb = prcb;
  kernel.currentThread = ethread;

  return { kernel, kind: "boot-default" };
}

/** Try to load a real-dump snapshot; returns parsed JSON or null. */
export async function tryLoadDumpWorld(fetchImpl = fetch) {
  try {
    const res = await fetchImpl("/dumps/kdemu-win10-19041.json");
    if (!res.ok) return null;
    const j = await res.json();
    if (!j?.processes?.length || !j?.modules?.length) return null;
    return j;
  } catch {
    return null;
  }
}




/**
 * Build the process world from REAL dump data: EPROCESS blocks live at their
 * true virtual addresses, with authentic pids/names/tokens/protection.
 * Lab fixtures (kfsample.exe, kftarget.exe) are appended so existing labs
 * remain playable on top of an otherwise-authentic machine.
 */
function populateFromDump(kernel, tables, world) {
  const mem = kernel.mem;
  const t = tables;
  const linksOff = t.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const pidOff = t.offsetOf("_EPROCESS", "UniqueProcessId");
  const nameOff = t.offsetOf("_EPROCESS", "ImageFileName");
  const tokOff = t.offsetOf("_EPROCESS", "Token");
  const protOff = (() => { try { return t.offsetOf("_EPROCESS", "Protection"); } catch { return null; } })();

  const procs = world.processes.map((p) => ({
    pid: BigInt(p.pid), eproc: BigInt(p.eprocess),
    name: p.name.slice(0, 15),
    tokenRaw: p.token ? BigInt(p.token.raw) : 0n,
    tokenTarget: p.token && p.token.target ? BigInt(p.token.target) : 0n,
    tokenBlobHex: p.token?.blob256,
    protectionByte: p.protectionByte,
  }));

  // lab fixtures appended (synthetic, clearly ours)
  let nextFakeEproc = 0x50000000n;
  for (const [nm, pid] of [["kfsample.exe", 312n], ["kftarget.exe", 666n]]) {
    procs.push({ pid, eproc: nextFakeEproc, name: nm, tokenRaw: 0n, tokenTarget: 0n });
    nextFakeEproc += 0x1000n;
  }

  // Rebuild the circular list: head.Flink -> first ... tail.Flink -> head.
  const head = kernel.PsActiveProcessHead;
  procs.forEach((p, i) => {
    mem.w64(p.eproc + pidOff, p.pid);
    mem.writeAnsi(p.eproc + nameOff, p.name, 15);
    if (p.tokenRaw) mem.w64(p.eproc + tokOff, p.tokenRaw);
    if (protOff !== null && typeof p.protectionByte === "number") {
      mem.w8(p.eproc + protOff, p.protectionByte);
    }
    const isFirst = i === 0;
    const isLast = i === procs.length - 1;
    const flink = isLast ? head : procs[i + 1].eproc + linksOff;
    const blink = isFirst ? head : procs[i - 1].eproc + linksOff;
    mem.w64(p.eproc + linksOff, flink);
    mem.w64(p.eproc + linksOff + 8n, blink);
    if (p.tokenBlobHex && p.tokenTarget) {
      const bytes = new Uint8Array(p.tokenBlobHex.match(/.{2}/g).map((x) => parseInt(x, 16)));
      mem.write(p.tokenTarget, bytes);
    }
    kernel.processesByName.set(p.name, p.eproc);
  });
  // head must point INTO the new ring
  mem.w64(head, procs[0].eproc + linksOff);            // head.Flink -> first
  mem.w64(head + 8n, procs[procs.length - 1].eproc + linksOff); // head.Blink -> tail

  // loaded modules: real bases/sizes/ordering (+ our probe module appended)
  kernel.loadedModules = [
    ...world.modules.map((m) => ({
      base: BigInt(m.base), sizeOfImage: m.sizeOfImage,
      name: (m.baseDllName || m.fullDllName || "?").split("\\").pop(),
      full: m.fullDllName || "",
      real: true,
    })),
    { base: 0x30000000n, name: "kfprobe.sys",
      full: `\\SystemRoot\\system32\\drivers\\${PROBE_FLAG}.sys` },
  ];
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

/** DKOM lab preview: identical world, named for the lab that will target it. */
scenarios["dkom-hide"] = {
  title: "dkom-hide — process-hiding target",
  description:
    "Same 22H2 world as boot-default. Once the browser compile service lands, " +
    "your driver will unlink kftarget.exe here; until then use it to practice " +
    "walking PsActiveProcessHead in the debugger.",
  boot: async (io) => {
    const session = await bootDefault(io);
    session.kind = "dkom-hide";
    return session;
  },
};

export function getScenario(id) {
  const s = scenarios[id];
  if (!s) throw new Error(`unknown scenario "${id}"`);
  return s;
}
