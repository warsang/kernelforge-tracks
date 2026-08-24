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
  // searchable probe-module content
  mem.writeUtf16(0x30000800n, "\\SystemRoot\\system32\\drivers\\kfprobe.sys");
  mem.writeAnsi(0x30000a00n, "FLAG{kfprobe} kernel probe driver v1.0");

  // Synthesize a loaded-module list (what `lm` walks). One entry is not a
  // real Windows module — its FullImageName carries this lab's flag.
  const ldrOff = tables.offsetOf("_KLDR_DATA_TABLE_ENTRY", "FullDllName");
  const modules = [
    { base: 0x10000000n, name: "ntoskrnl.exe", full: "\\SystemRoot\\system32\\ntoskrnl.exe" },
    { base: 0x20000000n, name: "hal.dll", full: "\\SystemRoot\\system32\\hal.dll" },
    { base: 0x30000000n, name: "kfprobe.sys", lab: true, full: `\\SystemRoot\\system32\\drivers\\${PROBE_FLAG}.sys` },
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

  if (!dumpWorld) {
  if (!dumpWorld) {
    // Plausible live context for the synthetic world (executing ntoskrnl+0x1000)
    if (kernel.loadedModules?.length) {
      kernel.cpu.regs.rip = kernel.loadedModules[0].base + 0x1000n;
      kernel.cpu.regs.rsp = 0xfffff8055b000000n;
      kernel.contextSource = "synthetic";
    }
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

  // give lsass a live thread list so !process <pid> 4 can enumerate it:
  // ThreadListHead <-> ethread.ThreadListEntry ring + ActiveThreads = 1
  const lsassEproc = kernel.findEprocessByPid(lsassPid);
  if (lsassEproc) {
    try {
      const tlhOff = BigInt(tables.offsetOf("_EPROCESS", "ThreadListHead"));
      const tleOff = BigInt(tables.offsetOf("_ETHREAD", "ThreadListEntry"));
      const headAddr = lsassEproc + tlhOff;
      const entry = ethread + tleOff;
      mem.w64(headAddr, entry);
      mem.w64(headAddr + 8n, entry);
      mem.w64(entry, headAddr);
      mem.w64(entry + 8n, headAddr);
      mem.w32(lsassEproc + BigInt(tables.offsetOf("_EPROCESS", "ActiveThreads")), 1);
    } catch { /* build without thread-list fields */ }
  }

  kernel.kpcr = kpcr;
    kernel.prcb = prcb;
    kernel.currentThread = ethread;
  }

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
    // authentic full _EPROCESS image — MUST be carried through, otherwise
    // every field beyond the planted subset (ActiveThreads, ThreadListHead,
    // VadCount, Cookie, …) silently reads as zero
    eprocessHex: p.eprocessHex,
  }));

  // lab fixtures appended (synthetic, clearly ours)
  let nextFakeEproc = 0xffffc80000000000n; // kernel-space synthetic range
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
    // Authentic full _EPROCESS image extracted from the dump (fields beyond
    // our planted subset — VadCount, Cookie, QuotaBlock, … — are now real).
    if (p.eprocessHex) {
      const bytes = new Uint8Array(p.eprocessHex.match(/.{2}/g).map((x) => parseInt(x, 16)));
      mem.write(p.eproc, bytes);
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
  // real PE headers at their DllBases — enables !dh parsing
  for (const m of world.modules) {
    if (!m.headerHex || !m.base) continue;
    const bytes = new Uint8Array(m.headerHex.match(/.{2}/g).map((x) => parseInt(x, 16)));
    mem.write(BigInt(m.base), bytes);
  }
  // head must point INTO the new ring
  mem.w64(head, procs[0].eproc + linksOff);            // head.Flink -> first
  mem.w64(head + 8n, procs[procs.length - 1].eproc + linksOff); // head.Blink -> tail

  // Wire dump globals into the symbol engine
  if (kernel.symbolEngine) {
    kernel.symbolEngine.loadDumpGlobals({
      psActiveProcessHead: kernel.PsActiveProcessHead,
      directoryTableBase: world.meta?.directoryTableBase,
    });
  }

  // Real KPCR / PRCB / CurrentThread extracted from the same dump
  if (world.kpcr) {
    const put = (vaHex, hex) => {
      const va = BigInt(vaHex);
      const bytes = new Uint8Array(hex.match(/.{2}/g).map((x) => parseInt(x, 16)));
      mem.write(va, bytes);
      return va;
    };
    kernel.kpcr = put(world.kpcr.va, world.kpcr.kpcrHex);
    kernel.prcb = put(world.kpcr.prcb, world.kpcr.prcbHex);
    kernel.currentThread = put(world.kpcr.currentThread, world.kpcr.threadHex);
  }

  // loaded modules: real bases/SIZES/ordering (+ our probe module appended).
  // The dumper truncated UNICODE_STRING buffers, so names are reconstructed:
  //   * index 0 / largest image -> ntoskrnl.exe (kernel base anchor)
  //   * otherwise longest usable path fragment -> <fragment>.sys
  const mods = world.modules.map((m, i) => {
    const hint = (m.baseDllName || m.fullDllName || "").split("\\").filter(Boolean).pop() || "";
    let name;
    if (i === 0 || m.sizeOfImage >= 0x800000) name = "ntoskrnl.exe";
    else if (/^hal(\\|\.|$)/i.test(hint) || /\\hal\.dll/i.test(m.fullDllName || "")) name = "hal.dll";
    else if (/^[A-Za-z0-9_-]{3,}$/.test(hint)) name = hint + ".sys";
    else name = "mod_" + i.toString(16) + ".sys";
    return {
      base: BigInt(m.base),
      sizeOfImage: m.sizeOfImage ?? 0x10000,
      name, full: m.fullDllName || "", real: true,
      nameRepaired: name !== hint,
    };
  });
  // lab probe module — relocated into kernel space (was wrongly user-range)
  mods.push({
    base: 0xfffff8055a000000n, sizeOfImage: 0x8000,
    name: "kfprobe.sys",
    full: `\\SystemRoot\\system32\\drivers\\${PROBE_FLAG}.sys`, lab: true,
  });
  kernel.loadedModules = mods;

  // lab probe module content: flag path as UTF-16 + ANSI, searchable via s/
  {
    const probeBase = 0xfffff8055a000000n;
    const probeFull = "\\SystemRoot\\system32\\drivers\\kfprobe.sys";
    const u16 = [...probeFull].map((c) => c.charCodeAt(0));
    mem.write(probeBase + 0x800n, new Uint8Array(new Uint16Array(u16).buffer));
    mem.writeAnsi(probeBase + 0xa00n,
      "FLAG{kfprobe} kernel probe driver v1.0 — hello from kernel land");
  }

  // saved crash-moment CPU context -> seed BOTH backends' register file
  // saved crash-moment CPU context -> seed BOTH backends' register file
  if (world.context) {
    for (const [reg, val] of Object.entries(world.context)) {
      try { kernel.cpu.regs[reg] = BigInt(val); } catch { /* unknown reg */ }
    }
    kernel.contextSource = "dump";
  }

  // correlate the dumped CurrentThread with its process via Cid (@ETHREAD+0x478)
  if (world.kpcr?.currentThread && world.kpcr.threadHex) {
    const bytes = world.kpcr.threadHex.match(/.{2}/g).map((x) => parseInt(x, 16));
    const cidProcOff = 0x478;
    const pidBytes = bytes.slice(cidProcOff, cidProcOff + 8);
    let pid = 0n;
    for (let i = 7; i >= 0; i--) pid = (pid << 8n) | BigInt(pidBytes[i]);
    const owner = kernel.findEprocessByPid(pid);
    kernel.threads = kernel.threads ?? {};
    kernel.threads[String(world.kpcr.currentThread)] = { pid, process: owner };

    // Make the resident thread enumerable: rebuild the owner's ThreadListHead
    // ring around it. The authentic head points at non-resident dump threads,
    // which !process 0x4 reports as unbacked pointers.
    if (owner) {
      try {
        const tlhOff = BigInt(t.offsetOf("_EPROCESS", "ThreadListHead"));
        const tleOff = BigInt(t.offsetOf("_ETHREAD", "ThreadListEntry"));
        const th = BigInt(world.kpcr.currentThread);
        const headAddr = owner + tlhOff;
        const entry = th + tleOff;
        mem.w64(headAddr, entry);
        mem.w64(headAddr + 8n, entry);
        mem.w64(entry, headAddr);
        mem.w64(entry + 8n, headAddr);
      } catch { /* build without thread-list fields */ }
    }
  }
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

/**
 * Manual-map lab world: same base world plus kfloader.sys — a mapper whose
 * import-resolution step ships STUBBED. The student inspects the loader
 * (!mmstate), repairs the stub from the debugger (eb), runs the map
 * (!mmrun) and captures the payload's DbgPrint secret.
 */
function setupManualMap(kernel) {
  const mem = kernel.mem;

  const LOADER_BASE = 0xfffff8055a300000n;
  const PAYLOAD_BASE = 0xfffff8055a200000n;
  const IAT_RVA = 0x2000n;
  const IMPORTS = ["nt!DbgPrint", "nt!ExAllocatePoolWithTag"];

  // resolve thunk targets against whichever ntoskrnl this world booted
  const ntBase = (kernel.loadedModules ?? []).find((m) => m.name === "ntoskrnl.exe")
    ?.base ?? 0xfffff8052b800000n;

  // materialize the loader's config page: g_ResolveImports = 0 (stubbed)
  const resolveFlag = LOADER_BASE;
  mem.w8(resolveFlag, 0);

  // payload IAT page (all zeros until the resolver runs)
  const iatBase = PAYLOAD_BASE + IAT_RVA;
  for (let i = 0; i < IMPORTS.length; i++) mem.w64(iatBase + BigInt(i * 8), 0n);

  kernel.manualMap = {
    loaderBase: LOADER_BASE,
    payloadBase: PAYLOAD_BASE,
    iatBase,
    resolveFlag,
    imports: IMPORTS,
    thunks: IMPORTS.map((_, i) => ntBase + BigInt(0x1000 + i * 0x10)),
    secret: "FLAG{manual_map_master}",
    runs: 0,
  };

  // make the loader visible to `lm` (payload appears only once mapped+run)
  kernel.loadedModules.push({
    base: LOADER_BASE, sizeOfImage: 0x8000, name: "kfloader.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfloader.sys", lab: true,
  });
}

scenarios["manual-map"] = {
  title: "manual-map — PE manual mapping with import resolution",
  description:
    "Boots the 22H2 world with kfloader.sys loaded. Its import resolution is " +
    "stubbed: mmpayload.sys cannot run until you repair the loader from the " +
    "debugger. Inspect with !mmstate, fix with eb, execute with !mmrun.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupManualMap(session.kernel);
    session.kind = "manual-map";
    return session;
  },
};

export function getScenario(id) {
  const s = scenarios[id];
  if (!s) throw new Error(`unknown scenario "${id}"`);
  return s;
}
