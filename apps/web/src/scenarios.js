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
import { PageTableSpace, joinVa } from "@kernelforge/ntsim/src/paging.mjs";
import { ServiceTable } from "@kernelforge/ntsim/src/ssdt.mjs";
import { writeFunctionGrid } from "@kernelforge/ghidra-decompiler";
import { loadDumpState } from "@kernelforge/ntsim/src/dumpstate.mjs";
import { Chipset, SmmEngine, DEFAULT_SMBASE } from "@kernelforge/ntsim/src/index.mjs";

/**
 * Low-memory bases for the blog-labs worlds (m11-m13): everything stays
 * under bit 47 so each world boots identically under the JsInterpreter AND
 * the Unicorn/QEMU backend (softmmu cannot traverse canonical kernel VAs,
 * see packages/ntsim-unicorn/src/backend.mjs). Page-table physical frames
 * live at 0x3000000+, fixture drivers at 0x5000000+.
 */
export const LOW_BASES = {
  kva: 0x10000000n, pool: 0x20000000n, thunk: 0x30000000n,
  eproc: 0x40000000n, driver: 0x50000000n,
};

/** Shared low-layout boot: same shape as bootDefault, unicorn-safe. */
async function bootLow({ makeBackend, loadTables }) {
  const mem = new SparseMemory();
  const cpu = await makeBackend(mem);
  const tables = await loadTables();
  const kernel = new NtKernel({ cpu, tables, bases: LOW_BASES });
  kernel.bootstrap();
  kernel.loadedModules ??= []; // bare worlds have no dump-populated module list
  return { kernel, kind: "", dumpPagesLoaded: false };
}

/** Dev flag planted by boot-default; index.html overrides via process.env. */
export const PROBE_FLAG = "FLAG{kfprobe}";

/**
 * @param {object} io
 * @param {(mem: object) => Promise<object>|object} io.makeBackend
 * @param {() => Promise<object>} io.loadTables StructTables provider
 */
async function bootDefault({ makeBackend, loadTables, dumpWorld = null, carvedState = null }) {
  const mem = new SparseMemory();
  const cpu = await makeBackend(mem);
  const tables = await loadTables();

  const kernel = new NtKernel({ cpu, tables });
  kernel.bootstrap();

  // Genuine dump pages first (ntoskrnl/CI/cng code+data at true VAs) — the
  // process/KPCR overlay below then patches live structures on top.
  let dumpPagesLoaded = 0;
  if (carvedState) {
    const info = loadDumpState(mem, carvedState);
    dumpPagesLoaded = info.pagesLoaded;
    kernel.dumpSource = "carved";
    kernel.carvedModules = info.modules;
  }

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
  // (no Vergilius _TOKEN table is loaded — see debugger note). Blobs live in
  // kernel pool range — a Token pointing at user-range VAs would scream
  // "emulator" in every !process listing.
  const tokOff = tables.offsetOf("_EPROCESS", "Token");
  const tokens = {};
  let tokBlob = 0xffffa40bc9e78000n;
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
  // Teb + Win32Thread so !process threads render the full kd field set
  try { mem.w64(ethread + BigInt(tables.offsetOf("_KTHREAD", "Teb")), 0x000000e4000660000n); } catch { /* optional */ }
  try { mem.w64(ethread + BigInt(tables.offsetOf("_KTHREAD", "Win32Thread")), 0xffffbe0100011000n); } catch { /* optional */ }

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
      // KTHREAD.ApcState.Process -> owner EPROCESS: the EDR cross-reference
      // that survives DKOM (see lessons m1.l0 / m1.l2). _KTHREAD embeds at
      // offset 0 of _ETHREAD, so the KTHREAD offset addresses this blob too.
      try {
        const apcOff = BigInt(tables.offsetOf("_KTHREAD", "ApcState"));
        mem.w64(ethread + apcOff, lsassEproc);
      } catch { /* build without KTHREAD.ApcState */ }
    } catch { /* build without thread-list fields */ }
  }

  kernel.kpcr = kpcr;
    kernel.prcb = prcb;
    kernel.currentThread = ethread;
  }

  return { kernel, kind: "boot-default", dumpPagesLoaded };
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
 * Try to load a CARVED dump state (carve-dump.mjs output: VA-keyed genuine
 * pages + module list). Returns parsed state or null when absent — labs then
 * fall back to the static JSON world.
 */
export async function tryLoadCarvedState(fetchImpl = fetch) {
  try {
    const res = await fetchImpl("/dumps/ntsim-state.json");
    if (!res.ok) return null;
    const j = await res.json();
    if (!Array.isArray(j?.pages) || !j.pages.length) return null;
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

  // lab fixtures appended (synthetic, clearly ours). Addresses imitate real
  // non-paged pool allocations on a Win10 x64 box — NOT page-aligned slab
  // look-alikes: kd output should not advertise its own fixtures. Cids are
  // unique system-wide against every authentic dump process (the dump world
  // carries an svchost.exe at 312, so kfsample moved to 1312; see
  // DEFAULT_PROCESSES in packages/ntsim/src/kernel.mjs).
  const FIXTURE_PROCS = [
    { name: "kfsample.exe", pid: 1312n, eproc: 0xffffa40bc9e731a0n, parent: 4n },
    { name: "kftarget.exe", pid: 888n, eproc: 0xffffa40bc9e73dc0n, parent: 1312n },
  ];
  let fixtureTokenBlob = 0xffffa40bc9e75000n;
  for (const f of FIXTURE_PROCS) {
    const pattern = BigInt(`0x7A${f.pid.toString(16)}CAFE`); // recognizable, like bootDefault
    const blobHex = pattern.toString(16).padStart(16, "0");
    procs.push({
      pid: f.pid, eproc: f.eproc, name: f.name,
      // EX_FAST_REF-encoded pointer to a live token blob — !process must
      // never print Token: 0x0 for a running process
      tokenRaw: fixtureTokenBlob | 0x8n,
      tokenTarget: fixtureTokenBlob,
      tokenBlobHex: blobHex,
      parentCid: f.parent,
    });
    fixtureTokenBlob += 0x100n;
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
    // fixtures carry a ParentCid so !process headers read like real kd
    if (p.parentCid) {
      try {
        mem.w64(p.eproc + BigInt(t.offsetOf("_EPROCESS", "InheritedFromUniqueProcessId")), p.parentCid);
      } catch { /* build without the field */ }
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
  // real PE headers at their DllBases — enables !dh parsing. Skipped per
  // module when the carve supplied full pages (header page included).
  const carvedBases = new Set(
    (kernel.carvedModules ?? []).map((m) => m.base.toString(16)));
  for (const m of world.modules) {
    if (!m.headerHex || !m.base) continue;
    if (carvedBases.has(BigInt(m.base).toString(16))) continue;
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
  kernel.materializeModuleRange(0xfffff8055a000000n, 0x8000);

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
        // KTHREAD.ApcState.Process -> owner (EDR cross-ref, lessons m1.l0/m1.l2)
        try {
          const apcOff = BigInt(t.offsetOf("_KTHREAD", "ApcState"));
          mem.w64(th + apcOff, owner);
        } catch { /* build without KTHREAD.ApcState */ }
      } catch { /* build without thread-list fields */ }
    }
  }

  seedDumpWorldThreads(kernel, tables);
}

/**
 * Materialize resident _ETHREAD images for the dump-overlay world.
 *
 * The authentic dump lists every process's threads through
 * _EPROCESS.ThreadListHead, but the pages holding those _ETHREADs are almost
 * never part of the carved snapshot — !process 0 7 used to answer with a wall
 * of "(thread image not resident)" stubs. Real _ETHREADs live in non-paged
 * pool and kd always shows full THREAD lines, so we synthesize the missing
 * images IN PLACE: each authentic ring pointer gets a readable _ETHREAD at
 * that very address (CLIENT_ID, Teb, Win32Thread, ApcState->owner), keeping
 * the dumped list topology intact. Processes whose ring is empty or
 * self-looped (the lab fixtures) get one freshly allocated thread instead.
 */
function seedDumpWorldThreads(kernel, tables) {
  const mem = kernel.mem;
  const t = tables;
  let cidOff, tleOff, tlhOff;
  try {
    cidOff = BigInt(t.offsetOf("_ETHREAD", "Cid"));
    tleOff = BigInt(t.offsetOf("_ETHREAD", "ThreadListEntry"));
    tlhOff = BigInt(t.offsetOf("_EPROCESS", "ThreadListHead"));
  } catch { return; } // build lacks basic thread fields — no seeding
  const opt = (type, field) => {
    try { return BigInt(t.offsetOf(type, field)); } catch { return null; }
  };
  const wssaOff = opt("_ETHREAD", "Win32StartAddress");
  const startOff = opt("_ETHREAD", "StartAddress");
  const tebOff = opt("_KTHREAD", "Teb");
  const w32Off = opt("_KTHREAD", "Win32Thread");
  const stateOff = opt("_KTHREAD", "State");
  const apcOff = kernel.apcStateOffset() !== null
    ? BigInt(kernel.apcStateOffset()) : null;

  const ethreadSize = t.has("_ETHREAD")
    ? BigInt(Number(t.sizeOf("_ETHREAD"))) : 0x600n;
  const align16 = (v) => (v + 15n) & ~15n;
  const canRead = typeof mem.canRead === "function"
    ? (a, n) => mem.canRead(a, n) : () => true;

  // GUI-ish processes get a non-NULL Win32Thread; services legitimately read 0
  const GUI_PROCS = new Set([
    "csrss.exe", "winlogon.exe", "dwm.exe", "explorer.exe", "sihost.exe",
    "ctfmon.exe", "fontdrvhost.ex", "TextInputHost.", "RuntimeBroker.",
    "SearchApp.exe", "SearchIndexer.", "StartMenuExper", "msedge.exe",
    "LogUI.exe", "LogonUI.exe",
  ]);

  // TID allocator: unique multiples of 4, skipping anything already visible
  const usedTids = new Set();
  for (const p of kernel.listProcesses()) {
    let cur = mem.u64(p.eprocess + tlhOff);
    const head = p.eprocess + tlhOff;
    for (let s = 0; cur && cur !== head && s < 64; s++) {
      if (!canRead(cur, 16)) break;
      try { usedTids.add(mem.u64(cur - tleOff + cidOff + 8n)); } catch { break; }
      const next = mem.u64(cur);
      if (!next || next === cur) break;
      cur = next;
    }
  }
  let nextTid = 0x1000n;
  const allocTid = () => {
    while (usedTids.has(nextTid)) nextTid += 4n;
    usedTids.add(nextTid);
    return nextTid;
  };

  /** Stamp a plausible thread image into [base, base+ethreadSize). */
  const stampThread = (base, proc, tid, isGui) => {
    mem.w64(base + cidOff, proc.pid);            // CLIENT_ID.UniqueProcess
    mem.w64(base + cidOff + 8n, tid);           // CLIENT_ID.UniqueThread
    if (stateOff !== null) mem.w8(base + stateOff, 5);   // Waiting
    if (tebOff !== null) {
      // deterministic user-mode Teb: unique per TID, plausible Win10 range
      mem.w64(base + tebOff, 0x000000e400000000n + tid * 0x100000n);
    }
    if (w32Off !== null) {
      mem.w64(base + w32Off,
        isGui ? 0xffffbe0100010000n + tid * 0x1000n : 0n);
    }
    // start addresses: kernel workers start in System range, user procs in
    // a plausible PEB-backedImage range
    const start = proc.pid === 4n
      ? 0xfffff8052b850000n + (tid & 0xffffn) * 0x10n
      : 0x00007ff600010000n + (tid & 0xffffn) * 0x1000n;
    if (startOff !== null) mem.w64(base + startOff, start);
    if (wssaOff !== null) mem.w64(base + wssaOff, start);
    if (apcOff !== null) mem.w64(base + apcOff, proc.eprocess);
  };

  // fresh-thread arena for processes with no enumerable ring at all
  let freshCursor = 0xffffa40bc9e76000n;

  for (const p of kernel.listProcesses()) {
    const head = p.eprocess + tlhOff;
    let cur = mem.u64(head);
    if (!cur || cur === head) {
      // empty/self-looped ring (fixtures): allocate one resident thread
      const base = align16(freshCursor);
      freshCursor = base + ethreadSize;
      const entry = base + tleOff;
      mem.w64(head, entry);
      mem.w64(head + 8n, entry);
      mem.w64(entry, head);
      mem.w64(entry + 8n, head);
      stampThread(base, p, allocTid(), GUI_PROCS.has(p.name));
      try {
        mem.w32(p.eprocess + BigInt(t.offsetOf("_EPROCESS", "ActiveThreads")), 1);
      } catch { /* counter optional */ }
      continue;
    }
    // materialize images for pointers whose pages the dump never carried
    const seen = new Set();
    for (let s = 0; cur && cur !== head && s < 128; s++) {
      if (seen.has(cur)) break;
      seen.add(cur);
      if (!canRead(cur - tleOff, Number(ethreadSize))) {
        stampThread(cur - tleOff, p, allocTid(), GUI_PROCS.has(p.name));
      }
      const next = mem.u64(cur);
      if (!next || next === cur) break;
      cur = next;
    }
  }

  // The dump rebuild relocated every EPROCESS — re-point the seeded
  // cross-process handle references at the new addresses (kfsample→kftarget
  // must survive as the row-#3 cross-check the labs teach).
  kernel.seedHandleRefs?.();
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
    secret: "kf-manual-map-master",
    runs: 0,
  };

  // make the loader visible to `lm` (payload appears only once mapped+run)
  kernel.loadedModules.push({
    base: LOADER_BASE, sizeOfImage: 0x8000, name: "kfloader.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfloader.sys", lab: true,
  });
  kernel.materializeModuleRange(LOADER_BASE, 0x8000);
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

/**
 * IRQL/DPC lab world: same base world plus kfdpc.sys — a misbehaving driver
 * whose init raised the IRQL and never lowered it, stranding one DPC in the
 * per-CPU queue. Student inspects (!irql, !dpcs), repairs (!irql 2) and
 * drains (!dpcdrain) to release the payload secret.
 */
function setupIrqlDpc(kernel) {
  const KFDPC_BASE = 0xfffff8055a400000n;
  const DPC_ROUTINE = KFDPC_BASE + 0x1400n;   // DeferredRoutine target
  const DPC_STRUCT = KFDPC_BASE + 0x2000n;

  // the driver left the processor pinned at the top software band
  kernel.currentIrql = 15;

  // stranded DPC: initialized but never drained because nothing below can run
  kernel.queueDpc(DPC_STRUCT, DPC_ROUTINE, 0n);

  // searchable evidence page
  kernel.mem.writeAnsi(KFDPC_BASE + 0x3000n,
    "kfdpc: deferred routine parked at DISPATCH pending drain");

  // payoff once the queue finally drains
  kernel.onDpcDrain = () => {
    kernel.dbgLog.push("kfdpc: deferred routine ran at DISPATCH_LEVEL");
    kernel.dbgLog.push("kfdpc: secret=kf-dpc-drain-ok");
  };

  kernel.loadedModules.push({
    base: KFDPC_BASE, sizeOfImage: 0x8000, name: "kfdpc.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfdpc.sys", lab: true,
  });
  kernel.materializeModuleRange(KFDPC_BASE, 0x8000);
}

scenarios["irql-dpc"] = {
  title: "irql-dpc — pinned IRQL with a stranded DPC",
  description:
    "Boots the 22H2 world with kfdpc.sys loaded. The CPU sits stuck above " +
    "DISPATCH_LEVEL and one DPC never drains. Inspect with !irql / !dpcs, " +
    "lower the level, release with !dpcdrain.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupIrqlDpc(session.kernel);
    session.kind = "irql-dpc";
    return session;
  },
};

/**
 * IRQL/DPC attack workshop world (m2.l3 / m2.l4): a healthy DISPATCH-level
 * machine running kvmdrv.sys — a benign driver with one queued DPC and one
 * periodic timer-DPC, plus a protected canary page for the integrity scan.
 * Student-compiled attack drivers tamper with this world; defender sensors
 * watch it. `hvci` turns on the VBS analog: clearing CR0.WP bugchecks 0x109.
 *
 * Deterministic layout (catalog.mjs header tracks these anchors):
 *   KFWARZ_BASE      0xfffff8055a700000   kvmdrv.sys image base
 *   VICTIM_DPC       base + 0x1000        KDPC struct ('DPCk' @+0, routine @+8)
 *   VICTIM_ROUTINE   base + 0x1400        heartbeat DeferredRoutine
 *   TIMER_STRUCT     base + 0x1800        KTIMER for the periodic heartbeat
 *   CANARY_PAGE      base + 0x2000        protected-range canary (64 bytes)
 */
export const KFWARZ_BASE = 0xfffff8055a700000n;
export const KFWARZ_VICTIM_DPC = KFWARZ_BASE + 0x1000n;
export const KFWARZ_VICTIM_ROUTINE = KFWARZ_BASE + 0x1400n;
export const KFWARZ_TIMER = KFWARZ_BASE + 0x1800n;
export const KFWARZ_CANARY = KFWARZ_BASE + 0x2000n;

function setupIrqlWarzone(kernel, { hvci = false } = {}) {
  // healthy core: PASSIVE-ish execution context at DISPATCH default
  kernel.currentIrql = 2;

  // victim module with a queued heartbeat DPC
  kernel.mem.writeAnsi(KFWARZ_VICTIM_DPC, "DPCk");
  kernel.mem.w64(KFWARZ_VICTIM_DPC + 8n, KFWARZ_VICTIM_ROUTINE);
  // real body for the heartbeat routine (mov eax,0x100; ret) so timer fires
  // and drains execute cleanly instead of hitting CC filler
  kernel.mem.write(KFWARZ_VICTIM_ROUTINE, new Uint8Array([0xb8, 0x00, 0x01, 0x00, 0x00, 0xc3]));
  kernel.mem.writeAnsi(KFWARZ_CANARY,
    "KFCANARY-kvmdrv-integrity-baseline-0123456789abcdef");
  kernel.protectRange(KFWARZ_CANARY, 0x40, "kvmdrv!CanaryPage");

  kernel.queueDpc(KFWARZ_VICTIM_DPC, KFWARZ_VICTIM_ROUTINE, 0n);

  // periodic timer bound to the same KDPC (due in 3 ticks, every 5 ticks)
  kernel.setTimer(KFWARZ_TIMER, (kernel.tickCount ?? 0n) + 3n, 5, KFWARZ_VICTIM_DPC);

  // payoff hooks: heartbeat prints on retire; hijack is called out loudly
  kernel.onDpcDrain = (d) => {
    if (!d || d.dpcVa !== KFWARZ_VICTIM_DPC) return;
    const live = kernel.liveDpcRoutine(d);
    if (live !== KFWARZ_VICTIM_ROUTINE) {
      kernel.dbgLog.push("kvmdrv: DeferredRoutine redirected before retirement — control-flow hijack");
      kernel.dbgLog.push("kvmdrv: secret=kf-hijack-seen");
    } else {
      kernel.dbgLog.push("kvmdrv: heartbeat DeferredRoutine retired normally");
    }
  };

  if (hvci) kernel.hvciMode = true;

  kernel.loadedModules.push({
    base: KFWARZ_BASE, sizeOfImage: 0x8000, name: "kvmdrv.sys",
    full: "\\SystemRoot\\system32\\drivers\\kvmdrv.sys", lab: true,
  });
  kernel.materializeModuleRange(KFWARZ_BASE, 0x8000);
}

scenarios["irql-attackers"] = {
  title: "irql-attackers — healthy world for the IRQL/DPC attack workshop",
  description:
    "Boots the 22H2 world with kvmdrv.sys: one queued DPC, one periodic " +
    "timer-DPC, a protected canary page. HVCI off — CR0.WP games work here. " +
    "Compile your attack driver, load it, then inspect with !irql -a, " +
    "!dpcs, !dpcstat, !pgscan and advance time with !dpcpump.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupIrqlWarzone(session.kernel, { hvci: false });
    session.kind = "irql-attackers";
    return session;
  },
};

scenarios["irql-hardened"] = {
  title: "irql-hardened — same world with the HVCI/VBS ceiling enforced",
  description:
    "Identical to irql-attackers but hvciMode is on: any CR0 write that " +
    "clears WP is intercepted with CRITICAL_STRUCTURE_CORRUPTION (0x109), " +
    "exactly like a real VBS box. Prove the WPOFFx64 technique dies here.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupIrqlWarzone(session.kernel, { hvci: true });
    session.kind = "irql-hardened";
    return session;
  },
};

/**
 * Inline-hook lab world: same base world plus kfhook.sys — a rootkit that
 * wrote an E9 detour over nt!PsLookupProcessByProcessId so lookups for one
 * PID come back STATUS_INVALID_PARAMETER. Student scans (!hookscan),
 * identifies the hidden PID (!hooktest probes), repairs with eb and proves
 * the lookup succeeds again.
 */
const KFHOOK_HIDDEN_PID = 888n;

function setupApiHook(kernel) {
  const API = "PsLookupProcessByProcessId";
  const KFHOOK_BASE = 0xfffff8055a600000n;
  const detourTarget = KFHOOK_BASE + 0x1000n;

  // gate behavior on LIVE prologue bytes: repairing with eb instantly unhooks
  const orig = kernel.apiImpls.get(API);
  kernel.defineApi(API, function (pid, outPtr) {
    if (kernel.isDetoured(API) && BigInt(pid) === KFHOOK_HIDDEN_PID) {
      kernel.dbgLog.push(`nt!${API}: hook suppressed pid ${KFHOOK_HIDDEN_PID}`);
      return 0xc000000bn; // STATUS_INVALID_PARAMETER
    }
    return orig(pid, outPtr);
  });

  kernel.installDetour(API, detourTarget);
  kernel.inlineHooks.push({ api: API, thunk: kernel.apiThunks.get(API), target: detourTarget, module: "kfhook.sys" });

  // deterministic .text grid for the static-analysis lab (m10): exactly
  // 0x800 / 16 = 128 recoverable function boundaries starting at detourTarget
  writeFunctionGrid(kernel.mem, detourTarget, 0x800);

  // searchable evidence on a dedicated page (kept out of the .text grid)
  kernel.mem.writeAnsi(detourTarget + 0x2000n,
    "kfhook: PsLookupProcessByProcessId detoured");
  kernel.mem.writeAnsi(detourTarget + 0x2080n,
    "kfhook: protected pid=888");

  kernel.loadedModules.push({
    base: KFHOOK_BASE, sizeOfImage: 0x8000, name: "kfhook.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfhook.sys", lab: true,
  });
  // whole image readable (db/s/u) and mapped in the emulator address space:
  // a detour target must be inspectable across its full extent, not just on
  // the pages evidence strings happened to touch
  kernel.materializeModuleRange(KFHOOK_BASE, 0x8000);
}

scenarios["api-hook"] = {
  title: "api-hook — detoured executive export",
  description:
    "Boots the 22H2 world with kfhook.sys loaded. One nt! export carries an " +
    "inline detour that hides one process from lookup. Scan with !hookscan, " +
    "probe with !hooktest, repair the prologue with eb.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupApiHook(session.kernel);
    session.kind = "api-hook";
    return session;
  },
};

/**
 * Authoring variant of the hook world: same nt! model that gates lookups on
 * live prologue bytes, but NO detour is installed and no kfhook.sys exists.
 * The student compiles their own detour writer against it (m3.l1.lab2).
 */
function setupApiHookBlank(kernel) {
  const API = "PsLookupProcessByProcessId";
  const KFHOOK_HIDDEN_PID = 888n;
  // gate behavior on LIVE prologue bytes: once the student's driver writes
  // an E9 over the thunk, PID 888 lookups start failing — exactly like the
  // pre-built kfhook.sys world, except here the bytes come from THEIR code
  const orig = kernel.apiImpls.get(API);
  kernel.defineApi(API, function (pid, outPtr) {
    if (kernel.isDetoured(API) && BigInt(pid) === KFHOOK_HIDDEN_PID) {
      kernel.dbgLog.push(`nt!${API}: hook suppressed pid ${KFHOOK_HIDDEN_PID}`);
      return 0xc000000bn;
    }
    return orig(pid, outPtr);
  });
}

scenarios["api-hook-blank"] = {
  title: "api-hook-blank — author your own detour",
  description:
    "A clean 22H2 world whose PsLookupProcessByProcessId suppresses pid 888 " +
    "whenever its prologue reads as detoured. Find the export's address, " +
    "compile a driver that writes an E9 over it, prove the suppression.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupApiHookBlank(session.kernel);
    session.kind = "api-hook-blank";
    return session;
  },
};

/**
 * m20 timing-lab world: api-hook-blank plus a fake mini-PatchGuard sweeping
 * FOUR protected regions on the lab clock. The taught race: install a hook
 * on a PG-protected export, do the read/write you needed, restore the
 * pristine bytes, and let a clean sweep re-arm — all before the next sweep
 * would have caught the tamper window. Stay hooked across a sweep and the
 * world bugchecks 0x109 like the real thing.
 */
function setupPatchguardHooks(kernel) {
  setupApiHookBlank(kernel);

  // protect the hookable export's thunk + neighbors + a code page
  const targets = [
    ["PsLookupProcessByProcessId", "nt!PsLookupProcessByProcessId"],
    ["DbgPrint", "nt!DbgPrint"],
    ["ExAllocatePoolWithTag", "nt!ExAllocatePoolWithTag"],
  ];
  for (const [api, label] of targets) {
    const thunk = kernel.apiThunks.get(api);
    if (thunk) kernel.protectRange(thunk, 8, label);
  }
  kernel.protectRange(0x30000a00n, 0x40, "kfprobe.sys .text");

  // deterministic clock: phase 2 means the first sweep lands on tick 6
  kernel.installPatchguard({ period: 4, phase: 2 });
}

scenarios["pg-hooks"] = {
  title: "pg-hooks — PatchGuard timing lab",
  description:
    "A mini-PatchGuard sweeps four protected regions every few ticks. Hook " +
    "PsLookupProcessByProcessId (eb an E9 over its prologue), prove it with " +
    "!hooktest, restore the pristine bytes, then !dpcpump past a sweep. Get " +
    "caught mid-hook and the world bugchecks 0x109.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupPatchguardHooks(session.kernel);
    session.kind = "pg-hooks";
    return session;
  },
};

/**
 * Pool-corruption lab world: same base world plus kfpooler.sys managing
 * three tag-KfPb blocks at deterministic VAs. An upstream overflow smashed
 * one trailing guard. Student audits (!poolfind), repairs with eb, verifies
 * (!poolverify) and captures the checksum secret.
 */
function setupPoolCorrupt(kernel) {
  const POOL_BASE = 0xfffff90000001000n;
  const STRIDE = 0x200n;
  const SIZE = 0x80;
  const TAG = "KfPb";

  const blocks = [0n, STRIDE, STRIDE * 2n].map((off) =>
    kernel.registerPoolBlock(POOL_BASE + off, SIZE, TAG));

  // upstream driver's out-of-bounds write landed here (first guard byte)
  kernel.mem.w8(blocks[1].addr + BigInt(SIZE), 0xde);

  let healed = false;
  kernel.onPoolHealed = () => {
    if (healed) return;
    healed = true;
    kernel.dbgLog.push("kfpooler: integrity pass complete — all guards intact");
    kernel.dbgLog.push("kfpooler: checksum=kf-pool-guard-ok");
  };

  kernel.mem.writeAnsi(POOL_BASE - 0x800n,
    "kfpooler: holding integrity pass until every KfPb guard reads A5");

  kernel.loadedModules.push({
    base: 0xfffff8055a700000n, sizeOfImage: 0x8000, name: "kfpooler.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfpooler.sys", lab: true,
  });
  kernel.materializeModuleRange(0xfffff8055a700000n, 0x8000);
}

scenarios["pool-corrupt"] = {
  title: "pool-corrupt — smashed pool guard forensics",
  description:
    "Boots the 22H2 world with kfpooler.sys loaded. One of its KfPb blocks " +
    "has a corrupted trailing guard from an upstream overflow. Audit with " +
    "!poolfind, repair with eb, confirm with !poolverify.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupPoolCorrupt(session.kernel);
    session.kind = "pool-corrupt";
    return session;
  },
};

/**
 * Sentinel v1 world (m1.l4 defense lab): the synthetic 22H2 world AFTER two
 * of module-1's attacks landed:
 *   1. kftarget.exe is DKOM-unlinked from ActiveProcessLinks — but its
 *      EPROCESS bytes are still carved-able in the eproc pool window.
 *   2. An unbacked executable page (manual-mapped code grid) sits in the
 *      pool region, covered by NO entry of the loaded-module list.
 * The KLDR chain is properly linked here so guest drivers can walk it the
 * way PsLoadedModuleList walkers do on real Windows.
 */
function setupSentinelM1(kernel, tables) {
  const mem = kernel.mem;

  // --- attack residue #1: DKOM unlink of kftarget.exe --------------------
  const linksOff = tables.offsetOf("_EPROCESS", "ActiveProcessLinks");
  const victim = kernel.findEprocessByPid(888n);
  if (victim) {
    const links = victim + linksOff;
    const flink = mem.u64(links);
    const blink = mem.u64(links + 8n);
    mem.w64(flink + 8n, blink); // next->Blink = prev
    mem.w64(blink, flink);      // prev->Flink = next
    // head self-heals around the hole; victim bytes stay in place for carving
    // give the student's carve sweep a dense, readable window around them
    const winStart = (BigInt(victim) & ~0xfffn) - 0x2000n;
    for (let p = winStart; p < winStart + 0x8000n; p += 0x1000n) {
      if (!mem.hasPage(p)) mem.write(p, new Uint8Array(0x1000));
    }
    kernel.sentinelCarve = { base: winStart, len: 0x8000 };
  }

  // --- attack residue #2: unbacked executable code in pool ---------------
  const GRID_VA = 0xfffff90000020000n; // outside every loaded-module range
  writeFunctionGrid(mem, GRID_VA, 0x400);

  // --- rebuild a properly linked KLDR chain any driver can walk ----------
  // (the synthetic world's list is field-only; dump worlds differ again —
  // so the defense lab always gets one canonical, linked list)
  const LDR_HEAD = 0x4ff00000n;
  const ENTRY_STRIDE = 0x100n;
  const ENTRY_BASE = 0x4fe00000n;
  const mods = (kernel.loadedModules ?? []).slice(0, 12);
  const ring = [];
  mods.forEach((m, i) => {
    const e = ENTRY_BASE + BigInt(i) * ENTRY_STRIDE;
    mem.w64(e, 0n);            // Flink patched below
    mem.w64(e + 8n, 0n);       // Blink patched below
    mem.w64(e + 0x30n, m.base);
    mem.w64(e + 0x38n, m.base + 0x1000n); // EntryPoint-ish
    mem.w64(e + 0x40n, BigInt(m.sizeOfImage ?? 0x10000));
    // FullDllName UNICODE_STRING {len, max, pad, buf} at +0x48
    const full = m.full ?? m.name ?? "module.sys";
    mem.w16(e + 0x48n, full.length * 2);
    mem.w16(e + 0x4an, full.length * 2 + 2);
    mem.w64(e + 0x50n, e + 0x80n);
    mem.writeUtf16(e + 0x80n, full, 120);
    ring.push(e);
  });
  for (const [i, e] of ring.entries()) {
    const prev = i === 0 ? LDR_HEAD : ring[i - 1];
    const next = i === ring.length - 1 ? LDR_HEAD : ring[i + 1];
    mem.w64(e, next);
    mem.w64(e + 8n, prev);
  }
  mem.w64(LDR_HEAD, ring[0] ?? LDR_HEAD);
  mem.w64(LDR_HEAD + 8n, ring[ring.length - 1] ?? LDR_HEAD);

  kernel.sentinel = {
    kind: "v1",
    ldrHead: LDR_HEAD,
    gridVa: GRID_VA,
    secret: "kf-sentinel-v1-ok",
  };
}

scenarios["sentinel-m1"] = {
  title: "sentinel-m1 — defend the module-1 world",
  description:
    "The world after module 1's attacks: kftarget.exe is unlinked and an " +
    "unbacked code page hides in pool. Compile KF-Sentinel v1 to catch both " +
    "from inside the kernel.",
  boot: async (io) => {
    const session = await bootDefault(io);
    setupSentinelM1(session.kernel, session.kernel.tables);
    session.kind = "sentinel-m1";
    return session;
  },
};

/**
 * windows-userland worlds (packages/sogen-runtime reference backend): a
 * headless Sauerbraten process under a sogen-style userspace emulator.
 * Sessions carry .world + .consoleEngine instead of .kernel — the pane
 * registry routes them to the userland console.
 */
scenarios["sauer-recon"] = {
  title: "sauer-recon — emulated game process",
  description:
    "Boots the headless Sauerbraten process model in the sogen runtime: " +
    "module list, heap entity array, live health state. Hunt the local " +
    "player with scans and !damage.",
  boot: async () => {
    const { createSogenSession } = await import("@kernelforge/sogen-runtime");
    const { world } = createSogenSession("sauer-recon");
    return {
      kind: "sauer-recon",
      sogen: true,
      world,
      consoleEngine: new (await import("@kernelforge/sogen-runtime")).SogenConsole(world),
    };
  },
};

scenarios["tbm-ac"] = {
  title: "tbm-ac — TryBypassMe-style ring-3 gauntlet",
  description:
    "Headless game process guarded by five classic user-mode AC vectors: " +
    "process/window blacklists, PEB debugger artifacts, XOR-encrypted stats " +
    "with shadow canaries, and a CRC-guarded AC thread. Spoof, clean and " +
    "!setstat your way to !godmode.",
  boot: async () => {
    const { createSogenSession } = await import("@kernelforge/sogen-runtime");
    const { world } = createSogenSession("tbm-ac");
    return {
      kind: "tbm-ac",
      sogen: true,
      world,
      consoleEngine: new (await import("@kernelforge/sogen-runtime")).SogenConsole(world),
    };
  },
};

scenarios["sauer-hook"] = {
  title: "sauer-hook — detoured input path",
  description:
    "Same game process; a cheat stub rewrote cl_sendinput's prologue into an " +
    "E9 trampoline to an aim-assist routine. hookscan it, resolve the target, " +
    "repair with eb and prove it with !inputtest.",
  boot: async () => {
    const { createSogenSession } = await import("@kernelforge/sogen-runtime");
    const { world } = createSogenSession("sauer-hook");
    return {
      kind: "sauer-hook",
      sogen: true,
      world,
      consoleEngine: new (await import("@kernelforge/sogen-runtime")).SogenConsole(world),
    };
  },
};

/**
 * linux-kernel worlds (packages/v86-lab): a real i386 buildroot guest under
 * v86. Boot requires the vendored bundle + image; without them the lab card
 * surfaces an instructive BundleMissingError instead of failing silently.
 */
async function bootLinuxWorld(worldId) {
  const { bootLinuxSession, fetchGuestImage } = await import("@kernelforge/v86-lab");
  const image = await fetchGuestImage();
  const session = await bootLinuxSession({ worldId, image });
  return { kind: worldId, linux: session };
}

scenarios["lkm-hello"] = {
  title: "lkm-hello — buildroot guest",
  description:
    "Boots the i386 Linux guest. Write your module in the editor, ship it into " +
    "the guest, insmod it and read dmesg over serial.",
  boot: () => bootLinuxWorld("lkm-hello"),
};

scenarios["syscall-trace"] = {
  title: "syscall-trace — kprobe world",
  description:
    "Same guest; /root/trigger fires execve storms. Register a kprobe and read " +
    "your handler's KFFLAG output from the serial stream.",
  boot: () => bootLinuxWorld("syscall-trace"),
};

scenarios["syscall-hook"] = {
  title: "syscall-hook — kfhooksy loaded",
  description:
    "kfhooksy.ko rewrote one sys_call_table entry to trampoline its own code. " +
    "Build the kallsyms cross-checker, print your KFFLAG, then call the " +
    "exported restore path and sweep clean.",
  boot: () => bootLinuxWorld("syscall-hook"),
};

scenarios["task-hide"] = {
  title: "task-hide — kfvillain loaded",
  description:
    "The villain rootkit hides decoy tasks during init. Measure nr_threads vs " +
    "/proc visibility, then make it confess through your detector.",
  boot: () => bootLinuxWorld("task-hide"),
};

/* ---------------------------------------------------------------------- */
/* Blog-labs worlds (catalog v4, m11-m16)                                   */
/* ---------------------------------------------------------------------- */

/**
 * m11 — x64 paging world. A decoy DTB is registered FIRST (EAC-style CR3
 * shuffle), so the lowest frame is a trap. kftarget.exe carries the real
 * tables with self-map index 0xF; one code-page PTE was corrupted with NX,
 * failing the driver's integrity pass until the student repairs it through
 * the self-map alias.
 */
export const PAGING_CONST = (() => {
  const ptsPhysBase = 0x3000000n;
  // raw VAs (low half; ptIndex/pdIndex/pdPtIndex/pml4Index all < 0x1ff)
  const CODE_VA = (0x9n << 39n) | (0x87n << 30n) | (0x65n << 21n) | (0x43n << 12n);
  return {
    ptsPhysBase,
    DECOY_SELFREF: 0x12,
    REAL_SELFREF: 0xf,
    CODE_VA,
    STACK_VA: (0xbn << 39n) | (2n << 30n) | (2n << 21n) | (0x44n << 12n),
    LARGE_VA: (0xcn << 39n) | (7n << 30n) | (0x33n << 21n),
    secret: "kf-pt-healed",
  };
})();

function setupPagingWalk(kernel) {
  const C = PAGING_CONST;
  const pts = new PageTableSpace(kernel, { physBase: C.ptsPhysBase });
  kernel.paging = pts;

  // decoy first: lowest frames belong to the shuffled decoy
  const decoy = pts.createProcess({ name: "decoy", pid: 664, selfRefIndex: C.DECOY_SELFREF });
  decoy.decoy = true;
  pts.mapPage(decoy, joinVa(8, 8, 8, 8, false), {});

  const target = pts.createProcess({
    name: "kftarget", pid: 888,
    eproc: kernel.processesByName.get("kftarget.exe"),
    selfRefIndex: C.REAL_SELFREF,
  });
  pts.mapPage(target, C.CODE_VA, { writable: true });
  pts.mapPage(target, C.STACK_VA, {});
  pts.mapPage(target, C.LARGE_VA, { size: 0x200000 });

  // corrupt the code page's PTE with NX through the alias window
  // (poke keeps physical frame + alias in sync)
  const pteRow = pts.translate(C.CODE_VA, target).rows.at(-1);
  const bad = kernel.mem.u64(pteRow.entryVa) | (1n << 63n);
  pts.poke64(pteRow.entryPa, bad);

  let paid = false;
  kernel.onVtopProbe = (va, res) => {
    if (va !== C.CODE_VA || !res.ok) return;
    const nx = (kernel.mem.u64(pteRow.entryPa) & (1n << 63n)) !== 0n;
    if (!nx && !paid) {
      paid = true;
      kernel.dbgLog.push("kfdriver: integrity pass complete — code page executable again");
      kernel.dbgLog.push(`kfdriver: secret=${C.secret}`);
    }
  };

  kernel.loadedModules.push({
    base: LOW_BASES.driver + 0x100000n, sizeOfImage: 0x8000,
    name: "kfmm.sys", full: "\\SystemRoot\\system32\\drivers\\kfmm.sys", lab: true,
  });
}

scenarios["paging-walk"] = {
  title: "paging-walk — four-level translation under a shuffled CR3",
  description:
    "Low-memory world with real PML4/PDPT/PD/PT pages. One process sports an " +
    "EAC-style shuffled self-map entry as a decoy. Walk the tables by hand " +
    "(!cr3/!pte/!vtop), repair the NX-smashed code PTE through the alias.",
  boot: async (io) => {
    const session = await bootLow(io);
    setupPagingWalk(session.kernel);
    session.kind = "paging-walk";
    return session;
  },
};

/**
 * m12 — EDR sensor world: kfalcon.sys registers a REAL Ex-style process-
 * creation callback (hand-assembled machine code executing on whichever
 * backend the pane selected — js and QEMU behave identically) that denies
 * kfimplant.exe via PS_CREATE_NOTIFY_INFO.CreationStatus.
 */
export const EDR_CONST = (() => {
  const KFALCON = LOW_BASES.driver + 0x100000n; // 0x50100000
  return {
    KFALCON,
    CALLBACK: KFALCON + 0x1000n,
    GRID: KFALCON + 0x1800n,
    BLOCKED_NAME: "kfimplant.exe",
    DENY_STATUS: 0xc0000022n, // STATUS_ACCESS_DENIED
    secret: "kf-edr-blindspot",
  };
})();

/** Assemble kfalcon's Ex callback (see packages/ntsim/test/notify.test.mjs). */
function assembleSensorCallback() {
  const enc = (s) => [...s].flatMap((c) => [c.charCodeAt(0), 0]);
  const q = (b) => [...b].reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
  const imm64 = (v) => { const o = []; let x = BigInt.asUintN(64, v); for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; } return o; };
  const bytes = []; const at = () => BigInt(bytes.length); const jz = []; const jnz = [];
  bytes.push(0x48, 0x85, 0xd2); jz.push(at()); bytes.push(0x74, 0x00);
  bytes.push(0x48, 0x8b, 0x4a, 0x28);                    // mov rcx,[rdx+28] US*
  bytes.push(0x66, 0x81, 0x39, 0x1a, 0x00); jnz.push(at()); bytes.push(0x75, 0x00); // cmp word[rcx],0x1A
  bytes.push(0x48, 0x8b, 0x41, 0x08);                    // mov rax,[rcx+8]
  bytes.push(0x48, 0xb9, ...imm64(q(enc("kfim")))); bytes.push(0x48, 0x39, 0x08); jnz.push(at()); bytes.push(0x75, 0x00);
  bytes.push(0x48, 0xb9, ...imm64(q(enc("plan")))); bytes.push(0x48, 0x39, 0x48, 0x08); jnz.push(at()); bytes.push(0x75, 0x00);
  bytes.push(0x44, 0x0f, 0xb7, 0x48, 0x10);              // movzx r9d,word[rax+10]
  bytes.push(0x66, 0x41, 0x81, 0xf9, 0x74, 0x00); jnz.push(at()); bytes.push(0x75, 0x00); // cmp r9w,'t'
  bytes.push(0xc7, 0x42, 0x40, 0x22, 0x00, 0x00, 0xc0);  // mov dword[rdx+40],ACCESS_DENIED
  const done = at(); bytes.push(0x31, 0xc0, 0xc3);
  for (const f of [...jz, ...jnz]) bytes[Number(f) + 1] = Number(done) - (Number(f) + 2);
  return Uint8Array.from(bytes);
}
// store instruction offset inside the assembled callback (for eb repair hints)
const SENSOR_STORE_OFFSET = (() => {
  const b = assembleSensorCallback();
  for (let i = 0; i < b.length - 6; i++) {
    if (b[i] === 0xc7 && b[i + 1] === 0x42 && b[i + 2] === 0x40) return i;
  }
  throw new Error("store not found");
})();

function setupEdrSensor(kernel) {
  const C = EDR_CONST;
  kernel.mem.write(C.CALLBACK, assembleSensorCallback());
  writeFunctionGrid(kernel.mem, C.GRID, 0x400);

  // register the sensor callback through the modeled API so kind-tracking
  // and !notifyroutines see exactly what a real driver registration does
  kernel.apiImpls.get("PsSetCreateProcessNotifyRoutineEx")(C.CALLBACK, 0);
  kernel.obCallbacks = [{
    callback: C.KFALCON + 0x2000n, altitude: "385201",
    masks: { process: 0xffedcfffn, thread: 0xffedf3ffn },
  }];

  let paid = false;
  const fire = kernel.fireProcessNotify.bind(kernel);
  kernel.fireProcessNotify = function (pid, imageName, opts = {}) {
    const res = fire(pid, imageName, opts);
    if (!res.blocked && imageName === C.BLOCKED_NAME && !paid) {
      paid = true;
      kernel.dbgLog.push("kfalcon: telemetry gap — implant spawn went unreported");
      kernel.dbgLog.push(`kfalcon: secret=${C.secret}`);
    }
    return res;
  };

  kernel.loadedModules.push({
    base: C.KFALCON, sizeOfImage: 0x8000, name: "kfalcon.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfalcon.sys", lab: true,
  });
}

scenarios["edr-sensor"] = {
  title: "edr-sensor — Falcon-style process-create blocking",
  description:
    "kfalcon.sys registers a kernel process-creation callback that denies " +
    "kfimplant.exe via CreationStatus. Enumerate callbacks, read the deny in " +
    "!notifytest, then blind the sensor by patching its name compare.",
  boot: async (io) => {
    const session = await bootLow(io);
    setupEdrSensor(session.kernel);
    session.kind = "edr-sensor";
    return session;
  },
};

/**
 * m13 — SSDT world: a KiServiceTable image over API thunks with one inline
 * detour on NtOpenProcess suppressing pid 888. Reuses pristine-snapshot
 * repair semantics; PatchGuard discussion ships in the lesson body.
 */
export const SSDT_CONST = (() => {
  const KFSSDT = LOW_BASES.driver + 0x200000n; // 0x5200000
  return {
    TABLE_BASE: LOW_BASES.kva + 0x200000n,
    KFSSDT,
    DETOUR_TARGET: KFSSDT + 0x1000n,
    HIDDEN_PID: 888n,
    secret: "kf-ssdt-clean",
  };
})();

function setupSsdtHook(kernel) {
  const C = SSDT_CONST;
  const st = new ServiceTable(kernel, { base: C.TABLE_BASE });

  const gate = (api, hiddenPid) => {
    const orig = kernel.apiImpls.get(api);
    kernel.defineApi(api, function (pid, ...rest) {
      if (kernel.isDetoured(api) && BigInt(pid) === hiddenPid) {
        kernel.dbgLog.push(`nt!${api}: hook suppressed pid ${hiddenPid}`);
        return 0xc0000022n; // STATUS_ACCESS_DENIED while hooked
      }
      return orig ? orig(pid, ...rest) : 0n;
    });
    return api;
  };

  st.add("NtCreateFile");
  st.add("NtQuerySystemInformation");
  const hookedIdx = st.add(gate("NtOpenProcess", C.HIDDEN_PID));
  st.add("NtAllocateVirtualMemory");
  st.add("NtWriteVirtualMemory");
  st.add("NtReadVirtualMemory");
  st.add("NtTerminateProcess");
  st.add("NtClose");
  kernel.serviceTable = st;

  kernel.installDetour("NtOpenProcess", C.DETOUR_TARGET);
  writeFunctionGrid(kernel.mem, C.KFSSDT + 0x1000n, 0x400);

  let paid = false;
  kernel.onSsdtScanned = (hooks) => {
    if (!hooks.length && !paid) {
      paid = true;
      kernel.dbgLog.push(`kfvillain: table clean — suppressed lookups released`);
      kernel.dbgLog.push(`kfvillain: secret=${C.secret}`);
    }
  };

  kernel.loadedModules.push({
    base: C.KFSSDT, sizeOfImage: 0x8000, name: "kfvillain.sys",
    full: "\\SystemRoot\\system32\\drivers\\kfvillain.sys", lab: true,
  });
  void hookedIdx;
}

scenarios["ssdt-hook"] = {
  title: "ssdt-hook — hooked system service dispatch",
  description:
    "A modeled KiServiceTable with one inline-detoured service hiding pid " +
    "888 from NtOpenProcess. Scan with !ssdt, resolve the detour target, " +
    "repair the prologue with eb, re-scan until clean.",
  boot: async (io) => {
    const session = await bootLow(io);
    setupSsdtHook(session.kernel);
    session.kind = "ssdt-hook";
    return session;
  },
};

export function getScenario(id) {
  const s = scenarios[id];
  if (!s) throw new Error(`unknown scenario "${id}"`);
  return s;
}

// ---------------------------------------------------------------------------
// SMM / SMRAM worlds (guest-paged; JsInterpreter engine by design — UC_HOOK_CODE
// is inert under CR0.PG in the wasm build, and these labs need thunk interception)
// ---------------------------------------------------------------------------


const SMM_SECRET = "KFSMM-EXFIL-2026";
export const SMM_LANDING_VA = 0xffffe00010000000n;
export const SMM_LANDING2_VA = 0xffffe00020000000n;

async function bootSmmWorld(io, { reloc = false } = {}) {
  // paged boot ignores the unicorn backend selector on purpose
  void io?.makeBackend;
  const loadTables = io.loadTables;
  const mem = new SparseMemory();
  const tables = await loadTables();
  // frameBase compensates for ntsim's upfront API-thunk-arena reservation
  // so PA-anchored constants (KUSER_SHARED_DATA @ 0x10d000) stay put
  const kernel = new NtKernel({ tables, paging: true, frameBase: 0xf1000n });
  kernel.bootstrap();

  const cs = new Chipset();
  const smm = new SmmEngine(kernel, cs);
  kernel.smm = smm;
  kernel.cs = cs;

  // SMRAM contents the labs care about
  kernel.rawMem.writeAnsi(DEFAULT_SMBASE + 0x1000n, SMM_SECRET);

  // firmware handler page starts as plain returns
  kernel.rawMem.write(DEFAULT_SMBASE + 0x8000n, new Uint8Array([0xc3]));

  kernel.smmLanding = SMM_LANDING_VA;
  if (reloc) {
    kernel.smmLanding2 = SMM_LANDING2_VA;
    kernel.smmRelocTarget = 0x7e400000n;
  }

  return { kind: reloc ? "smm-vault-reloc" : "smm-foundations", kernel, debugger: null };
}

scenarios["smm-foundations"] = {
  title: "smm-foundations — guest-paged world",
  description:
    "Boots ntsim with real x64 guest paging enabled: KUSER_SHARED_DATA dual-mapped, " +
    "EPROCESS DirectoryTableBase wired. Use !vtop/!pte/!cr to explore the MMU.",
  boot: (io) => bootSmmWorld(io),
};

scenarios["smm-vault"] = {
  title: "smm-vault — locked-away secrets behind an unlocked SMRAMC",
  description:
    "The firmware parks secrets in SMRAM and trusts D_LCK... which nobody set. " +
    "Open the vault from ring 0, patch the SMI handler, and make ring -2 hand you " +
    "the goods through port 0xB2.",
  boot: async (io) => {
    const session = await bootSmmWorld(io);
    session.kind = "smm-vault";
    return session;
  },
};

scenarios["smm-reloc"] = {
  title: "smm-reloc — SMBASE relocation persistence",
  description:
    "Same vulnerable platform. Relocate SMBASE from inside your patched SMI " +
    "handler so the next SMI enters code YOU planted below ring 0.",
  boot: async (io) => {
    const session = await bootSmmWorld(io, { reloc: true });
    session.kind = "smm-reloc";
    return session;
  },
};
