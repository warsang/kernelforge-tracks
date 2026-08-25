/**
 * Minimal WinDbg-flavored command console over a booted NtKernel.
 *
 * createCommands(kernel) is pure/DOM-free and returns the command map;
 * createDebugger(kernel, out) binds it to a console element.
 *
 * Every command handler shares one signature: (args: string[], w: writeFn).
 *
 * Field walks are driven entirely by the active build's Vergilius tables —
 * nothing here hardcodes struct layouts. Types absent from the scraped set
 * (_TOKEN, _CLIENT_ID as a standalone type, …) degrade to raw dumps or are
 * called out explicitly.
 */

import { irqlName } from "@kernelforge/ntsim/src/kernel.mjs";
import { decodePte, pteBitsString } from "@kernelforge/ntsim/src/paging.mjs";
import { ServiceTable } from "@kernelforge/ntsim/src/ssdt.mjs";
import { analyzeExtent, resolveRel32, decompile as ghidraDecompile } from "@kernelforge/ghidra-decompiler";

const FAST_REF_MASK = ~0xfn; // x64: low nibble holds reference count

/** Common NTSTATUS codes for symbolic display in lab output. */
const STATUS_NAMES = {
  0x00000000n: "STATUS_SUCCESS",
  0xc0000001n: "STATUS_NOT_IMPLEMENTED",
  0xc0000005n: "STATUS_ACCESS_VIOLATION",
  0xc000000bn: "STATUS_INVALID_PARAMETER",
  0xc000000dn: "STATUS_INVALID_PARAMETER",
  0xc0000022n: "STATUS_ACCESS_DENIED",
  0xc0000034n: "STATUS_OBJECT_NAME_NOT_FOUND",
  0xc00000bbn: "STATUS_NOT_SUPPORTED",
};

function statusName(v) {
  return STATUS_NAMES[BigInt.asUintN(32, BigInt(v))] ?? `0x${BigInt.asUintN(32, BigInt(v)).toString(16).padStart(8, "0")}`;
}

function hexBytes(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

/** Parse 0x-prefixed (or bare hex) address text into BigInt; null on garbage. */
function parseAddr(s) {
  try {
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9a-fA-F]{8,}$/.test(s)) return BigInt("0x" + s);
  } catch { /* fallthrough */ }
  return null;
}

function fmtAddr(v) {
  return "0x" + v.toString(16).padStart(16, "0");}

function fmtValue(bytes /* LE Uint8Array */) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

function byteSizeOf(base) {
  const b = String(base ?? "");
  if (/VOID\*|PTR$|\*$/.test(b)) return 8;
  if (/^(ULONG64|ULONGLONG|DWORD64|SIZE_T|long long)/i.test(b)) return 8;
  if (/^(ULONG|DWORD|unsigned long|^long$)/i.test(b)) return 4;
  return 8; // default pointer-ish
}

/** Fields eligible for the generic walker: pointers, scalars, fastrefs,
 *  and embedded _LIST_ENTRYs (decoded as Flink/Blink). Embedded structs,
 *  bitfields and arrays are skipped. */
function walkableFields(tables, typeName) {
  const info = tables.types.get(typeName);
  if (!info?.fieldsByName) return null;
  const out = [];
  for (const f of Object.values(info.fieldsByName)) {
    if (f.bitfield || f.array) continue;
    const base = String(f.base ?? "");
    const isPtr = /\*$/.test(base);            // e.g. "struct _KPCR*" — pointer
    const embedded = /^(struct|union)\b/.test(base) && !isPtr;
    if (embedded && base !== "struct _EX_FAST_REF" && base !== "struct _LIST_ENTRY") continue;
    out.push(f);
  }
  return out.sort((a, b) => a.offset - b.offset);
}

export function createCommands(kernel) {
  const mem = kernel.mem;
  const tables = kernel.tables;

  // x64 canonical: bits 63..47 identical -> user < 2^47 or kernel >= 2^64-2^47
  const TOP17 = 0xffff800000000000n;
  /** x64 canonicality + backed-by-memory check. Returns null or error text. */
  function memFault(va, len = 8) {
    let v = BigInt(va);
    if (v < 0n) v = BigInt.asUintN(64, v);
    const hi = v >> 47n;
    const canonical = hi === 0n || hi === 0x1ffffn;
    if (!canonical) return "non-canonical address";
    if (typeof mem.canRead === "function" && !mem.canRead(v, len)) return "unmapped";
    return null;
  }
  const memErr = (va, why) =>
    `Memory read error at 0x${BigInt.asUintN(64, BigInt(va)).toString(16).padStart(16, "0")} (${why})`;

  const resolveProcess = (token) => {
    let v;
    try { v = BigInt(token); } catch { return null; }
    if (v > 0xffffn) return v;
    return kernel.findEprocessByPid(v);
  };

  /**
   * Walk _EPROCESS.ThreadListHead (LIST_ENTRY of _ETHREAD.ThreadListEntry
   * nodes). Returns { addr, backed }[] — `backed` false marks pointers into
   * non-resident dump images we can still report but not dereference.
   * Guards: zero head (empty ring), self-loop, visited-set and step cap so
   * corrupt/unbacked chains always terminate.
   */
  const listThreads = (eproc, cap = 64) => {
    const out = [];
    let tlhOff, tleOff;
    try {
      tlhOff = BigInt(tables.offsetOf("_EPROCESS", "ThreadListHead"));
      tleOff = BigInt(tables.offsetOf("_ETHREAD", "ThreadListEntry"));
    } catch { return out; } // build lacks the fields — no enumeration
    const head = eproc + tlhOff;
    let cur = mem.u64(head);
    const seen = new Set();
    for (let steps = 0; cur && cur !== head && steps < cap * 2; steps++) {
      if (seen.has(cur)) break; // corrupt ring
      seen.add(cur);
      const entry = cur + tleOff;
      const backed = typeof mem.canRead !== "function" || mem.canRead(entry, 16);
      out.push({ addr: cur, backed });
      if (!backed) break;       // cannot follow a chain we cannot read
      const next = mem.u64(entry);
      if (!next || next === cur) break;
      cur = next;
    }
    return out;
  };

  /** One `THREAD <ethread>` output line per walked thread. */
  const threadLines = (eproc, w) => {
    const threads = listThreads(eproc);
    if (!threads.length) return 0;
    let cidOff = null, tleOff = null;
    try { cidOff = BigInt(tables.offsetOf("_ETHREAD", "Cid")); } catch { /* optional */ }
    try { tleOff = BigInt(tables.offsetOf("_ETHREAD", "ThreadListEntry")); } catch { /* optional */ }
    for (const t of threads) {
      // walkers carry _LIST_ENTRY addresses; WinDbg prints _ETHREAD bases
      const base = tleOff !== null ? t.addr - tleOff : t.addr;
      if (!t.backed) {
        w(`    THREAD ${fmtAddr(base)}  (thread image not resident — pointer from authentic list)`, "dim");
        continue;
      }
      let note = "";
      if (cidOff !== null) {
        try {
          const tid = mem.u64(base + cidOff + 8n); // CLIENT_ID.UniqueThread
          note = `  Tid: ${tid}`;
        } catch { /* optional */ }
      }
      w(`    THREAD ${fmtAddr(base)}${note}`);
    }
    return threads.length;
  };

  function* dumpStruct(typeName, addr, { max = 96 } = {}) {
    const fields = walkableFields(tables, typeName);
    if (!fields) {
      yield `dt: unknown type "${typeName}"`;
      yield `available: ${[...tables.types.keys()].sort().join(", ")}`;
      return;
    }
    yield `${typeName} @ ${fmtAddr(addr)}`;
    let shown = 0;
    for (const f of fields) {
      if (shown >= max) { yield `  ... (${fields.length - shown} more fields)`; break; }
      const fa = addr + BigInt(f.offset);
      const base = String(f.base ?? "");
      if (base === "struct _LIST_ENTRY") {
        yield `  +0x${f.offset.toString(16).padStart(3, "0")} ${f.name}.Flink : ${fmtAddr(mem.u64(fa))}`;
        shown++;
        if (shown >= max) break;
        yield `  +0x${(f.offset + 8).toString(16).padStart(3, "0")} ${f.name}.Blink : ${fmtAddr(mem.u64(fa + 8n))}`;
        shown++;
        continue;
      }
      const size = base === "struct _EX_FAST_REF" ? 8 : byteSizeOf(base);
      const raw = fmtValue(mem.read(fa, size));
      let extra = "";
      if (base === "struct _EX_FAST_REF") {
        const target = raw & FAST_REF_MASK;
        extra = target ? `  -> ${fmtAddr(target)} (fastref refs=${raw & 0xfn})` : "  -> NULL";
      } else if (/UniqueProcessId|InheritedFrom/.test(f.name)) {
        extra = `  (dec ${raw})`;
      }
      yield `  +0x${f.offset.toString(16).padStart(3, "0")} ${f.name.padEnd(26)} : ${fmtAddr(raw)}${extra}`;
      shown++;
    }
  }

  /** module+offset symbolization, e.g. ntoskrnl+0x2a1f0 */
  const sym = (va) => {
    for (const m of kernel.loadedModules ?? []) {
      const base = m.base;
      const end = base + BigInt(m.sizeOfImage ?? 0x100000);
      if (va >= base && va < end) {
        return `${m.name}+0x${(va - base).toString(16)}`;
      }
    }
    return null;
  };

  const kindNote = (k) => `ChildSP               RetAddr               Call Site`;

  const stack = (args, w, header) => {
    let sp;
    try { sp = kernel.cpu.kernel.cpu.regs.rsp; } catch { sp = undefined; }
    // fall back to PRCB.RspBase when kernel.cpu.regs.rsp is zero
    if (!sp && kernel.prcb) {
      try {
        sp = mem.u64(kernel.prcb + 0x28n);
        w("   ; ChildSP from PRCB.RspBase", "dim");
      } catch { sp = 0n; }
    }
    const ripSym = sym(kernel.cpu.regs.rip) ?? "<unknown>";
    w(header, "hdr");
    w(`00 ${fmtAddr(sp)}  ${fmtAddr(kernel.cpu.regs.rip)}  ${ripSym}`);
    // nearest-module annotation
    for (const m of kernel.loadedModules ?? []) {
      const base = m.base;
      if (kernel.cpu.regs.rsp >= base && kernel.cpu.regs.rsp < base + BigInt(m.sizeOfImage ?? 0x100000)) {
        w(`   ^ stack inside ${m.name} mapping`, "dim");
        break;
      }
    }
    w("   (single-frame model: no unwind metadata in emulated images)", "dim");
  };

  const commands = {
    help(args, w) {
      w("commands:");
      w("  lm                        loaded modules");
      w("  !process 0 [flags]        process list (flag bit2=0x4 walks threads)");
      w("  !process <addr|pid> [f]   detail _EPROCESS walk; 0x4 = ThreadListHead");
      w("  !eproc <addr|pid>         short summary");
      w("  !token <addr|pid>         decode Token EX_FAST_REF + raw dump");
      w("  !pcr [addr] / !kpcr       KPCR -> PRCB -> CurrentThread chain");
      w("  !ps                       alias for !process 0 0");
      w("  !pt                       current thread summary");
      w("  !prcb [addr]              _KPRCB field walk");
      w("  dt <Type>                 layout-only mode (symbol-only)");
      w("  dt <Type> <Field>         single field lookup");
      w("  !dh <module|base>         parse PE headers from memory");
      w("  s [-a] <start> <len> <pat> search memory (hex bytes or \"text\" w/ -a)");
      w("  !prcb [addr]              _KPRCB field walk");
      w("  dt <Type>                 layout-only mode (symbol-only)");
      w("  dt <Type> <Field>         single field lookup");
      w("  k | kp | kv | ks          stack (rip frame + module+offset; no unwind data)");
      w("  !analyze [-v]             modeled crash/state analysis");
      w("  sym <addr>                resolve module+offset");
      w("  !thread [addr]            _ETHREAD walk (default: PRCB.CurrentThread)");
      w("  dt <Type> [addr]          walk any loaded type");
      w("  eb <a> <b1> [b2...]       write bytes into mapped memory");
      w("  !mmstate / !mmrun         manual-map loader state / run (manual-map lab)");
      w("  !irql [n]                 current IRQL (name) / force a level (lab ext)");
      w("  !dpcs / !dpcdrain         DPC queue contents / drain at <= DISPATCH");
      w("  !hookscan [export]        diff live vs pristine export prologues");
      w("  !hooktest <exp> [args]    exercise a modeled nt! call path");
      w("  !poolfind <tag>           list tagged pool blocks + guard health");
      w("  !poolverify               sweep all allocation guards");
      w("  !funcs <module>           static function recovery over a module");
      w("  !decomp <addr>            decompile (needs vendored wasm; static info otherwise)");
      w("  !cr3 [proc]               page-table base + self-map index (paging labs)");
      w("  !pte <va> [proc]          full 4-level walk: entries, aliases, bits");
      w("  !vtop <va> [proc]         translate VA -> PA");
      w("  !notifyroutines           registered process/thread/image/Ob/Cm callbacks");
      w("  !notifytest <exe> [pid]   drive a process-create through the notify chain");
      w("  !ssdt [module]            system service table + inline-hook scan");
      w("  r | db <a> [n] | dq <a> [n] | clear");
    },
    "!help"(args, w) { commands.help(args, w); },
    clear(args, w, out) { out.innerHTML = "(cleared)\n"; },

    lm(args, w) {
      if (args.length && args[0] && /[a-zA-Z]/.test(args[0][0])) {
        w(`note: lm option '${args[0]}' is not modeled — showing standard list`, "dim");
      }
      const DIR_WORDS = new Set(["systemroot", "system32", "system", "drivers",
        "driverstore", "filerepository", "windows", "drivers"]);
      // name recovery: longest usable fragment wins; directory words skipped
      const used = new Map();
      for (const m of kernel.loadedModules ?? []) {
        const hint = (m.baseDllName || m.fullDllName || "");
        const frags = hint.split("\\").filter(Boolean)
          .filter((f) => !DIR_WORDS.has(f.toLowerCase()))
          .filter((f) => f.length >= 3);
        m._frag = frags.sort((a, b) => b.length - a.length)[0] ?? "";
      }
      w("start             end                 module name", "hdr");
      let repaired = 0;
      for (const m of kernel.loadedModules ?? []) {
        if (m.lab) {
          w(`${fmtAddr(m.base)} ${fmtAddr(m.base + BigInt(m.sizeOfImage ?? 0x100000))} ${m.name}` +
            "   <-- suspicious");
          continue;
        }
        let name = m.name;
        if (m.nameRepaired || /mod_[0-9a-f]+\.sys$/.test(name) ||
            /^(System3|System|system3|system|sy|syst|System32|driv|driver)$/.test(name)) {
          const frag = m._frag;
          name = frag ? frag + ".sys" : name;
          // dedupe repeats
          const n = (used.get(name) ?? 0);
          used.set(name, n + 1);
          if (n > 0 && frag) name = name.replace(/(\.[^.]+)$/, `_${n}$1`);
          repaired++;
        }
        m.name = name; // keep sym() consistent with the improved table
        const sizeOfImg = BigInt(m.sizeOfImage ?? 0x100000);
        w(`${fmtAddr(m.base)} ${fmtAddr(m.base + sizeOfImg)} ${name}`);
      }
      if (repaired) w(`(${repaired} names reconstructed from truncated dump strings)`, "dim");
    },

    "!process"(args, w) {
      if (!args.length || args[0] === "0") {
        const bits = Number(args[1] ?? 0);
        w("PROCESS fff...  SessionId: none  Cid: xxxx  Peb: 00000000  ParentCid: 0004", "hdr");
        const procs = kernel.listProcesses();
        for (const p of procs) {
          w(`PROCESS ${fmtAddr(p.eprocess)}  Cid: ${p.pid.toString().padStart(4, "0")}  ImageFileName: ${p.name}`);
          if (bits > 0) {
            try {
              const tokOff = tables.offsetOf("_EPROCESS", "Token");
              const raw = mem.u64(p.eprocess + tokOff);
              const threads = mem.u32(p.eprocess + tables.offsetOf("_EPROCESS", "ActiveThreads"));
              w(`    Token: ${fmtAddr(raw & FAST_REF_MASK)}  ActiveThreads: ${threads}`, "dim");
            } catch { /* optional fields */ }
          }
          if (bits & 4) threadLines(p.eprocess, w);
        }
        return;
      }
      // thread-address guard: route obviously-thread addresses to a hint
      if (kernel.currentThread && BigInt(args[0]) === kernel.currentThread) {
        return w(`!process: ${fmtAddr(kernel.currentThread)} is an _ETHREAD — use !thread`, "err");
      }
      if (kernel.threads?.[String(BigInt(args[0]))]) {
        return w(`!process: ${fmtAddr(BigInt(args[0]))} is an _ETHREAD — use !thread`, "err");
      }
      const eproc = resolveProcess(args[0]);
      if (!eproc) return w(`!process: no process for "${args[0]}"`, "err");
      // second arg is a WinDbg-style flag bitmask: bit1=0x2 wide walk,
      // bit2=0x4 enumerate ThreadListHead threads beneath this process
      const flags = Number(args[1] ?? 1);
      w(`Dumping _EPROCESS for "${args[0]}" (flags ${args[1] ?? "1"}):`, "hdr");
      for (const line of dumpStruct("_EPROCESS", eproc, { max: flags > 1 ? 200 : 140 })) w(line);
      if (flags & 4) threadLines(eproc, w);
    },

    "!eproc"(args, w) {
      const eproc = args[0] ? resolveProcess(args[0]) : null;
      if (!eproc) return w("usage: !eproc <addr|pid>", "err");
      for (const l of dumpStruct("_EPROCESS", eproc, { max: 12 })) w(l);
    },

    "!token"(args, w) {
      if (!args[0]) return w("usage: !token <TokenAddress|pid>", "err");
      let target = 0n;
      try {
        const v = BigInt(args[0]);
        if (v > 0xffffn) target = v & FAST_REF_MASK;
        else {
          const off = tables.offsetOf("_EPROCESS", "Token");
          const e = resolveProcess(args[0]);
          target = e ? mem.u64(e + off) & FAST_REF_MASK : 0n;
        }
      } catch { return w("!token: bad argument", "err"); }
      if (!target) return w("!token: NULL token", "dim");
      w(`TOKEN @ ${fmtAddr(target)}`, "hdr");
      w("  NOTE: no Vergilius _TOKEN table loaded yet — raw qwords only.", "dim");
      for (let i = 0; i < 8; i++) {
        w(`  +0x${(i * 8).toString(16).padStart(2, "0")} ${fmtAddr(target + BigInt(i * 8))}  ${fmtAddr(mem.u64(target + BigInt(i * 8)))}`);
      }
    },

    "!pcr"(args, w) {
      const kpcr = args[0] ? BigInt(args[0]) : kernel.kpcr;
      if (!kpcr) return w("!pcr: kernel not booted with a synthesized KPCR", "err");
      w("KPCR (x64: normally addressed via GS base — see note)", "hdr");
      for (const l of dumpStruct("_KPCR", kpcr, { max: 24 })) w(l);
      const prcb = mem.u64(kpcr + tables.offsetOf("_KPCR", "CurrentPrcb"));
      w("", "dim");
      w(`CurrentPrcb -> ${fmtAddr(prcb)}   try: dt _KPRCB ${fmtAddr(prcb)}`, "dim");
      const ctOff = (() => { try { return tables.offsetOf("_KPRCB", "CurrentThread"); } catch { return null; } })();
      if (ctOff !== null) {
        const ct = mem.u64(prcb + ctOff);
        w(`PRCB.CurrentThread -> ${fmtAddr(ct)}   try: dt _ETHREAD ${fmtAddr(ct)}`, "dim");
        w("  (cross-ref to its process via Cid.UniqueProcess — 22h2 tables do not", "dim");
        w("   expose ETHREAD.ThreadsProcess)", "dim");
      }
    },

    "!dh"(args, w) {
      let base;
      if (!args[0]) {
        base = kernel.kpcr ? (() => { try { return null; } catch { return null; } })() : null;
        // default: ntoskrnl (largest real module)
        const mods = kernel.loadedModules ?? [];
        const nt = mods.find((m) => m.name === "ntoskrnl.exe") ?? mods[0];
        base = nt?.base;
      } else {
        try { base = BigInt(args[0]); } catch {
          const m = (kernel.loadedModules ?? []).find((x) => x.name === args[0]);
          base = m?.base;
        }
      }
      if (!base) return w("usage: !dh <module|base>   (e.g. !dh ntoskrnl.exe)", "err");
      if (!mem.canRead(base, 0x400)) return w(memErr(base, "unmapped"), "err");

      if (mem.u16(base) !== 0x5a4d) return w(`!dh: no MZ at ${fmtAddr(base)}`, "err");
      const e_lfanew = mem.u32(BigInt(base) + 0x3cn);
      const pe = BigInt(base) + BigInt(e_lfanew);
      if (mem.u32(pe) !== 0x00004550) return w(`!dh: bad PE signature`, "err");
      const machine = mem.u16(BigInt(pe) + 4n);
      const numSections = mem.u16(BigInt(pe) + 6n);
      const sizeOpt = mem.u16(BigInt(pe) + 20n);
      const opt = BigInt(pe) + 24n;
      const magic = mem.u16(opt);
      const entryRva = mem.u32(opt + 16n);
      const rawBase = magic === 0x20b ? mem.u64(opt + 24n) : BigInt(mem.u32(opt + 28));
      const imageBase = BigInt(rawBase);
      w(`PE signature OK`, "hdr");
      w(`  machine            : 0x${machine.toString(16)}${machine === 0x8664 ? " (x64)" : ""}`);
      w(`  sections           : ${numSections}`);
      w(`  entry point        : ${fmtAddr(imageBase + BigInt(entryRva))}`);
      w(`  image base         : ${fmtAddr(imageBase)}`);
      const secTab = opt + BigInt(sizeOpt);
      w(`  section table      :`, "hdr");
      for (let i = 0; i < numSections; i++) {
        const so = secTab + BigInt(i * 40);
        const nmBytes = mem.read(so, 8);
        const nm = [...nmBytes].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "")).join("");
        const vsize = mem.u32(so + 8n), vaddr = mem.u32(so + 12n);
        w(`    ${nm.padEnd(8)} VirtSize:0x${vsize.toString(16).padStart(6, "0")} VirtAddr:0x${vaddr.toString(16).padStart(6, "0")}`);
      }
    },

    "!ps"(args, w) {
      commands["!process"](["0", "0"], w);
    },
    "!pt"(args, w) {
      // Walk threads of the current process
      const ct = kernel.currentThread ?? (kernel.kpcr ? (() => {
        try { return mem.u64(mem.u64(kernel.kpcr + tables.offsetOf("_KPCR", "CurrentPrcb")) +
          tables.offsetOf("_KPRCB", "CurrentThread")); } catch { return null; }
      })() : null);
      if (!ct) return w("!pt: no current thread", "err");
      w(`THREAD @ ${fmtAddr(ct)}`, "hdr");
      for (const line of dumpStruct("_ETHREAD", ct, { max: 24 })) w(line);
      w("  (use !thread <addr> for full walk)", "dim");
    },
    "!kpcr"(args, w) {
      commands["!pcr"](args, w);
    },
    "!prcb"(args, w) {
      const prcb = args[0] ? BigInt(args[0]) : kernel.prcb;
      if (!prcb) return w("!prcb: no PRCB (boot a scenario first)", "err");
      for (const l of dumpStruct("_KPRCB", prcb, { max: 40 })) w(l);
    },

    "!thread"(args, w) {
      const ctOff = (() => { try { return tables.offsetOf("_KPRCB", "CurrentThread"); } catch { return null; } })();
      let addr;
      try {
        addr = args[0] ? BigInt(args[0])
          : (kernel.kpcr && ctOff !== null
              ? mem.u64(mem.u64(kernel.kpcr + tables.offsetOf("_KPCR", "CurrentPrcb")) + ctOff)
              : 0n);
      } catch { return w("!thread: bad address", "err"); }
      if (!addr) return w("!thread: no current thread (boot a scenario first)", "err");
      for (const l of dumpStruct("_ETHREAD", addr, { max: 48 })) w(l);
    },

    dt(args, w) {
      let raw = args[0] ?? "";
      const clean = raw.replace(/^(?:nt|ntoskrnl|ntoskrnl\.exe)!/i, "");
      const tname = clean.startsWith("_") ? clean : `_${clean}`;
      const second = args[1] ?? null;
      const sym = kernel.symbolEngine;

      const knownType = !!tables.types.get(tname);
      if (!knownType) {
        return w(`dt: unknown type "${tname}"\navailable: ${[...tables.types.keys()].sort().join(", ")}`, "err");
      }

      // ---- 1. Layout-only mode (no second arg) ----
      if (!second) {
        const fields = walkableFields(tables, tname);
        w(`struct ${tname} (${fields.length} walkable fields, layout-only — pass an address or PID for a memory dump)`, "hdr");
        let shown = 0;
        for (const f of fields) {
          if (shown >= 48) { w(`  ... (${fields.length - shown} more)`); break; }
          const base = String(f.base ?? "");
          const sz = /\*$/.test(base) ? 8 : byteSizeOf(base);
          w(`  +0x${f.offset.toString(16).padStart(3, "0")} ${f.name.padEnd(28)} : ${base || "?"} (${sz} bytes)`);
          shown++;
        }
        return;
      }

      // ---- 2. Field-specific schema query (non-numeric second arg) ----
      // Try this BEFORE address/PID parsing — a field name like "ActiveProcessLinks"
      // would fail hex parsing but succeed as a field descriptor.
      if (!/^(0x)?[0-9]+$/i.test(second)) {
        if (sym) {
          const f = sym.getField(tname, second);
          if (f) {
            w(`${tname}.${second}`, "hdr");
            w(`  +0x${f.offset.toString(16).padStart(3, "0")} ${f.decl || second}`);
            w(`  offset=0x${f.offset.toString(16)} size=${f.size}`);
            return;
          }
          // not a field either → maybe it IS a hex address after all
        }
        // fall through to address parsing below
      }

      // ---- 3. Parse the value as BigInt (handles dec + hex) ----
      let val;
      try { val = BigInt(second); } catch { return w(`dt: bad address "${second}"`, "err"); }

      // ---- 4. PID resolution for process/thread types ----
      // Small integers (< 2^20 ≈ 1M) that match an active PID are resolved
      // via the kernel process table rather than dereferenced literally.
      if (/^_(?:EPROCESS|ETHREAD)$/.test(tname)) {
        if (val > 0n && val < 0x100000n) {
          const eproc = kernel.findEprocessByPid(val);
          if (eproc) {
            w(`Resolving pid ${val} -> _EPROCESS @ ${fmtAddr(eproc)}`, "dim");
            for (const line of dumpStruct(tname, eproc, { max: 96 })) w(line);
            return;
          }
          // small value but no matching PID — still treat as address
        }
      }

      // ---- 5. Literal address-dump mode with memory safety ----
      const totalSize = Math.max(
        ...walkableFields(tables, tname).map((f) => f.offset + 8));
      const why = memFault(val, totalSize);
      if (why) return w(memErr(val, why), "err");
      for (const line of dumpStruct(tname, val, { max: 96 })) w(line);
    },

    s(args, w) {
      // usage: s [-a] <startAddr> <len> <hex bytes | "ascii">
      let ascii = false;
      const a = [...args];
      if (a[0] === "-a") { ascii = true; a.shift(); }
      let start, len, pat = [];
      try {
        start = BigInt(a[0]);
        len = Number(a[1]);
        if (ascii) {
          const q = a.slice(2).join(" ").replace(/^"|"$/g, "");
          pat = [...q].map((ch) => ch.charCodeAt(0));
        } else {
          pat = a.slice(2).join("").match(/.{2}/g)?.map((x) => parseInt(x, 16)) ?? [];
        }
      } catch { return w('usage: s [-a] <start> <len> <hex | "text"> ', "err"); }
      if (!pat.length) return w("s: empty pattern", "err");
      if (start < 0n) start = BigInt.asUintN(64, start);
      const why = memFault(start, len);
      if (why) return w(memErr(start, why), "err");
      const hay = mem.read(start, len);
      let hits = 0;
      outer:
      for (let i = 0; i + pat.length <= hay.length; i++) {
        for (let j = 0; j < pat.length; j++) if (hay[i + j] !== pat[j]) continue outer;
        w(`Found ${fmtAddr(start + BigInt(i))}`); hits++;
        if (hits >= 32) { w("... (truncated)", "dim"); break; }
      }
      if (!hits) w("0 matches", "dim");
    },
    ks(args, w) { commands["kv"](args, w); },

    r(args, w) {
      const src = kernel.contextSource === "dump" ? "   ; context from dump" : "";
      for (const [k, v] of Object.entries(kernel.cpu.regs)) {
        const s = sym(v);
        w(`${k.padEnd(4)}=${fmtAddr(v)}${s ? `  ${s}` : ""}`);
      }
      if (src) w(src, "dim");
    },

    k(args, w) { stack(args, w, kindNote("k")); },
    kp(args, w) { stack(args, w, kindNote("kp") + "\n   (parameters unavailable — no unwind data modeled)"); },
    kv(args, w) { stack(args, w, kindNote("kv") + "\n   (frame sizes unavailable — no unwind data modeled)"); },

    "!analyze"(args, w) {
      const verbose = args.includes("-v");
      w("======================= ANALYSIS =======================", "hdr");
      if (kernel.bugcheck) {
        w(`BUGCHECK_CODE: 0x${kernel.bugcheck.code.toString(16)}`);
        w(`BUGCHECK_P1..P4: ${kernel.bugcheck.params.map((p) => "0x" + p.toString(16)).join(" ")}`);
      } else {
        w("No bugcheck recorded — machine state is live-modeled.", "dim");
      }
      const rip = kernel.cpu.regs.rip;
      const ripSym = sym(rip) ?? "<unknown module>";
      w(`CONTEXT:  rip=${fmtAddr(rip)} (${ripSym})`);
      w(`          rsp=${fmtAddr(kernel.cpu.regs.rsp)}`);
      const curEproc = (() => {
        try {
          const pidOff = tables.offsetOf("_EPROCESS", "UniqueProcessId");
          const cidOff = (() => { try { return tables.offsetOf("_ETHREAD", "Cid"); } catch { return null; } })();
          if (kernel.currentThread && cidOff !== null) {
            const pid = mem.u64(kernel.currentThread + cidOff);
            return kernel.findEprocessByPid(pid);
          }
        } catch { /* none */ }
        return null;
      })();
      if (curEproc) {
        const pid = mem.u64(curEproc + tables.offsetOf("_EPROCESS", "UniqueProcessId"));
        const nm = mem.readAnsi(curEproc + tables.offsetOf("_EPROCESS", "ImageFileName"), 15);
        w(`PROCESS:  ${nm} (pid ${pid}) @ ${fmtAddr(curEproc)}`);
      }
      if (verbose) {
        w(`IRQL:     ${kernel.currentIrql ?? "?"}`);
        w(`MODULES:  ${(kernel.loadedModules ?? []).length} loaded` +
          ((kernel.loadedModules ?? []).some((m) => m.real) ? " (real-dump set)" : ""));
        w(`THREADS:  CurrentThread=${fmtAddr(kernel.currentThread ?? 0n)}`);
        const tail = (kernel.dbgLog ?? []).slice(-5);
        if (tail.length) { w("--- recent DbgPrint ---", "hdr"); for (const l of tail) w("  " + l, "dim"); }
      }
      w("========================================================", "hdr");
    },

    sym(args, w) {
      try {
        const va = BigInt(args[0] ?? "0x0");
        w(sym(va) ?? `${fmtAddr(va)} <no module>`);
      } catch { w("usage: sym <address>", "err"); }
    },

    db(args, w) {
      let addr; try { addr = BigInt(args[0] ?? "0x0"); } catch { return w("db: bad address", "err"); }
      const len = Math.min(Number(args[1] ?? 128), 512);
      if (addr !== 0n) {
        const why = memFault(addr, len);
        if (why) return w(memErr(addr, why), "err");
      }
      const bytes = mem.read(addr, len);
      for (let row = 0; row < len; row += 16) {
        const chunk = [...bytes.slice(row, row + 16)];
        const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
        const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
        w(`${fmtAddr(addr + BigInt(row))}  ${hex.padEnd(47)}  |${ascii}|`);
      }
    },

    dq(args, w) {
      let addr; try { addr = BigInt(args[0] ?? "0x0"); } catch { return w("dq: bad address", "err"); }
      const count = Math.min(Number(args[1] ?? 8), 64);
      if (addr !== 0n) {
        const why = memFault(addr, count * 8);
        if (why) return w(memErr(addr, why), "err");
      }
      for (let i = 0; i < count; i++) {
        w(`${fmtAddr(addr + BigInt(i * 8))}  ${fmtAddr(mem.u64(addr + BigInt(i * 8)))}`);
      }
    },

    // WinDbg-style byte write into MAPPED memory only — we never materialize
    // new pages on write so typos can't fabricate phantom backing.
    eb(args, w) {
      if (args.length < 2) return w("usage: eb <addr> <byte> [bytes...]", "err");
      let addr;
      try { addr = BigInt(args[0]); } catch { return w("eb: bad address", "err"); }
      if (addr < 0n) addr = BigInt.asUintN(64, addr);
      const vals = [];
      for (const tok of args.slice(1)) {
        const v = parseInt(tok, 16);
        if (!(v >= 0 && v <= 255)) return w(`eb: bad byte "${tok}"`, "err");
        vals.push(v);
      }
      const why = memFault(addr, vals.length);
      if (why) return w(memErr(addr, why), "err");
      mem.write(addr, vals);
      w(`wrote ${vals.length} byte(s) at ${fmtAddr(addr)}: ` +
        vals.map((v) => v.toString(16).padStart(2, "0")).join(" "), "dim");
    },

    "!irql"(args, w) {
      if (!args[0]) {
        const lvl = kernel.currentIrql ?? 0;
        w(`IRQL: ${lvl} (${irqlName(lvl)})`, "hdr");
        if (lvl > 2) {
          w("  note: threads should never SIT here — drivers raise transiently", "warn");
        }
        w("  lab extension: '!irql <n>' forces a level (0..31)", "dim");
        return;
      }
      const n = Number(args[0]);
      if (!Number.isInteger(n) || n < 0 || n > 31) {
        return w("!irql: level must be an integer 0..31", "err");
      }
      const old = kernel.currentIrql ?? 0;
      kernel.currentIrql = n; // debugger force, not driver semantics
      kernel.dbgLog.push(`nt: (lab) IRQL forced ${old} -> ${n}`);
      w(`IRQL: ${old} -> ${n} (${irqlName(n)})`);
    },

    "!dpcs"(args, w) {
      const q = kernel.pendingDpcs ?? [];
      if (!q.length) return w("!dpcs: DPC queue is empty", "dim");
      w("DPC queue (per-CPU, drained at <= DISPATCH_LEVEL)", "hdr");
      w("  DPC               DeferredRoutine     Status", "hdr");
      for (const d of q) {
        const target = d.routine ? `${fmtAddr(d.routine)}${sym(d.routine) ? ` (${sym(d.routine)})` : ""}` : "NULL";
        w(`  ${fmtAddr(d.dpcVa)}  ${target}  ${d.drained ? "drained" : "QUEUED"}`,
          d.drained ? "dim" : "");
      }
      const stuck = q.filter((d) => !d.drained).length;
      if (stuck && (kernel.currentIrql ?? 0) > 2) {
        w(`  ${stuck} DPC(s) stranded: CPU pinned above DISPATCH_LEVEL`, "warn");
      }
    },

    "!dpcdrain"(args, w) {
      const queued = (kernel.pendingDpcs ?? []).filter((d) => !d.drained);
      if (!queued.length) return w("!dpcdrain: nothing queued", "dim");
      if ((kernel.currentIrql ?? 0) > 2) {
        w(`!dpcdrain: cannot request a DPC interrupt at IRQL ${kernel.currentIrql}`, "err");
        w("hint: lower the level first ('!irql 2')", "dim");
        return;
      }
      const fired = kernel.drainDpcs();
      w(`drained ${fired.length} DPC(s):`, "hdr");
      for (const d of fired) w(`  ${fmtAddr(d.dpcVa)} -> ${sym(d.routine) ?? fmtAddr(d.routine)}`);
      const tail = (kernel.dbgLog ?? []).slice(-3);
      if (tail.length) { w("--- recent DbgPrint ---", "hdr"); for (const l of tail) w("  " + l); }
    },

    "!hookscan"(args, w) {
      // optional filter: tolerate nt!-prefixed export names
      const want = args[0] ? args[0].replace(/^nt!|ntoskrnl\.exe!/i, "") : null;
      const diffs = [];
      for (const [name, thunk] of kernel.apiThunks ?? []) {
        if (want && name.toLowerCase() !== want.toLowerCase()) continue;
        const pristine = kernel.pristineThunks.get(name);
        if (!pristine) continue;
        const live = mem.read(thunk, pristine.length);
        if (live.some((b, i) => b !== pristine[i])) diffs.push({ name, thunk, live, pristine });
      }
      if (!diffs.length) {
        w(want ? `${want}: prologue matches pristine bytes` : "no detoured exports found", "hdr");
        return;
      }
      w("DETECTED INLINE HOOKS:", "hdr");
      for (const d of diffs) {
        const hook = (kernel.inlineHooks ?? []).find((x) => x.api === d.name);
        const target = hook ? `${fmtAddr(hook.target)}${sym(hook.target) ? ` (${sym(hook.target)})` : ""}` : "<unknown>";
        w(`  ${d.name}`, "hdr");
        w(`    thunk   : ${fmtAddr(d.thunk)}`);
        w(`    live    : ${hexBytes(d.live.slice(0, 5))}`);
        w(`    pristine: ${hexBytes(d.pristine.slice(0, 5))}`);
        w(`    detour  : -> ${target}  [${hook?.module ?? "?"}]`, "warn");
        w(`    repair  : eb ${fmtAddr(d.thunk)} ${hexBytes(d.pristine.slice(0, 1))}`, "dim");
      }
    },

    "!hooktest"(args, w) {
      if (!args[0]) {
        return w("usage: !hooktest <Export> [args...]   e.g. !hooktest PsLookupProcessByProcessId 666", "err");
      }
      const name = args[0].replace(/^nt!|ntoskrnl\.exe!/i, "");
      const impl = kernel.apiImpls.get(name);
      const thunk = kernel.apiThunks.get(name);
      if (!impl || !thunk) return w(`!hooktest: unknown export "${name}"`, "err");

      // lookup-style exports: last arg is a PID; provide an out-pointer scratch
      const isLookup = /(ByProcessId|ByThreadId)$/i.test(name);
      let callArgs = args.slice(1);
      let scratch = null;
      if (isLookup) {
        scratch = kernel.allocPool(8);
        callArgs = [...callArgs, scratch];
      }
      try {
        const vals = callArgs.map((t) => /^\d+$/.test(t) ? BigInt(t)
          : t.startsWith("0x") ? BigInt(t) : t);
        if (vals.some((v) => typeof v === "string")) {
          return w("!hooktest: numeric arguments only in this model", "err");
        }
        const ret = impl(...vals);
        const status = BigInt.asUintN(32, BigInt(ret));
        const hookNote = kernel.isDetoured(name) ? "  [PROLOGUE DETOURED]" : "";
        w(`${name}(${callArgs.map((a) => a.toString()).join(", ")}) -> ${statusName(status)}${hookNote}`,
          status === 0n ? "good" : "");
        if (isLookup && status === 0n && scratch) {
          const resolved = mem.u64(scratch);
          w(`  *out = ${resolved ? fmtAddr(resolved) + (sym(resolved) ? ` (${sym(resolved)})` : "") : "NULL"}`);
        }
      } catch (e) {
        w(`!hooktest: ${e.message}`, "err");
      }
    },

    "!poolfind"(args, w) {
      if (!args[0]) return w("usage: !poolfind <tag>   e.g. !poolfind KfPb", "err");
      const tag = args[0].toLowerCase();
      const blocks = (kernel.poolAllocs ?? []).filter((a) => a.tag.toLowerCase() === tag);
      if (!blocks.length) return w(`!poolfind: no blocks tagged "${args[0]}"`, "dim");
      w(`pool blocks tagged '${args[0]}':`, "hdr");
      let corrupted = 0;
      for (const b of blocks) {
        let guard = "intact";
        for (let i = 0; i < 16; i++) {
          const got = mem.u8(b.addr + BigInt(b.size) + BigInt(i));
          if (got !== 0xa5) {
            guard = `CORRUPTED at guard[${i}] (got 0x${got.toString(16)}, expected 0xa5)`;
            corrupted++;
            break;
          }
        }
        w(`  ${fmtAddr(b.addr)}  size=0x${b.size.toString(16)}  ${b.freed ? "freed" : "active"}  guard: ${guard}`,
          guard === "intact" ? "" : "warn");
      }
      if (corrupted) {
        w(`repair: rewrite the smashed guard with 'eb' (expected pattern: ` +
          `a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5), then !poolverify`, "dim");
      } else {
        w("all guards read A5 patterns", "good");
      }
    },

    "!poolverify"(args, w) {
      const bad = kernel.verifyGuards?.() ?? [];
      if (!bad.length) {
        w("!poolverify: all allocation guards intact", "good");
        kernel.onPoolHealed?.();
        return;
      }
      w(`!poolverify: ${bad.length} corrupted allocation(s):`, "err");
      for (const b of bad) {
        const got = mem.u8(b.addr + BigInt(b.size));
        w(`  ${fmtAddr(b.addr)} tag='${b.tag}' size=0x${b.size.toString(16)} ` +
          `guard[0]=0x${got.toString(16)} (expected 0xa5)`, "warn");
      }
      w("hint: !poolfind <tag> shows expected bytes; repair with 'eb'", "dim");
    },

    "!funcs"(args, w) {
      // static function recovery over a module extent (ghidra-decompiler)
      if (!args[0]) { w("usage: !funcs <module>", "err"); return; }
      const want = args[0].toLowerCase().replace(/\.sys$/, "");
      const mod = (kernel.loadedModules ?? []).find((m) =>
        m.name.toLowerCase().replace(/\.sys$/, "") === want);
      if (!mod) { w(`module '${args[0]}' not found — try lm`, "err"); return; }
      const size = Number(mod.sizeOfImage ?? 0);
      const res = analyzeExtent(mem, BigInt(mod.base), Math.min(size, 0x10000));
      if (!res.count) {
        w(`${mod.name}: no code pages materialized for analysis`, "dim");
        return;
      }
      w(`${mod.name} — ${res.count} function(s) recovered:`, "hdr");
      for (const f of res.funcs.slice(0, 32)) {
        const rel = res.rel32.find((r) => r.site === f.start);
        w(`  ${fmtAddr(f.start)}${rel ? `  E9 -> ${fmtAddr(rel.target)}` : ""}`);
      }
      if (res.count > 32) w(`  ... ${res.count - 32} more`);
      if (res.rel32.length) {
        w("rel32 transfer sites at boundary edges:", "hdr");
        for (const r of res.rel32) w(`  ${fmtAddr(r.site)} -> ${fmtAddr(r.target)}`, "warn");
      }
    },

    "!decomp"(args, w) {
      // pseudocode via the vendored Ghidra native decompiler; loud degrade
      const addr = args[0] ? parseAddr(args[0]) : null;
      if (addr === null) { w("usage: !decomp <addr>  (static !funcs works without the wasm)", "err"); return; }
      ghidraDecompile(new Uint8Array(0), addr, addr)
        .then(({ c }) => w(c.split("\n").slice(0, 40).join("\n"), "code"))
        .catch((e) => {
          w(`!decomp: ${e.message}`, "warn");
          const t = resolveRel32(mem, addr);
          if (t !== null) w(`static: ${fmtAddr(addr)} is a rel32 transfer to ${fmtAddr(t)}`, "dim");
        });
    },

    "!mmstate"(args, w) {
      const mm = kernel.manualMap;
      if (!mm) return w("!mmstate: no manual-map loader booted (boot the manual-map lab)", "err");
      w("kfloader.sys manual-mapping state", "hdr");
      w(`  payload image : ${fmtAddr(mm.payloadBase)} (mmpayload.sys)`);
      w(`  loader base   : ${fmtAddr(mm.loaderBase)}`);
      const flag = mem.u8(mm.resolveFlag);
      w(`  g_ResolveImports @ ${fmtAddr(mm.resolveFlag)} = ${flag} ` +
        `(${flag ? "imports will be resolved" : "STUBBED — IAT left unmapped"})`,
        flag ? "" : "warn");
      mm.imports.forEach((imp, i) => {
        const slot = mem.u64(mm.iatBase + BigInt(i * 8));
        w(`  IAT[${i}] ${imp.padEnd(26)} : ${slot ? fmtAddr(slot) : "0000000000000000  (unresolved)"}`);
      });
      w(`  map attempts  : ${mm.runs}`);
    },

    "!mmrun"(args, w) {
      const mm = kernel.manualMap;
      if (!mm) return w("!mmrun: no manual-map loader booted (boot the manual-map lab)", "err");
      mm.runs++;
      if (!mem.u8(mm.resolveFlag)) {
        w("kfloader: mapping mmpayload.sys sections...", "dim");
        w("kfloader: import resolution is STUBBED — IAT left zeroed", "err");
        w("kfloader: payload DriverEntry skipped (first import call would fault)", "err");
        w("hint: inspect !mmstate, repair the loader with 'eb', retry !mmrun", "dim");
        kernel.dbgLog.push("kfloader: failed to resolve imports for mmpayload.sys");
        return;
      }
      mm.imports.forEach((_, i) => mem.w64(mm.iatBase + BigInt(i * 8), mm.thunks[i]));
      w(`kfloader: resolved ${mm.imports.length} import(s) against nt!`);
      for (const [i, imp] of mm.imports.entries()) {
        w(`  IAT[${i}] ${imp.padEnd(26)} -> ${fmtAddr(mm.thunks[i])}`, "dim");
      }
      w("kfloader: transferring control to mmpayload.sys!DriverEntry...");
      kernel.dbgLog.push("mmpayload: DriverEntry entered (manually mapped, imports resolved)");
      kernel.dbgLog.push(`mmpayload: secret=${mm.secret}`);
      w("--- recent DbgPrint ---", "hdr");
      for (const l of kernel.dbgLog.slice(-2)) w("  " + l);
      w("(captured in the DbgPrint buffer — see !analyze -v)", "dim");
      if (!kernel.loadedModules.some((m) => m.name === "mmpayload.sys")) {
        kernel.loadedModules.push({
          base: mm.payloadBase, sizeOfImage: 0x4000, name: "mmpayload.sys",
          full: "\\SystemRoot\\system32\\mmpayload.sys",
        });
      }
    },

    "!cr3"(args, w) {
      const pts = kernel.paging;
      if (!pts) return w("!cr3: no paging world booted (this lab has no page tables)", "err");
      const token = args[0];
      let proc = null;
      if (token) {
        proc = pts.findProcess(token.replace(/\.sys$/, ""));
        if (!proc) return w(`!cr3: no paging record for '${token}'`, "err");
      } else {
        proc = [...pts.processes.values()].find((p) => !p.decoy) ??
          [...pts.processes.values()][0];
        if (!proc) return w("!cr3: paging world is empty", "err");
      }
      w(`process ${proc.name}${proc.pid ? ` (pid ${proc.pid})` : ""}`, "hdr");
      w(`  DirectoryTableBase  : 0x${proc.dtb.toString(16).padStart(16, "0")}` +
        `  (PFN 0x${(proc.dtb >> 12n).toString(16)})`);
      w(`  self-map PML4 index : 0x${proc.selfRefIndex.toString(16)}` +
        `   (alias windows live under PML4 slot; dq/eb them directly)`);
      if (proc.decoy) w("  NOTE: this DTB looks shuffled/decoyed — verify before trusting", "warn");
    },

    "!pte"(args, w) {
      const pts = kernel.paging;
      if (!pts) return w("!pte: no paging world booted (this lab has no page tables)", "err");
      const va = args[0] ? parseAddr(args[0]) : null;
      if (va === null) return w("usage: !pte <va> [proc]", "err");
      const proc = args[1] ? pts.findProcess(args[1]) :
        [...pts.processes.values()].find((p) => !p.decoy) ?? [...pts.processes.values()][0];
      if (!proc) return w("!pte: paging world is empty", "err");
      const res = pts.translate(va, proc);
      w(`VA ${fmtAddr(va)}  (${proc.name}, DTB 0x${proc.dtb.toString(16)}, ` +
        `split ${res.rows.map(() => "").join("")}9/9/9/9/12)`, "hdr");
      for (const row of res.rows) {
        const d = decodePte(row.value);
        w(`  ${row.label.padEnd(6)} @ phys 0x${row.entryPa.toString(16).padStart(12, "0")}` +
          `  alias ${fmtAddr(row.entryVa)}`);
        w(`         contains ${row.value.toString(16).padStart(16, "0")}` +
          `   [${pteBitsString(row.value)}]` +
          (d.large ? "  LARGE" : "") + `  pfn 0x${d.pfn.toString(16)}`);
      }
      if (!res.ok) {
        w(`  walk FAILS at ${res.failedAt} — page not present at this level`, "err");
        return;
      }
      w(`  => PA ${fmtAddr(res.pa)}  (${res.level} page)`, "good");
    },

    "!vtop"(args, w) {
      const pts = kernel.paging;
      if (!pts) return w("!vtop: no paging world booted (this lab has no page tables)", "err");
      const va = args[0] ? parseAddr(args[0]) : null;
      if (va === null) return w("usage: !vtop <va> [proc]", "err");
      const proc = args[1] ? pts.findProcess(args[1]) :
        [...pts.processes.values()].find((p) => !p.decoy) ?? [...pts.processes.values()][0];
      if (!proc) return w("!vtop: paging world is empty", "err");
      const res = pts.translate(va, proc);
      if (!res.ok) {
        w(`!vtop: ${fmtAddr(va)} -> not mapped (${res.failedAt} not present for ${proc.name})`, "err");
        return;
      }
      w(`!vtop: ${fmtAddr(va)} -> ${fmtAddr(res.pa)}  (${res.level}, ${proc.name})`, "good");
      kernel.onVtopProbe?.(va, res);
    },

    "!notifyroutines"(args, w) {
      const nr = kernel.notifyRoutines;
      if (!nr) return w("!notifyroutines: kernel has no notify registry", "err");
      const groups = [
        ["process-creation", nr.process],
        ["thread-creation", nr.thread],
        ["image-load", nr.image],
        ["object (ObRegisterCallbacks)", kernel.obCallbacks ?? []],
        ["registry (CmRegisterCallback)", kernel.cmCallbacks ?? []],
      ];
      let any = false;
      for (const [label, arr] of groups) {
        if (!arr?.length) continue;
        any = true;
        w(`${label}:`, "hdr");
        for (const cb of arr) {
          const va = typeof cb === "bigint" ? cb : BigInt(cb?.callback ?? cb?.preOperation ?? 0);
          const mod = sym(va);
          const extra = typeof cb === "object" && cb.altitude ? ` altitude=${cb.altitude}` : "";
          w(`  ${fmtAddr(va)}${mod ? `  (${mod})` : ""}${extra}`);
        }
      }
      if (!any) w("no kernel notification callbacks registered", "dim");
      else w("hint: callbacks fire on kernel events — try !notifytest", "dim");
    },

    "!notifytest"(args, w) {
      const fire = kernel.fireProcessNotify ?? kernel._fireNotifyForTest;
      if (typeof fire !== "function") {
        return w("!notifytest: notify invocation engine not booted in this world", "err");
      }
      const name = args.find((a) => /[a-z]/i.test(a)) ?? "kftarget.exe";
      const pid = Number(args.find((a) => /^\d+$/.test(a)) ?? 4242);
      w(`spawning pid ${pid} (${name}) through PspCreateProcessNotify...`, "dim");
      const res = fire(BigInt(pid), name, { parentPid: 312n });
      for (const l of res.log) w("  " + l);
      if (res.blocked) {
        w(`RESULT: creation BLOCKED — CreationStatus=0x${res.status.toString(16)}`, "err");
      } else {
        w(`RESULT: created (CreationStatus=STATUS_SUCCESS)`, "good");
      }
    },

    "!ssdt"(args, w) {
      const st = kernel.serviceTable;
      if (!st) return w("!ssdt: no service table booted (this lab has none)", "err");
      const hooks = st.scanHooks();
      const want = args[0]?.toLowerCase().replace(/\.sys$/, "");
      w(`${st.name} @ ${fmtAddr(st.base)} — ${st.entries.length} service(s):`, "hdr");
      for (let i = 0; i < st.entries.length; i++) {
        const e = st.entries[i];
        const hooked = st.isHooked(i);
        if (want && !e.name.toLowerCase().includes(want)) continue;
        let note = "";
        if (hooked) {
          const t = ServiceTable.rel32Target(st.kernel.mem, e.thunk);
          note = `  [HOOKED] E9 -> ${fmtAddr(t ?? 0n)}`;
        }
        w(`  [${String(i).padStart(3, " ")}] ${fmtAddr(st.readEntry(i))}  nt!${e.name}${note}`,
          hooked ? "warn" : "");
      }
      if (!hooks.length) {
        w("no inline detours detected across the table", "good");
      } else {
        w(`${hooks.length} hooked service(s). Repair a prologue with 'eb' ` +
          `(pristine bytes via !hookscan <export>), then re-run !ssdt.`, "dim");
        kernel.onSsdtScanned?.(hooks);
      }
    },
  };
  return commands;
}

export function createDebugger(kernel, out) {
  const commands = createCommands(kernel);
  const write = (text, cls = "") => {
    // console adapter (xterm/fallback from console.js) — preferred surface
    if (typeof out?.write === "function" && !out.appendChild) {
      out.write(text, cls);
      return;
    }
    const line = document.createElement("div");
    if (cls) line.className = cls;
    line.textContent = text;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  };
  const exec = (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    write(`kd> ${trimmed}`, "prompt");
    let [cmd, ...args] = trimmed.split(/\s+/);
    // tolerate windbg-style command flags: lmD / lmv -> lm <flag>
    if (!commands[cmd]) {
      const m = cmd.match(/^(lm)([a-zA-Z]+)$/i);
      if (m) { cmd = m[1]; args = [m[2], ...args]; }
    }
    const fn = commands[cmd];
    if (!fn) {
      const bare = cmd.replace(/^!/, "").toLowerCase();
      const known = Object.keys(commands).map((c) => c.replace(/^!/, "").toLowerCase());
      const near = known.find((c) => c.startsWith(bare.slice(0, 3)) && bare.length >= 2);
      write(near
        ? `Couldn't resolve "${cmd}" — did you mean "!${near}"? (try help)`
        : `Couldn't resolve "${cmd}" — try help`, "err");
    }
    else try { fn(args, write, out); } catch (e) { write(`error: ${e.message}`, "err"); }
  };
  return { exec, write };
}
