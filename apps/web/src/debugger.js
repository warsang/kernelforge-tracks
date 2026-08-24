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

const FAST_REF_MASK = ~0xfn; // x64: low nibble holds reference count

function fmtAddr(v) {
  return "0x" + v.toString(16).padStart(16, "0");
}

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
