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

  const resolveProcess = (token) => {
    let v;
    try { v = BigInt(token); } catch { return null; }
    if (v > 0xffffn) return v;
    return kernel.findEprocessByPid(v);
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

  const commands = {
    help(args, w) {
      w("commands:");
      w("  lm                        loaded modules");
      w("  !process 0 0              process list");
      w("  !process <addr|pid> [n]   detailed _EPROCESS field walk");
      w("  !eproc <addr|pid>         short summary");
      w("  !token <addr|pid>         decode Token EX_FAST_REF + raw dump");
      w("  !pcr [addr]               KPCR -> PRCB -> CurrentThread chain");
      w("  !thread [addr]            _ETHREAD walk (default: PRCB.CurrentThread)");
      w("  dt <Type> [addr]          walk any loaded type");
      w("  r | db <a> [n] | dq <a> [n] | clear");
    },
    clear(args, w, out) { out.innerHTML = "(cleared)\n"; },

    lm(args, w) {
      w("start             end                 module name", "hdr");
      for (const m of kernel.loadedModules ?? []) {
        w(`${fmtAddr(m.base)} ${fmtAddr(m.base + 0x100000n)} ${m.name}` +
          (m.full.includes("FLAG") ? "   <-- suspicious" : ""));
        w(`    FullDllName: ${m.full}`, "dim");
      }
    },

    "!process"(args, w) {
      if (!args.length || args[0] === "0") {
        w("PROCESS fff...  SessionId: none  Cid: xxxx  Peb: 00000000  ParentCid: 0004", "hdr");
        for (const p of kernel.listProcesses()) {
          w(`PROCESS ${fmtAddr(p.eprocess)}  Cid: ${p.pid.toString().padStart(4, "0")}  ImageFileName: ${p.name}`);
        }
        return;
      }
      const eproc = resolveProcess(args[0]);
      if (!eproc) return w(`!process: no process for "${args[0]}"`, "err");
      w(`Dumping _EPROCESS for "${args[0]}" (detail bits ${args[1] ?? "1"}):`, "hdr");
      for (const line of dumpStruct("_EPROCESS", eproc, { max: Number(args[1] ?? 1) > 1 ? 200 : 140 })) w(line);
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
      const [typeName, addrTok] = args;
      if (!typeName) return w("usage: dt <Type> [addr]", "err");
      const tname = typeName.startsWith("_") ? typeName : `_${typeName}`;
      let addr = 0n;
      try { addr = addrTok ? BigInt(addrTok) : 0n; } catch { return w("dt: bad address", "err"); }
      for (const line of dumpStruct(tname, addr, { max: 96 })) w(line);
    },

    r(args, w) {
      for (const [k, v] of Object.entries(kernel.cpu.regs)) w(`${k.padEnd(4)}=${fmtAddr(v)}`);
    },

    db(args, w) {
      let addr; try { addr = BigInt(args[0] ?? "0x0"); } catch { return w("db: bad address", "err"); }
      const len = Math.min(Number(args[1] ?? 128), 512);
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
    const [cmd, ...args] = trimmed.split(/\s+/);
    const fn = commands[cmd];
    if (!fn) write(`Couldn't resolve "${cmd}" — try help`, "err");
    else try { fn(args, write, out); } catch (e) { write(`error: ${e.message}`, "err"); }
  };
  return { exec, write };
}
