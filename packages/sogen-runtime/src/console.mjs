/**
 * kd-style console engine over a sogen session world.
 * Mirrors the windbg-web engine philosophy: output formatting builds
 * transferable muscle memory; every lab is solvable through these commands.
 */

const W = 8; // userland addresses print as 8-digit hex

const HEX = (v, w = W) => `0x${v.toString(16).padStart(w, "0")}`;

function pad(s, n) { return s.length >= n ? s : s + " ".repeat(n - s.length); }

export class SogenConsole {
  /**
   * @param {object} world buildSauerWorld() result
   */
  constructor(world) {
    this.w = world;
    this.history = [];
  }

  execute(line) {
    const trimmed = line.trim();
    if (!trimmed) return "";
    this.history.push(trimmed);
    const [cmd, ...rest] = trimmed.split(/\s+/);
    const arg = rest.join(" ");

    switch (cmd.toLowerCase()) {
      case "lm": return this.cmdLm();
      case "pe": return this.cmdPe(arg);
      case "x": return this.cmdX(rest);
      case "scan": return this.cmdScan(rest);
      case "eb": return this.cmdEb(rest);
      case "hookscan": return this.cmdHookscan();
      case "!damage": return this.cmdDamage(rest);
      case "!inputtest": return this.cmdInputTest();
      case "!actrace": return this.cmdAcTrace();
      case "!etwtrace": return this.cmdEtwTrace();
      case "!providers": return this.cmdEtwProviders();
      case "!etwpump": return this.cmdEtwPump(rest);
      case "!callview": return this.w.uchooks && this.w.mode === "vtable"
        ? this.w.callView() : "unknown command";
      case "!spreadtest": return this.w.uchooks && this.w.mode === "hotpatch"
        ? this.w.spreadTest() : "unknown command";
      case "!drset": {
        if (!this.w.uchooks || this.w.mode !== "drx") return "unknown command";
        const a = parseNum(rest[0] ?? "");
        if (a === null) return "usage: !drset <addr>   e.g. !drset 0x004532a0";
        return this.w.drSet(a);
      }
      case "!drclear": return this.w.uchooks && this.w.mode === "drx"
        ? this.w.drClear() : "unknown command";
      case "!frametest": {
        if (!this.w.uchooks || this.w.mode !== "drx") return "unknown command";
        const n = Number.parseInt(rest[0] ?? "", 10) || 1;
        return this.w.frameTest(Math.min(n, 64));
      }
      case "!drxaudit": return this.w.uchooks && this.w.mode === "drx"
        ? this.w.drxAudit() : "unknown command";
      case "!spoof-process": {
        if (!this.w.ac) return "unknown command";
        const n = rest.join(" ");
        this.w.mem.processes = this.w.mem.processes.map((p) => (/cheat/i.test(p) ? n || "renamed.bin" : p));
        return `process list now: ${this.w.mem.processes.join(", ")}`;
      }
      case "!spoof-window": {
        if (!this.w.ac) return "unknown command";
        const t = rest.join(" ");
        this.w.mem.windows = this.w.mem.windows.map((x) => (/cheat/i.test(x) ? t || "Untitled" : x));
        return `windows now: ${this.w.mem.windows.join(", ")}`;
      }
      case "!setstat": {
        if (!this.w.ac) return "unknown command";
        const [what, num] = rest;
        const v = Number(num);
        if (!["ammo", "health"].includes(what ?? "") || !Number.isFinite(v)) {
          return "usage: !setstat ammo|health <n>  (game API: keeps shadow + encryption in sync)";
        }
        this.w.mem.statsPlain[what] = Math.trunc(v);
        this.w.mem.statsEnc[what] = (Math.trunc(v) ^ this.w.xorKey) >>> 0;
        this.w.mem.statsShadowEnc[what] = this.w.mem.statsEnc[what];
        return `${what} -> ${Math.trunc(v)} (encrypted live + shadow updated)`;
      }
      case "!godmode": {
        if (!this.w.ac) return "unknown command";
        const res = this.w.engine.godmode();
        return [...res.log, res.ok ? "GODMODE GRANTED" : "GODMODE DENIED"].join("\n");
      }
      case "help": case "?": return this.cmdHelp();
      default:
        return `Couldn't resolve error at '${cmd}'`;
    }
  }

  // ------------------------------------------------------------------ info

  cmdLm() {
    let out = "start             end               module name";
    for (const m of this.w.modules) {
      const end = m.base + BigInt(m.size);
      out += `\n${HEX(m.base)} ${HEX(end)} ${pad(m.name, 24)}`;
      if (!this.w.mem.hasPage(m.base)) out += " (deferred)";
    }
    return out;
  }

  cmdPe(arg) {
    if (!arg) return "Usage: pe <module name>";
    const needle = arg.toLowerCase().replace(/\.dll$|\.exe$/, "");
    const m = this.w.modules.find((x) => x.name.toLowerCase().startsWith(needle));
    if (!m) return `Couldn't resolve error at '${arg}'`;
    if (!this.w.mem.hasPage(m.base)) {
      return `${m.name} @ ${HEX(m.base)} — image not materialized in this world`;
    }
    const hdr = Array.from(this.w.mem.read(m.base, 2));
    const size = this.w.mem.u32(m.base + 0x3cn); // e_lfanew
    const magic = hdr[0] === 0x4d ? "MZ" : "??";
    return `${m.name}\n` +
      `    base: ${HEX(m.base)}  size: 0x${m.size.toString(16)}\n` +
      `    header: ${magic}  e_lfanew: ${HEX(BigInt(size), 4)}`;
  }

  // ------------------------------------------------------------- memory ui

  cmdX(rest) {
    if (!rest.length) return "Usage: x <addr> [len]";
    const addr = parseNum(rest[0]);
    if (addr === null) return `Couldn't resolve error at '${rest[0]}'`;
    const len = rest[1] ? Number.parseInt(rest[1], 16) || 0x60 : 0x60;
    if (!this.w.mem.canRead(addr, Math.min(len, 0x100))) {
      return `Memory access fault at ${HEX(addr)}`;
    }
    const bytes = Array.from(this.w.mem.read(addr, Math.min(len, 0x400)));
    let out = "";
    for (let row = 0; row < bytes.length; row += 16) {
      const slice = bytes.slice(row, row + 16);
      const hex = slice.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const ascii = slice.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
      out += `${HEX(addr + BigInt(row))}  ${pad(hex, 47)} |${ascii}|\n`;
    }
    return out.trimEnd();
  }

  cmdScan(rest) {
    // scan <start> <len> <value> [size=4]
    if (rest.length < 3) return "Usage: scan <start> <len-hex> <value> [size]";
    const start = parseNum(rest[0]);
    const len = parseInt(rest[1], 16);
    const value = Number(rest[2]);
    const size = rest[3] ? Number(rest[3]) : 4;
    if (start === null || !Number.isFinite(len) || !Number.isFinite(value)) {
      return "Usage: scan <start> <len-hex> <value> [size]";
    }
    if (!this.w.mem.canRead(start, BigInt(len))) {
      return `Memory access fault scanning ${HEX(start)}`;
    }
    const hits = [];
    for (let off = 0; off + size <= len && hits.length < 64; off++) {
      const a = start + BigInt(off);
      const v = size === 1 ? this.w.mem.u8(a)
        : size === 8 ? Number(this.w.mem.u64(a))
        : this.w.mem.u32(a);
      if (v === value) hits.push(a);
    }
    if (!hits.length) return `no matches for ${value} (${size}-byte)`;
    return hits.map((a) => HEX(a)).join("\n") +
      (hits.length >= 64 ? "\n... (truncated)" : "");
  }

  cmdEb(rest) {
    if (rest.length < 2) return "Usage: eb <addr> <b1 b2 ...>";
    const addr = parseNum(rest[0]);
    if (addr === null) return `Couldn't resolve error at '${rest[0]}'`;
    const bytes = rest.slice(1)
      .flatMap((t) => t.split(","))
      .filter(Boolean)
      .map((h) => parseInt(h, 16));
    if (bytes.some(Number.isNaN)) return "Usage: eb <addr> <hex bytes>";
    this.w.mem.write(addr, bytes);
    return `wrote ${bytes.length} byte(s) at ${HEX(addr)}`;
  }

  // ------------------------------------------------------------ hook tooling

  cmdHookscan() {
    const diffs = this.w.hookscan();
    if (!diffs.length) return "no modifications — all monitored pages pristine";
    // group into runs
    const runs = [];
    for (const d of diffs) {
      const last = runs[runs.length - 1];
      if (last && d.addr === last.end + 1n) { last.end = d.addr; last.live.push(d.live); last.orig.push(d.orig); }
      else runs.push({ start: d.addr, end: d.addr, orig: [d.orig], live: [d.live] });
    }
    let out = `${runs.length} modified region(s):`;
    for (const r of runs.slice(0, 8)) {
      const liveHex = r.live.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const origHex = r.orig.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      out += `\n  site ${HEX(r.start)}  live: ${liveHex}`;
      out += `\n         orig: ${origHex}`;
      if (r.live[0] === 0xe9 && r.live.length >= 5) {
        const rel = (r.live[1] | (r.live[2] << 8) | (r.live[3] << 16) | (r.live[4] << 24)) >>> 0;
        out += `\n         E9 -> ${HEX(r.start + 5n + BigInt(rel))}`;
      }
    }
    if (runs.length > 8) out += `\n  ... ${runs.length - 8} more`;
    return out;
  }

  // -------------------------------------------------------- modeled actions

  cmdAcTrace() {
    if (!this.w.ac) return "tbm-ac world not booted";
    const m = this.w.mem;
    const lines = [
      `detection vectors (${2 + 3}):`,
      "  process-blacklist     processes: " + m.processes.join(", "),
      "  window-title-scan     windows:   " + m.windows.join(", "),
      `  debugger-detection    BeingDebugged=${m.beingDebugged} NtGlobalFlag=0x${m.ntGlobalFlag.toString(16)} DebugPort=${m.debugPort}`,
      `  stat-canary-shadow    live=${m.statsEnc.ammo}/${m.statsEnc.health} shadow=${m.statsShadowEnc.ammo}/${m.statsShadowEnc.health} (XOR key hidden)`,
      `  code-crc-thread       acThread @ 0x600300 CRC ${m.crcBad ? "MISMATCH" : "ok"}`,
      "hint: !spoof-process/!spoof-window, clear PEB artifacts, !setstat for god-tier values",
    ];
    return lines.join("\n");
  }

  cmdDamage(rest) {
    const n = Number.parseInt(rest[0] ?? "", 10);
    if (!Number.isFinite(n)) return "Usage: !damage <decimal>";
    const now = this.w.damage(n);
    return `world: local player took ${n} damage (health events are live state)`;
  }

  cmdInputTest() {
    const r = this.w.inputTest();
    return r.lines.join("\n");
  }

  // ------------------------------------------------------------ etw (m26)

  cmdEtwTrace() {
    if (!this.w.etw) return "etw-blind world not booted";
    return this.w.trace();
  }

  cmdEtwProviders() {
    if (!this.w.etw) return "etw-blind world not booted";
    const C = this.w.constants;
    const lines = ["registered providers:"];
    C.providers.forEach((p, i) => {
      const h = this.w.mem.u32(C.providerTable + BigInt(i * 8));
      lines.push(`  ${p.name.padEnd(16)} RegHandle=0x${h.toString(16).padStart(8, "0")} @ ${HEX(C.providerTable + BigInt(i * 8))}`);
    });
    lines.push(`wrapper: ntdll!EtwEventWrite @ ${HEX(C.etwEventWrite)}`);
    return lines.join("\n");
  }

  cmdEtwPump(rest) {
    if (!this.w.etw) return "etw-blind world not booted";
    const n = Number.parseInt(rest[0] ?? "", 10);
    if (!Number.isFinite(n) || n <= 0 || n > 64) {
      return "usage: !etwpump <n>   (emit 1-64 modeled telemetry events)";
    }
    this.w.emitEvents(n);
    return `emitted ${n} event(s) through ntdll!EtwEventWrite — see !etwtrace`;
  }

  cmdHelp() {
    return [
      "Userland console (sogen reference backend)",
      "  lm                       list modules",
      "  pe <name>                PE header summary",
      "  x <addr> [len]           hexdump (+ascii)",
      "  scan <start> <len> <val> [size]   search memory for a value",
      "  eb <addr> <bytes>        write hex bytes",
      "  hookscan                 diff .text against pristine snapshot",
      "  !damage <n>              world action: player takes damage",
      "  !inputtest               replay scripted input batch",
      "  !providers               ETW providers + RegHandles (etw-blind world)",
      "  !etwpump <n>             emit n telemetry events through EtwEventWrite",
      "  !etwtrace                delivered vs suppressed telemetry trace",
      "  !callview                call the object's live vtable slot (vtable-hook)",
      "  !spreadtest              replay calcspread live bytes (hotpatch-hook)",
      "  !drset/!drclear <addr>   arm/clear modeled DR0 execute bp (drx-hook)",
      "  !frametest <n>           replay n frames against armed DRs",
      "  !drxaudit                anticheat thread-context DR audit",
    ].join("\n");
  }
}

/** Parse 0x-hex or bare hex into BigInt; null on garbage. */
export function parseNum(s) {
  try {
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9a-fA-F]+$/.test(s) && s.length >= 6) return BigInt("0x" + s);
  } catch { /* fallthrough */ }
  return null;
}
