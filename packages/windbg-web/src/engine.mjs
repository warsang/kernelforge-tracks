/**
 * kd> command engine over a live NtKernel.
 * Output formatting mirrors real WinDbg transcripts (spacing, hex casing,
 * field tables) so students build transferable muscle memory.
 */

const HEX = (v, w = 16) => `0x${v.toString(16).padStart(w, "0")}`;

/** WinDbg-style 64-bit address: fffff805`2b9d1000 */
export function dbgAddr(v) {
  const s = v.toString(16).padStart(16, "0");
  return `${s.slice(0, 8)}\`${s.slice(8)}`;
}

function pad(s, w) { return s.length >= w ? s : s + " ".repeat(w - s.length); }
function padL(s, w) { return s.length >= w ? s : " ".repeat(w - s.length) + s; }

export class KdEngine {
  /**
   * @param {import('@kernelforge/ntsim').NtKernel} kernel
   */
  constructor(kernel) {
    this.k = kernel;
    this.breakpoints = new Map(); // addr -> {original: byte}
    this.history = [];
  }

  execute(line) {
    const trimmed = line.trim();
    if (!trimmed) return "";
    this.history.push(trimmed);
    const [cmd, ...rest] = trimmed.split(/\s+/);
    const arg = rest.join(" ");

    switch (cmd) {
      case "!process": return this.cmdProcess(arg);
      case "dt": return this.cmdDt(arg);
      case "lm": return this.cmdLm();
      case "r": return this.cmdRegs(arg);
      case "u": return this.cmdUnassemble(arg);
      case "bp": return this.cmdBp(arg);
      case "bl": return this.cmdBl();
      case "bc": return this.cmdBc(arg);
      case "!idt": return this.cmdIdt();
      case "!pool": return this.cmdPool();
      case "!dbgprint": case "!for_each_process": return this.cmdDbgLog();
      case "!pte": return this.cmdPte(arg);
      case "!vtop": return this.cmdVtop(arg);
      case "!cr": return this.cmdCr();
      case "help": case "?": return this.cmdHelp();
      default:
        return `Couldn't resolve error at '${cmd}'`;
    }
  }

  // ------------------------------------------------------------ !process

  cmdProcess(arg) {
    const t = this.k.tables;
    const procs = this.k.listProcesses();
    if (!arg || arg === "0 0") {
      // minimal listing: !process 0 0
      let out = "";
      for (const p of procs) {
        out += `${dbgAddr(p.eprocess)} ${pad(p.name, 17)}${padL(p.pid.toString(), 6)}\n`;
      }
      return `Listing processes...\n` +
        `PROCESS ${" ".repeat(6)}ImageFileName ${" ".repeat(6)}PID\n` + out;
    }
    const pidMatch = arg.match(/^\d+$/);
    if (pidMatch) {
      const pid = BigInt(arg);
      const eproc = this.k.findEprocessByPid(pid);
      if (eproc === null) return `Process ${arg} not found`;
      return this.renderEprocess(eproc);
    }
    return `Usage: !process 0 0 | !process <pid>`;
  }

  renderEprocess(eprocAddr) {
    const t = this.k.tables;
    const lines = [];
    lines.push(`PROCESS ${dbgAddr(eprocAddr)}`);
    lines.push(`    ImageFileName: ${this.k.mem.readAnsi(eprocAddr + t.offsetOf("_EPROCESS", "ImageFileName"), 15)}`);
    lines.push(`    UniqueProcessId: ${this.k.mem.u64(eprocAddr + t.offsetOf("_EPROCESS", "UniqueProcessId"))}`);
    if (t.has("_PS_PROTECTION")) {
      const prot = this.k.mem.u8(eprocAddr + t.offsetOf("_EPROCESS", "Protection"));
      const type = prot >> 4, signer = prot & 0xf;
      const typeNames = { 0: "None", 1: "ProtectedLight", 2: "Protected" };
      const signerNames = { 0: "None", 1: "Authenticode", 2: "CodeGen", 3: "Antimalware", 4: "Lsa", 5: "Windows", 6: "WinTcb", 7: "WinSystem", 8: "App" };
      lines.push(`    Protection: ${typeNames[type] ?? type} (Signer: ${signerNames[signer] ?? signer})`);
    }
    lines.push(`    ActiveProcessLinks.Flink: ${dbgAddr(this.k.mem.u64(eprocAddr + t.offsetOf("_EPROCESS", "ActiveProcessLinks")))}`);
    return lines.join("\n");
  }

  // ------------------------------------------------------------ dt

  cmdDt(arg) {
    // dt nt!_EPROCESS [addr]  |  dt nt!_EPROCESS  (type layout only)
    const m = arg.match(/^(?:nt!)?_?([A-Za-z0-9_]+)(?:\s+(?<addr>0x[0-9a-fA-F`]+|[0-9a-fA-F`]{8,}))?$/);
    if (!m) return `Couldn't resolve error at '${arg}'`;
    const typeName = `_${m[1]}`;
    const t = this.k.tables;
    if (!t.has(typeName)) return `Couldn't resolve error at 'nt!${typeName}'`;

    const addrStr = m.groups?.addr?.replace(/`/g, "").replace(/^0x/i, "");
    if (!addrStr) return this.renderTypeLayout(typeName);

    const addr = BigInt(`0x${addrStr}`);
    return this.renderTypeInstance(typeName, addr);
  }

  renderTypeLayout(typeName) {
    const t = this.k.tables;
    const rec = t.types.get(typeName);
    const lines = [];
    lines.push(`nt!${typeName}`);
    lines.push(`   +0x000 Size             : ${HEX(BigInt(rec.totalSize ?? 0), 3)}`);
    for (const f of Object.values(rec.fieldsByName)) {
      const off = `+0x${f.offset.toString(16).padStart(3, "0")}`;
      lines.push(`   ${pad(off, 9)}${pad(f.name, 22)}: ${f.base}${f.pointer ? "*" : ""}${f.bitfield ? " (bitfield)" : ""}${f.array != null ? `[${f.array}]` : ""}`);
    }
    return lines.join("\n");
  }

  renderTypeInstance(typeName, addr) {
    const t = this.k.tables;
    const rec = t.types.get(typeName);
    const lines = [];
    lines.push(`nt!${typeName}`);
    lines.push(`   +0x000 (sizeof=${HEX(BigInt(rec.totalSize ?? 0), 3)})`);
    for (const f of Object.values(rec.fieldsByName)) {
      if (f.bitfield) continue; // skip individual bits in instance view
      const off = `+0x${f.offset.toString(16).padStart(3, "0")}`;
      const fa = addr + BigInt(f.offset);
      let valStr;
      if (f.base.endsWith("_PS_PROTECTION")) {
        const prot = this.k.mem.u8(fa);
        const type = prot >> 4, signer = prot & 0xf;
        const typeNames = { 0: "None", 1: "None", 2: "ProtectedLight" };
        const signerNames = { 0: "None", 1: "Authenticode", 2: "CodeGen", 3: "Antimalware", 4: "Lsa", 5: "Windows", 6: "WinTcb", 7: "WinSystem", 8: "App" };
        valStr = `${typeNames[type] ?? type} (Signer: ${signerNames[signer] ?? signer})`;
      } else if (f.array != null && f.base.startsWith("UCHAR")) {
        valStr = `"${this.k.mem.readAnsi(fa, f.array)}"`;
      } else if (f.pointer || f.base.includes("*")) {
        const v = this.k.mem.u64(fa);
        valStr = v === 0n ? "null" : dbgAddr(v);
      } else if (f.base.startsWith("UCHAR")) {
        const v = this.k.mem.u8(fa);
        valStr = `0x${v.toString(16).padStart(2, "0")} '${String.fromCharCode(v)}'`;
      } else if (f.base.startsWith("ULONG")) {
        valStr = `0x${this.k.mem.u32(fa).toString(16).padStart(8, "0")}`;
      } else if (f.base.startsWith("ULONGLONG") || f.base.startsWith("LONGLONG") || f.base.startsWith("LARGE_INTEGER")) {
        valStr = dbgAddr(this.k.mem.u64(fa)).replace("`", "");
      } else {
        valStr = dbgAddr(this.k.mem.u64(fa)).replace("`", "");
      }
      lines.push(`   ${pad(off, 9)}${pad(f.name, 22)}: ${valStr}`);
    }
    return lines.join("\n");
  }

  // ------------------------------------------------------------ lm / regs / u / bp

  cmdLm() {
    const lines = ["start             end                 module name"];
    for (const d of this.k.loadedDrivers) {
      const base = d.base ?? 0xfffff80120000000n;
      lines.push(`${dbgAddr(base)} ${dbgAddr(base + BigInt(d.imageSize ?? 0x1000))} ${pad(d.name, 12)}(export symbols)`);
    }
    lines.push(`${dbgAddr(0xfffff8052b800000n)} ${dbgAddr(0xfffff8052c000000n)} nt        (export symbols)       ntoskrnl.exe`);
    return lines.join("\n");
  }

  cmdRegs(_arg) {
    const r = this.k.cpu.regs;
    const f = (v) => dbgAddr(v).replace("`", "");
    return [
      `rax=${f(r.rax)} rbx=${f(r.rbx)} rcx=${f(r.rcx)}`,
      `rdx=${f(r.rdx)} rsi=${f(r.rsi)} rdi=${f(r.rdi)}`,
      `rip=${f(this.k.cpu.rip)} rsp=${f(r.rsp)} rbp=${f(r.rbp)}`,
      ` r8=${f(r.r8)}  r9=${f(r.r9)} r10=${f(r.r10)} r11=${f(r.r11)}`,
      `r12=${f(r.r12)} r13=${f(r.r13)} r14=${f(r.r14)} r15=${f(r.r15)}`,
      `iopl=0         nv up ei pl zr na pe nc`,
      `cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246`,
    ].join("\n");
  }

  cmdUnassemble(_arg) {
    // minimal: report current rip region as bytes (full disasm lands with capstone-wasm)
    const rip = this.k.cpu.rip;
    const bytes = this.k.mem.read(rip, 16);
    return `nt!+0x0:\n${dbgAddr(rip)} ${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ")}   (capstone disasm pending)`;
  }

  cmdBp(arg) {
    if (!arg) return `Usage: bp <address>`;
    const addr = BigInt(`0x${arg.replace(/`/g, "")}`);
    this.k.cpu.onCodeHook = this.k._installCpuHook ? this.k.cpu.onCodeHook : this.k.cpu.onCodeHook;
    // real int3 semantics: patch byte, restore on hit
    this.breakpoints.set(addr, { original: this.k.mem.u8(addr) });
    this.k.mem.w8(addr, 0xcc);
    return `breakpoint 0 redefined\n${dbgAddr(addr)}`;
  }

  cmdBl() {
    if (!this.breakpoints.size) return "No breakpoints set.";
    return [...this.breakpoints.entries()]
      .map(([a, _], i) => `${i} e ${dbgAddr(a)}`).join("\n");
  }

  cmdBc(arg) {
    const idx = parseInt(arg, 10);
    const entries = [...this.breakpoints.entries()];
    if (idx >= entries.length) return `Invalid breakpoint id`;
    const [addr] = entries[idx];
    this.k.mem.w8(addr, this.breakpoints.get(addr).original);
    this.breakpoints.delete(addr);
    return "";
  }

  cmdIdt() {
    if (!this.k.idtBase) return `IDT not initialized in this scenario`;
    const lines = [`IDT at ${dbgAddr(this.k.idtBase)}`];
    for (let i = 0; i < 8; i++) {
      const entry = this.k.idtBase + BigInt(i * 16);
      lines.push(`${i.toString().padStart(2)}: ${dbgAddr(this.k.mem.u64(entry + 6n))}`);
    }
    return lines.join("\n");
  }

  cmdPool() {
    const lines = [`Pool allocations: ${this.k.poolAllocs.length}`];
    for (const a of this.k.poolAllocs.slice(-20)) {
      lines.push(`${dbgAddr(a.addr)} size=${a.size.toString().padStart(6)} tag='${a.tag}'`);
    }
    return lines.join("\n");
  }

  cmdDbgLog() {
    if (!this.k.dbgLog.length) return "(no DbgPrint output)";
    return this.k.dbgLog.join("\n");
  }

  cmdHelp() {
    return [
      "commands:",
      "  !process 0 0 | !process <pid>   list/show processes",
      "  dt nt!_EPROCESS [addr]          dump type / instance",
      "  lm                              list modules",
      "  r                               registers",
      "  u [addr]                        unassemble",
      "  bp <addr> / bl / bc <n>         breakpoints",
      "  !idt / !pool / !dbgprint        kernel info",
      "  !vtop <va>                      virtual -> physical (guest paging)",
      "  !pte <va>                       page-table entry walk (guest paging)",
      "  !cr                             control registers (cr0/cr3/cr4/efer)",
    ].join("\n");
  }

  // ------------------------------------------------- guest paging introspection

  #parseAddr(arg) {
    if (!arg) return null;
    const clean = arg.replace(/`/g, "").trim();
    if (!/^0x[0-9a-f]+$/i.test(clean) && !/^[0-9a-f]+$/i.test(clean)) return null;
    try { return BigInt(clean.startsWith("0x") || clean.startsWith("0X") ? clean : "0x" + clean); }
    catch { return null; }
  }

  cmdVtop(arg) {
    if (!this.k.paging) return `!vtop: guest paging is not enabled in this session`;
    const va = this.#parseAddr(arg);
    if (va === null) return `Usage: !vtop <virtual address>`;
    const pa = this.k.vtop(va);
    if (pa === null) {
      return `!vtop ${dbgAddr(va)}\n  *** ERROR: unmapped (PTE not present)`;
    }
    return `!vtop ${dbgAddr(va)}\n  x64 PTE for ${dbgAddr(va)}\n  maps to physical ${dbgAddr(pa)}`;
  }

  cmdPte(arg) {
    if (!this.k.paging) return `!pte: guest paging is not enabled in this session`;
    const va = this.#parseAddr(arg);
    if (va === null) return `Usage: !pte <virtual address>`;
    const pte = this.k.readPte(va);
    if (pte === null) return `!pte ${dbgAddr(va)}\n  Va ${dbgAddr(va)}\n  *** ERROR: no PTE (unmapped or demand-filled on access)`;
    const flag = (bit, ch, set) => set ? ch : "-";
    const flags = [
      flag(0, "V", (pte & 1n) !== 0n),
      (pte & 2n) !== 0n ? "W" : "R",
      (pte & 4n) !== 0n ? "U" : "S",
      (pte & BigInt(0x8000000000000000n)) !== 0n ? "NX" : "X ",
    ].join(" ");
    return [
      `!pte ${dbgAddr(va)}`,
      `                     PTE at ${dbgAddr(this.k.mmu.walkToPte(va) ?? 0n)}`,
      `                    contains ${dbgAddr(pte)}`,
      `                          pfn ${((pte & 0x000ffffffffff000n) >> 12n).toString(16).padStart(5, "0")}  ${flags}`,
    ].join("\n");
  }

  cmdCr() {
    // authoritative state lives in the Mmu under paging, else the backend
    const cr = (name) => {
      if (this.k.paging) {
        return { cr0: this.k.mmu.cr0, cr3: this.k.mmu.cr3, cr4: this.k.mmu.cr4, efer: this.k.mmu.efer }[name];
      }
      const v = this.k.cpu[name];
      return v === undefined ? 0n : BigInt(v);
    };
    const f = (v) => dbgAddr(BigInt(v)).replace("`", "");
    return [
      `cr0=${f(cr("cr0"))}  pg=${(cr("cr0") & 0x80000000n) !== 0n ? 1 : 0}`,
      `cr3=${f(cr("cr3"))}   (DirectoryTableBase)`,
      `cr4=${f(cr("cr4"))}  pae=${(cr("cr4") & 0x20n) !== 0n ? 1 : 0}`,
      `efer=${f(cr("efer"))}  lma=${(cr("efer") & 0x400n) !== 0n ? 1 : 0}`,
    ].join("\n");
  }
}
