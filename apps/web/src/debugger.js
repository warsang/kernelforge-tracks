/**
 * Minimal WinDbg-flavored command console over a booted NtKernel.
 * Supported: lm, !process 0 0, r, db <addr> [len], dq <addr> [count],
 * !eproc <addr|pid>, help. Output lines are appended to an element.
 */

function fmtAddr(v) {
  return "0x" + v.toString(16).padStart(16, "0");
}

export function createDebugger(kernel, out) {
  const write = (text, cls = "") => {
    const line = document.createElement("div");
    if (cls) line.className = cls;
    line.textContent = text;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  };

  function parseAddr(token) {
    if (/^0x/i.test(token)) return BigInt(token);
    return BigInt(token);
  }

  const commands = {
    help() {
      write("commands: lm | !process 0 0 | r | db <addr> [len] | dq <addr> [n] | !eproc <addr|pid> | clear");
    },
    clear() { out.innerHTML = ""; },
    lm() {
      write("start             end                 module name", "hdr");
      for (const m of kernel.loadedModules ?? []) {
        const start = m.base;
        const end = m.base + 0x100000n;
        write(
          `${fmtAddr(start)} ${fmtAddr(end)} ${m.name}` +
          (m.full.includes("FLAG") ? "   <-- suspicious" : "")
        );
        write(`    FullDllName: ${m.full}`, "dim");
      }
    },
    "!process"(args) {
      if (args[0] === "0" && args[1] === "0") {
        write("PROCESS fff...  SessionId: none  Cid: xxxx  Peb: 00000000  ParentCid: 0004", "hdr");
        for (const p of kernel.listProcesses()) {
          write(`PROCESS ${fmtAddr(p.eprocess)}  Cid: ${p.pid.toString().padStart(4, "0")}  ImageFileName: ${p.name}`);
        }
      } else {
        write("usage: !process 0 0", "dim");
      }
    },
    r() {
      for (const [k, v] of Object.entries(kernel.cpu.regs)) {
        write(`${k.padEnd(4)}=${fmtAddr(v)}`);
      }
    },
    db(args) {
      const addr = parseAddr(args[0] ?? "0x0");
      const len = Math.min(Number(args[1] ?? 128), 512);
      const bytes = kernel.mem.read(addr, len);
      for (let row = 0; row < len; row += 16) {
        const chunk = [...bytes.slice(row, row + 16)];
        const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
        const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
        write(`${fmtAddr(addr + BigInt(row))}  ${hex.padEnd(47)}  |${ascii}|`);
      }
    },
    dq(args) {
      const addr = parseAddr(args[0] ?? "0x0");
      const count = Math.min(Number(args[1] ?? 8), 64);
      for (let i = 0; i < count; i++) {
        write(`${fmtAddr(addr + BigInt(i * 8))}  ${fmtAddr(kernel.mem.u64(addr + BigInt(i * 8)))}`);
      }
    },
    "!eproc"(args) {
      let va;
      try { va = parseAddr(args[0]); } catch { va = null; }
      const eproc = va && va > 0xffffn ? va : kernel.findEprocessByPid(parseAddr(args[0] ?? "0"));
      if (!eproc) return write("no such process", "err");
      const tables = kernel.tables;
      const pid = kernel.mem.u64(eproc + tables.offsetOf("_EPROCESS", "UniqueProcessId"));
      const name = kernel.mem.readAnsi(eproc + tables.offsetOf("_EPROCESS", "ImageFileName"), 15);
      write(`_EPROCESS @ ${fmtAddr(eproc)}`);
      write(`  UniqueProcessId : ${pid}`);
      write(`  ImageFileName   : ${name}`);
      const protOff = tables.has("_PS_PROTECTION")
        ? tables.offsetOf("_EPROCESS", "Protection") : null;
      if (protOff !== null) {
        const p = kernel.mem.u8(eproc + protOff);
        write(`  Protection      : 0x${p.toString(16)} (type=${p >> 4} signer=${p & 15})`);
      }
    },
  };

  function exec(line) {
    const trimmed = line.trim();
    if (!trimmed) return;
    write(`kd> ${trimmed}`, "prompt");
    const [cmd, ...args] = trimmed.split(/\s+/);
    const fn = commands[cmd];
    if (!fn) write(`Couldn't resolve "${cmd}" — try help`, "err");
    else try { fn(args); } catch (e) { write(`error: ${e.message}`, "err"); }
  }

  return { exec, write };
}
