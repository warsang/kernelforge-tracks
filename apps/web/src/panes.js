/**
 * Pane registry: lab.kind -> presentation/behavior overrides for the lab
 * card. Tracks add new lab kinds by registering here instead of editing
 * main.js core flow.
 *
 * def shape (all optional):
 *   backends?: [{value,label}]         options for the CPU/backend select
 *   noDump?: boolean                   skip tryLoadDumpWorld() on boot
 *   rawBoot?: boolean                  skip the ntsim backend factory entirely
 *   createDebugger?(session, host)     console debugger factory over the
 *                                      booted session (default: kernel kd)
 *   mountShell?(session, ctx)          graphical debugger shell; ctx =
 *                                      {card, consoleHost, shellHost, h};
 *                                      returns a facade (or null)
 *   attachEditor?(ui)                  pane IDE hookup
 */

import { createSogenDebugger } from "./sogen-debugger.js";
import { createLinuxDebugger, attachLinuxEditor } from "./linux-pane.js";
import { createDebuggerShell } from "@kernelforge/debugger-ui";
import { createStaticDebugSession, SAUER_CONSTANTS } from "@kernelforge/sogen-runtime";
import { createDecompilerClient } from "@kernelforge/ghidra-decompiler";
import { createGdbConsole } from "./gdb-console.js";

const panes = new Map();

export function registerPane(kind, def) {
  panes.set(kind, def);
}

export function paneFor(kind) {
  return panes.get(kind) ?? null;
}

// --- ntsim family: default flow (kernel sessions + kd engine) -------------
registerPane("windbg", {});
registerPane("ntsim", {});
registerPane("compiler", {});

// --- windows-userland: sogen track ------------------------------------------
// Graphical shell over the reference world (static views today: disasm,
// memory, modules, visual breakpoints). The vendored sogen WASM core swaps
// in a full DebugSession (registers/threads/stack/real bp+step) behind the
// same mount point — see packages/sogen-runtime/src/backend-static.mjs.
registerPane("sogen", {
  backends: [
    { value: "js", label: "Emulator: sogen reference backend (deterministic)" },
  ],
  noDump: true,
  createDebugger: (session, host) => createSogenDebugger(session, host),
  mountShell: (session, ctx) => {
    if (!session?.world) return null;
    const world = session.world;
    const dbgSession = createStaticDebugSession(world);
    // pyre-style decompiler client over the game image extent (loud-degrades
    // until the ghidra wasm is vendored; function LIST works statically)
    const decompiler = createDecompilerClient({
      readImage: (addr, size) => {
        const base = BigInt(addr);
        if (typeof world.mem.canRead === "function" && !world.mem.canRead(base, 1)) return null;
        return world.mem.read(base, Number(size));
      },
      extent: { base: SAUER_CONSTANTS.imageBase, size: SAUER_CONSTANTS.imageSize },
    });
    const shell = createDebuggerShell(ctx.shellHost, {
      session: dbgSession,
      title: "sogen — userland debugger",
      initialTab: "disasm",
      decompiler,
    });
    // console commands mutate the world; refresh panels after each exec
    if (ctx.consoleDebugger) ctx.consoleDebugger.onAfterExec = () => shell.refresh();
    return shell;
  },
});

// --- linux-kernel: v86 buildroot guest --------------------------------------
registerPane("linux", {
  backends: [
    { value: "v86", label: "Guest: v86 i386 Linux (buildroot)" },
  ],
  noDump: true,
  rawBoot: true, // no ntsim CPU factory involved
  createDebugger: (session, host) => createLinuxDebugger(session, host),
  attachEditor: attachLinuxEditor,
  /**
   * GDB shell docks above the guest console; the Console tab hosts a
   * dedicated (gdb) prompt. Attach happens lazily when the student runs
   * `gdb start <path>` in the guest terminal.
   */
  mountShell: (session, ctx) => {
    const adapter = ctx.consoleDebugger;
    if (!adapter?.hooks) return null;

    const placeholder = document.createElement("div");
    placeholder.className = "dim dbg-note pad";
    placeholder.textContent =
      'gdb bridge idle — run "gdb start /root/lab/app" in the guest console ' +
      "(buildroot image must include gdb-server).";
    ctx.shellHost.append(placeholder);

    let shell = null;
    adapter.hooks.onGdbAttach.push((gdbSession) => {
      placeholder.remove();
      shell = createDebuggerShell(ctx.shellHost, {
        session: gdbSession,
        title: "gdb — v86 target",
        initialTab: "disasm",
        closable: true,
        onClose: () => {
          ctx.shellHost.append(placeholder);
          shell.dispose();
          shell = null;
        },
        /** Dedicated (gdb)-prompt console inside the shell's Console tab. */
        consoleFactory: (tabHost) => {
          tabHost.className = "dbg-console-host";
          const out = document.createElement("div");
          out.className = "console";
          const input = document.createElement("input");
          input.className = "cmd";
          input.placeholder = "(gdb) break *0x8048000 …";
          tabHost.append(input, out);
          const writeLine = (text, cls2 = "") => {
            const div = document.createElement("div");
            if (cls2) div.className = cls2;
            div.textContent = text;
            out.appendChild(div);
            out.scrollTop = out.scrollHeight;
          };
          const gdbConsole = createGdbConsole({
            getSession: () => gdbSession,
            write: writeLine,
          });
          return {
            write: writeLine,
            clear() { out.innerHTML = ""; },
            exec: (line) => gdbConsole.exec(line),
            focusTarget: input,
            dispose() { tabHost.innerHTML = ""; },
          };
        },
      });
      // keep panels fresh after every stop
      gdbSession.onStateChange(() => shell?.refresh());
    });
    // Facade so a re-boot disposes the placeholder + any attached gdb shell
    // instead of stacking another dock above the console.
    return {
      dispose() {
        try { shell?.dispose?.(); } catch { /* best effort */ }
        shell = null;
        placeholder.remove();
      },
    };
  },
});
