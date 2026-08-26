/**
 * views/script.js — JavaScript scripting console over a DebugSession.
 *
 * Vanilla port of upstream sogen's page/src/components/script-console.tsx:
 * Monaco editor (via the shared createCodeEditor service), named scripts
 * persisted in localStorage, Run/Stop buttons and an output pane.
 * Scripts execute as async functions receiving an `emu` facade whose
 * `emu.debug.*` verbs mirror the DebugSession contract and whose
 * `emu.memory.read` reads paused memory. Cancellation is cooperative:
 * every facade call first checks a per-run cancelled flag.
 */

import { createCodeEditor } from "../editor.js";
import { toBig } from "../session.mjs";

const LS_KEY = "kf.debugger.scripts.js";

const DEFAULT_SCRIPT = `// Inspect the target from here. Examples:
const mods = await emu.debug.modules();
print("modules:", mods.map(m => m.name).join(", "));

for (const m of mods.slice(0, 3)) {
  const insns = await emu.debug.disassemble(BigInt(m.base), 5);
  print(m.name, "@", m.base);
  for (const i of insns) print("  ", i.address, i.mnemonic, i.operands ?? "");
}
`;

function loadScripts() {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) ?? "{}");
  } catch {
    return {};
  }
}
function saveScripts(map) {
  try { localStorage.setItem(LS_KEY, JSON.stringify(map)); } catch { /* private mode */ }
}

/** Build the `emu` facade handed to scripts. */
export function createEmuFacade(session, print, handle) {
  const guard = () => {
    if (handle?.cancelled) throw new Error("script cancelled");
    if (session && session.paused === false) {
      throw new Error("target running — pause before scripted introspection");
    }
  };
  const wrap = (fn) => async (...args) => {
    guard();
    return fn(...args);
  };
  const regsObj = async () => {
    const list = await session.getRegisters();
    return Object.fromEntries(list.map((r) =>
      [r.name, toBig(r.value) ?? 0n]));
  };
  const disassemble = async (addr, count = 32) =>
    session.disassemble(
      (typeof addr === "bigint" ? addr : toBig(addr) ?? 0n).toString(16),
      Number(count),
    );
  return {
    debug: {
      breakpoints: wrap(() => session.listBreakpoints()),
      setBreakpoint: wrap((addr) => session.setBreakpoint(
        (toBig(addr) ?? 0n).toString(16))),
      clearBreakpoint: wrap((addr) => session.clearBreakpoint(
        (toBig(addr) ?? 0n).toString(16))),
      step_into: wrap(() => session.stepInto?.()),
      step_over: wrap(() => session.stepOver?.()),
      step_out: wrap(() => session.stepOut?.()),
      run_to: wrap((addr) => session.runTo?.((toBig(addr) ?? 0n).toString(16))),
      continue_execution: wrap(() => session.resume?.()),
      registers: wrap(regsObj),
      disassemble: wrap(disassemble),
      modules: wrap(() => session.getModules()),
      threads: wrap(() => session.getThreads()),
      call_stack: wrap(() => session.getCallStack()),
    },
    memory: {
      read: wrap(async (addr, size) => {
        const big = typeof addr === "bigint" ? addr : toBig(addr) ?? 0n;
        return session.readMemory(big.toString(16), Number(size));
      }),
      /** NUL-terminated ASCII convenience reader */
      read_string: wrap(async (addr, max = 64) => {
        const big = typeof addr === "bigint" ? addr : toBig(addr) ?? 0n;
        const bytes = await session.readMemory(big.toString(16), Number(max));
        let out = "";
        for (const b of bytes) {
          if (!b) break;
          out += String.fromCharCode(b);
        }
        return out;
      }),
    },
    get state() {
      return { paused: !!session?.paused, pauseCount: session?.pauseCount ?? 0 };
    },
  };
}

export function createScriptView({ session }) {
  const element = document.createElement("div");
  element.className = "dbg-script";

  // header row: script picker + name + actions
  const bar = document.createElement("div");
  bar.className = "dbg-script-bar";
  const select = document.createElement("select");
  select.className = "dbg-input mono";
  const nameInput = document.createElement("input");
  nameInput.className = "dbg-input mono";
  nameInput.placeholder = "script name";
  nameInput.spellcheck = false;
  const btnSave = document.createElement("button");
  btnSave.className = "dbg-btn";
  btnSave.textContent = "Save";
  const btnDelete = document.createElement("button");
  btnDelete.className = "dbg-btn";
  btnDelete.textContent = "Delete";
  const btnRun = document.createElement("button");
  btnRun.className = "dbg-btn primary";
  btnRun.textContent = "\u25b6 Run";
  const btnStop = document.createElement("button");
  btnStop.className = "dbg-btn";
  btnStop.textContent = "\u25a0 Stop";
  btnStop.disabled = true;
  bar.append(select, nameInput, btnSave, btnDelete, btnRun, btnStop);

  const editorHost = document.createElement("div");
  editorHost.className = "dbg-script-editor";
  const out = document.createElement("div");
  out.className = "dbg-script-out";
  element.append(bar, editorHost, out);

  const print = (...parts) => {
    const line = parts.map((p) =>
      typeof p === "string" ? p : JSON.stringify(p, (_k, v) =>
        typeof v === "bigint" ? v.toString(16) : v)).join(" ");
    const div = document.createElement("div");
    div.textContent = line;
    out.append(div);
    out.scrollTop = out.scrollHeight;
  };

  // ---- script persistence -----------------------------------------------------

  const refreshPicker = (selected) => {
    const scripts = loadScripts();
    select.innerHTML = "";
    for (const name of Object.keys(scripts)) {
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = name;
      select.append(opt);
    }
    if (selected && scripts[selected]) select.value = selected;
  };
  let handle = null;

  void createCodeEditor(editorHost, {
    value: DEFAULT_SCRIPT,
    language: "javascript",
    height: "100%",
  }).then((h2) => { handle = h2; });

  btnSave.addEventListener("click", () => {
    const name = (nameInput.value || "").trim();
    if (!name) {
      nameInput.reportValidity?.();
      return;
    }
    const scripts = loadScripts();
    scripts[name] = handle?.getValue?.() ?? "";
    saveScripts(scripts);
    refreshPicker(name);
    print(`saved "${name}"`);
  });
  btnDelete.addEventListener("click", () => {
    const name = select.value;
    if (!name) return;
    const scripts = loadScripts();
    delete scripts[name];
    saveScripts(scripts);
    refreshPicker();
    print(`deleted "${name}"`);
  });
  select.addEventListener("change", () => {
    const scripts = loadScripts();
    const src = scripts[select.value];
    if (src !== undefined) handle?.setValue(src);
  });

  // ---- execution ----------------------------------------------------------------

  let currentRun = null;
  btnStop.addEventListener("click", () => {
    if (currentRun) currentRun.cancelled = true;
  });

  btnRun.addEventListener("click", () => {
    if (!session) {
      print("no debug session attached");
      return;
    }
    const src = handle?.getValue?.() ?? "";
    out.innerHTML = "";
    const h2 = { cancelled: false };
    currentRun = h2;
    btnStop.disabled = false;
    const emu = createEmuFacade(session, print, h2);
    const done = (err) => {
      btnStop.disabled = true;
      if (currentRun === h2) currentRun = null;
      print(err ? `✗ ${err.message ?? err}` : "(done)");
    };
    print(`— run @ ${new Date().toLocaleTimeString()} —`);
    try {
      const fn = new Function("emu", "print", "console",
        '"use strict"; return (async () => {\n' + src + "\n})();");
      Promise.resolve(fn(emu, print, console))
        .then(() => done(null))
        .catch((e) => done(e));
    } catch (e) {
      done(e); // syntax error
    }
  });

  return {
    element,
    dispose() {
      handle?.dispose?.();
      element.remove();
    },
  };
}
