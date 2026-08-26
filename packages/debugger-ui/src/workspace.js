/**
 * workspace.js — floating pyre-style analysis workspace.
 *
 * A draggable/resizable/minimizable tool window that overlays the current
 * page (never navigates away): function list | disassembly | pseudocode
 * (Monaco via createCodeEditor) | memory, plus live-session tabs when a
 * DebugSession provides them, and CFG/Script (views/cfg.js, views/script.js).
 *
 * Data seams (all optional, views degrade):
 *   session     DebugSession contract (static image adapters welcome)
 *   decompiler  { decompile(addrHex)->{c}, functions()->{count,funcs} }
 *
 * Hotkeys are scoped to the window element (tabindex) so they never fight
 * the docked debugger shell's global F5/F10/F11 handling.
 */

import { toBig, fmtAddr } from "./session.mjs";
import { createDisasmView } from "./views/disasm.js";
import { createHexView } from "./views/hexdump.js";
import {
  createRegistersPanel,
  createCallStackPanel,
  createBreakpointsPanel,
  createThreadsPanel,
  createModulesPanel,
} from "./views/panels.js";
import { createPseudocodeView } from "./views/pseudocode.js";
import { createCfgView } from "./views/cfg.js";
import { createScriptView } from "./views/script.js";

/** All open workspaces (lesson re-render housekeeping). */
const live = new Set();
export function disposeWorkspaces() {
  for (const w of [...live]) {
    try { w.dispose(); } catch { /* best effort */ }
  }
  live.clear();
}

let zTop = 5000;

/**
 * @param {object} opts
 * @param {string} [opts.title]
 * @param {import("./session.mjs").DebugSession} [opts.session]
 * @param {object} [opts.decompiler]
 * @param {(big: bigint) => void} [opts.onClose]
 */
export function createAnalysisWorkspace(opts = {}) {
  const {
    title = "Analysis",
    session = null,
    decompiler = null,
    onClose = null,
  } = opts;

  // ---- chrome ---------------------------------------------------------------

  const element = document.createElement("div");
  element.className = "kf-ws";
  element.tabIndex = -1; // focus target for scoped hotkeys

  const head = document.createElement("div");
  head.className = "kf-ws-head";
  const titleEl = document.createElement("span");
  titleEl.className = "kf-ws-title";
  titleEl.textContent = title;
  const headBtns = document.createElement("span");
  headBtns.className = "kf-ws-head-btns";
  const btnMin = document.createElement("button");
  btnMin.textContent = "\u2013";
  btnMin.title = "Minimize";
  const btnClose = document.createElement("button");
  btnClose.textContent = "\u00d7";
  btnClose.title = "Close";
  headBtns.append(btnMin, btnClose);
  head.append(titleEl, headBtns);

  // toolbar
  const toolbar = document.createElement("div");
  toolbar.className = "kf-ws-toolbar";
  const gotoInput = document.createElement("input");
  gotoInput.className = "dbg-input mono";
  gotoInput.placeholder = "go to address (Ctrl+G)";
  gotoInput.spellcheck = false;
  const engineStatus = document.createElement("span");
  engineStatus.className = "dim kf-ws-engine";
  toolbar.append(gotoInput, engineStatus);

  // body: side (functions) + main (tabs)
  const body = document.createElement("div");
  body.className = "kf-ws-body";
  const side = document.createElement("div");
  side.className = "kf-ws-side";
  const sideHead = document.createElement("div");
  sideHead.className = "kf-ws-side-head";
  sideHead.textContent = "Functions";
  const funcList = document.createElement("div");
  funcList.className = "kf-ws-funcs";
  side.append(sideHead, funcList);

  const main = document.createElement("div");
  main.className = "kf-ws-main";
  const tabbar = document.createElement("div");
  tabbar.className = "dbg-tabbar";
  const content = document.createElement("div");
  content.className = "dbg-content kf-ws-content";
  main.append(tabbar, content);
  body.append(side, main);

  const statusbar = document.createElement("div");
  statusbar.className = "dbg-status kf-ws-status";

  // resize grips
  const gripSe = document.createElement("div");
  gripSe.className = "kf-ws-grip-se";

  element.append(head, toolbar, body, statusbar, gripSe);
  (document.body ?? element.ownerDocument?.body)?.append(element);

  // ---- geometry / drag / resize ----------------------------------------------

  const vw = () => window.innerWidth || 1200;
  const vh = () => window.innerHeight || 800;
  let rect = {
    x: Math.max(16, Math.round(vw() * 0.08)),
    y: Math.max(16, Math.round(vh() * 0.06)),
    w: Math.min(1180, Math.round(vw() * 0.82)),
    h: Math.min(760, Math.round(vh() * 0.8)),
  };
  let minimized = false;

  function applyRect() {
    rect.w = Math.min(Math.max(rect.w, 520), vw() - 24);
    rect.h = Math.min(Math.max(rect.h, 320), vh() - 24);
    rect.x = Math.min(Math.max(rect.x, 4), Math.max(4, vw() - 80));
    rect.y = Math.min(Math.max(rect.y, 4), Math.max(4, vh() - 60));
    if (!minimized) {
      element.style.left = `${rect.x}px`;
      element.style.top = `${rect.y}px`;
      element.style.width = `${rect.w}px`;
      element.style.height = `${rect.h}px`;
    }
  }

  let drag = null;
  head.addEventListener("mousedown", (e) => {
    if (e.target.closest("button")) return;
    drag = { mode: "move", dx: e.clientX - rect.x, dy: e.clientY - rect.y };
    e.preventDefault();
  });
  gripSe.addEventListener("mousedown", (e) => {
    drag = { mode: "resize", sx: e.clientX, sy: e.clientY, w: rect.w, h: rect.h };
    e.preventDefault();
    e.stopPropagation();
  });
  const onMove = (e) => {
    if (!drag) return;
    if (drag.mode === "move") {
      rect.x = e.clientX - drag.dx;
      rect.y = e.clientY - drag.dy;
    } else {
      rect.w = drag.w + (e.clientX - drag.sx);
      rect.h = drag.h + (e.clientY - drag.sy);
    }
    applyRect();
  };
  const onUp = () => { drag = null; };
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);

  function bringToFront() {
    element.style.zIndex = String(++zTop);
    if (minimized) restore();
    element.classList.remove("minimized");
    try { element.focus({ preventScroll: true }); } catch { /* headless */ }
  }
  element.addEventListener("mousedown", bringToFront);

  function minimize() {
    minimized = true;
    element.classList.add("minimized");
    chip.style.display = "";
  }
  function restore() {
    minimized = false;
    element.classList.remove("minimized");
    chip.style.display = "none";
    applyRect();
  }
  btnMin.addEventListener("click", minimize);
  btnClose.addEventListener("click", () => facade.close());

  // minimize chip
  const chip = document.createElement("button");
  chip.className = "kf-ws-chip";
  chip.textContent = `\u2697 ${title}`;
  chip.title = "Restore analysis workspace";
  chip.style.display = "none";
  chip.addEventListener("click", () => { restore(); bringToFront(); });
  (document.body ?? element.ownerDocument?.body)?.append(chip);

  // ---- views ------------------------------------------------------------------

  let extraRefresh = null;
  const disasm = createDisasmView({ session: session ?? stubSession() });
  const pseudo = createPseudocodeView({ decompiler });
  const hex = createHexView({ session: session ?? stubSession() });
  const cfg = createCfgView({ session: session ?? stubSession() });
  const script = createScriptView({ session: session ?? stubSession() });

  let current = null; // BigInt address under the crosshair
  const followAddr = (addr, opts2 = {}) => {
    const big = typeof addr === "bigint" ? addr : toBig(addr);
    if (big === null) return;
    current = big;
    activateTab(opts2.tab ?? activeTabId ?? "disasm");
    disasm.show(big);
    void pseudo.show(big.toString(16));
    cfg.setEntry(big);
    renderSide(big);
    gotoInput.value = big.toString(16);
    statusbar.textContent = `0x${fmtAddr(big)}${session ? "" : "  ·  static image"}`;
  };

  disasm.onFollow((addr) => followAddr(addr));
  cfg.onFollow((addr) => followAddr(addr));

  // ---- tabs -------------------------------------------------------------------

  /** @type {Map<string, {label:string, el:HTMLElement}>} */
  const tabs = new Map();
  const addTab = (id, label, el) => tabs.set(id, { label, el });
  addTab("disasm", "Disassembly", disasm.element);
  addTab("pseudo", "Pseudocode", pseudo.element);
  addTab("cfg", "CFG", cfg.element);
  addTab("script", "Script", script.element);
  addTab("memory", "Memory", hex.element);
  if (session) {
    const registers = createRegistersPanel();
    const stack = createCallStackPanel({});
    const bpsPanel = createBreakpointsPanel({ onChanged: () => {} });
    const threads = createThreadsPanel({});
    const modules = createModulesPanel({});
    addTab("registers", "Registers", registers.element);
    addTab("stack", "Stack", stack.element);
    addTab("breakpoints", "Breakpoints", bpsPanel.element);
    addTab("threads", "Threads", threads.element);
    addTab("modules", "Modules", modules.element);
    extraRefresh = async () => {
      const regs = await session.getRegisters().catch(() => []);
      registers.update(regs);
      await Promise.all([
        stack.refresh(session),
        bpsPanel.refresh(session),
        threads.refresh(session),
        modules.refresh(session),
      ]);
      hex.invalidate();
    };
  }

  for (const [id, t] of tabs) {
    const b = document.createElement("button");
    b.className = "dbg-tab";
    b.dataset.tab = id;
    b.textContent = t.label;
    b.addEventListener("click", () => activateTab(id));
    tabbar.append(b);
  }

  let activeTabId = null;
  function activateTab(id) {
    const t = tabs.get(id);
    if (!t) return;
    activeTabId = id;
    content.innerHTML = "";
    content.append(t.el);
    for (const b of tabbar.querySelectorAll(".dbg-tab")) {
      b.classList.toggle("active", b.dataset.tab === id);
    }
  }

  // ---- functions sidebar ---------------------------------------------------------

  async function loadFunctions() {
    funcList.innerHTML = "";
    let funcs = [];
    try {
      if (decompiler?.functions) {
        const analysis = await decompiler.functions();
        funcs = analysis?.funcs ?? [];
      } else if (session?.getModules) {
        const mods = await session.getModules().catch(() => []);
        funcs = mods.map((m) => ({ addr: m.base, size: m.size, name: m.name }));
      }
    } catch { /* empty */ }
    sideHead.textContent = funcs.length
      ? `Functions (${funcs.length})`
      : "Functions";
    for (const f of funcs.slice(0, 512)) {
      const big = toBig(f.addr ?? f.address ?? f.start ?? f);
      if (big === null) continue;
      const row = document.createElement("button");
      row.className = "kf-ws-func";
      row.dataset.addr = big.toString(16);
      row.innerHTML =
        `<span class="kf-ws-func-addr">${fmtAddr(big, 8)}</span>` +
        `<span class="kf-ws-func-size">${f.size ? `${f.size}b` : ""}</span>`;
      row.addEventListener("click", () => followAddr(big));
      funcList.append(row);
    }
  }
  function renderSide(activeBig) {
    for (const row of funcList.querySelectorAll(".kf-ws-func")) {
      row.classList.toggle(
        "active",
        activeBig !== null && row.dataset.addr === activeBig.toString(16),
      );
    }
  }

  // ---- goto + scoped hotkeys ------------------------------------------------------

  gotoInput.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const v = toBig(gotoInput.value);
    if (v !== null) followAddr(v);
    else gotoInput.reportValidity?.();
  });
  element.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === "g") {
      e.preventDefault();
      e.stopPropagation();
      gotoInput.focus();
      gotoInput.select();
    }
  });

  // ---- engine badge -----------------------------------------------------------------

  void (async () => {
    try {
      const ok = decompiler
        ? (decompiler.available ? !!(await decompiler.available()) : true)
        : false;
      engineStatus.textContent = ok
        ? "ghidra wasm \u2713"
        : "static analysis only (npm run vendor:ghidra)";
      engineStatus.classList.toggle("warn", !ok);
    } catch { /* leave blank */ }
  })();

  // ---- cfg hook ----------------------------------------------------------------

  let cfgShowFn = null;
  function cfgShow(big) { cfgShowFn?.(big); }
  void cfgShow; // kept for registerTab consumers

  // ---- boot ------------------------------------------------------------------------

  applyRect();
  activateTab("disasm");
  void loadFunctions();
  bringToFront();

  const facade = {
    element,
    chip,
    get current() { return current; },
    get minimized() { return minimized; },
    /** Register an extra view (cfg/script) at runtime. */
    registerTab(id, label, el, hooks = {}) {
      addTab(id, label, el);
      const b = document.createElement("button");
      b.className = "dbg-tab";
      b.dataset.tab = id;
      b.textContent = label;
      b.addEventListener("click", () => activateTab(id));
      tabbar.append(b);
      if (hooks.onFollow) {
        const prev = cfgShowFn;
        cfgShowFn = (big) => { prev?.(big); hooks.onFollow(big); };
      }
    },
    followAddr,
    minimize,
    restore,
    refresh: async () => {
      await disasm.refresh().catch(() => {});
      await extraRefresh?.()?.catch?.(() => {});
      void loadFunctions();
    },
    close() {
      onClose?.();
      this.dispose();
    },
    dispose() {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      disasm.dispose();
      hex.dispose();
      pseudo.dispose();
      cfg.dispose();
      script.dispose();
      chip.remove();
      element.remove();
      live.delete(facade);
    },
  };
  live.add(facade);
  return facade;
}

/** Minimal no-op session so views never crash before attach(). */
function stubSession() {
  return {
    paused: true,
    pauseCount: 0,
    onStateChange() { return () => {}; },
    async getRegisters() { return []; },
    async disassemble() { return []; },
    async readMemory() { return new Uint8Array(0); },
    async writeMemory() {},
    async getModules() { return []; },
    async getThreads() { return []; },
    async getCallStack() { return []; },
    async getMemoryRegions() { return []; },
    async setBreakpoint(a) { return [{ address: a, type: 0, enabled: true }]; },
    async clearBreakpoint() { return []; },
    async listBreakpoints() { return []; },
  };
}
