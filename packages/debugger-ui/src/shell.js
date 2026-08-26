/**
 * shell.js — the docked debugger shell.
 *
 * Vanilla-JS port of the sogen.dev playground debugger UX: resizable right
 * panel, transport toolbar (F5/F10/F11/Shift+F11/Ctrl+G), tabs for
 * Disassembly | Registers | Memory | Stack | Breakpoints | Threads | Modules
 * | Pseudocode | Console, and a pause-generation refresh model keyed off the
 * session's `pauseCount`.
 *
 * Host integration contract (mirrors apps/web debugger adapters):
 *   const shell = createDebuggerShell(el, { session, consoleFactory });
 *   shell.write("banner")      -> routed to the Console tab
 *   await shell.exec("line")   -> routed to the Console tab's onSubmit path
 *
 * Everything reads state through the DebugSession contract only.
 */

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
import { toBig, fmtAddr } from "./session.mjs";

/** All live shells; disposed together on lesson re-render. */
const live = new Set();
export function disposeShells() {
  for (const s of [...live]) {
    try { s.dispose(); } catch { /* best effort */ }
  }
  live.clear();
}

/**
 * @param {HTMLElement} host mount point (the shell fills it)
 * @param {object} opts
 * @param {import("./session.mjs").DebugSession} opts.session
 * @param {string} [opts.title]
 * @param {(tabHost: HTMLElement) => {write?: Function, clear?: Function,
 *   exec?: Function, dispose?: Function}} [opts.consoleFactory]
 * @param {{decompile: (addr: string) => Promise<{c: string}>}} [opts.decompiler]
 * @param {(addrBig: bigint) => void} [opts.onFollow]
 * @param {"disasm"|"console"} [opts.initialTab]
 * @param {boolean} [opts.closable]
 */
export function createDebuggerShell(host, opts = {}) {
  const {
    session,
    title = "Debugger",
    consoleFactory = null,
    decompiler = null,
    onFollow = null,
    initialTab = "disasm",
    closable = false,
  } = opts;

  // ---- skeleton ------------------------------------------------------------

  const element = document.createElement("div");
  element.className = "dbg-shell";

  const grip = document.createElement("div");
  grip.className = "dbg-grip";
  grip.title = "Drag to resize";

  const toolbar = document.createElement("div");
  toolbar.className = "dbg-toolbar";
  const titleSpan = document.createElement("span");
  titleSpan.className = "dbg-title";
  titleSpan.textContent = title;
  toolbar.append(titleSpan);

  const tabbar = document.createElement("div");
  tabbar.className = "dbg-tabbar";

  const content = document.createElement("div");
  content.className = "dbg-content";

  const statusbar = document.createElement("div");
  statusbar.className = "dbg-status";
  statusbar.textContent = "paused";

  element.append(grip, toolbar, tabbar, content, statusbar);
  host.append(element);

  let width = Math.min(900, Math.round((typeof window !== "undefined" ? window.innerWidth : 1200) * 0.42));
  applyWidth(width);
  function applyWidth(w) {
    width = Math.min(Math.max(w, 480), typeof window !== "undefined" ? window.innerWidth - 160 : 1040);
    element.style.width = `${width}px`;
  }

  // ---- views ---------------------------------------------------------------

  const disasm = createDisasmView({ session });
  const registers = createRegistersPanel();
  const hex = createHexView({ session });
  const stack = createCallStackPanel({ onFollow });
  const bpsPanel = createBreakpointsPanel({ onFollow, onChanged: () => refreshAll() });
  const threads = createThreadsPanel({ onFollow });
  const modules = createModulesPanel({ onFollow });
  const pseudo = createPseudocodeView({ decompiler });
  const cfg = createCfgView({ session });

  const followAddr = (addr) => {
    const big = toBig(addr);
    if (big === null) return;
    activateTab("disasm");
    disasm.show(big);
    cfg.setEntry(big);
    if (onFollow) onFollow(big);
  };
  disasm.onFollow(followAddr);
  cfg.onFollow((addr) => followAddr(addr));

  // ---- tabs ----------------------------------------------------------------

  /** @type {Map<string, {label: string, el: HTMLElement, onShow?: Function}>} */
  const tabs = new Map();
  const addTab = (id, label, el, onShow) => tabs.set(id, { label, el, onShow });

  addTab("disasm", "Disassembly", disasm.element);
  addTab("registers", "Registers", registers.element);
  addTab("memory", "Memory", hex.element);
  addTab("stack", "Stack", stack.element);
  addTab("breakpoints", "Breakpoints", bpsPanel.element);
  addTab("threads", "Threads", threads.element);
  const script = createScriptView({ session });
  addTab("modules", "Modules", modules.element);
  addTab("cfg", "CFG", cfg.element);
  addTab("pseudocode", "Pseudocode", pseudo.element);
  addTab("script", "Script", script.element);
  if (consoleFactory) {
    const consoleHost = document.createElement("div");
    consoleHost.className = "dbg-console-host";
    const adapter = consoleFactory(consoleHost) ?? {};
    addTab("console", "Console", consoleHost, () => {
      if (!consoleAdapter) setConsoleAdapter(adapter);
    });
  }

  for (const [id, t] of tabs) {
    const btn = document.createElement("button");
    btn.className = "dbg-tab";
    btn.dataset.tab = id;
    btn.textContent = t.label;
    btn.addEventListener("click", () => activateTab(id));
    tabbar.append(btn);
  }

  let activeTabId = null;
  let consoleAdapter = null;
  const pendingWrites = [];

  function setConsoleAdapter(a) {
    consoleAdapter = a;
    for (const [text, cls] of pendingWrites.splice(0)) a.write?.(text, cls);
  }

  function activateTab(id) {
    activeTabId = id;
    const t = tabs.get(id);
    if (!t) return;
    content.innerHTML = "";
    content.append(t.el);
    for (const b of tabbar.querySelectorAll(".dbg-tab")) {
      b.classList.toggle("active", b.dataset.tab === id);
    }
    t.onShow?.();
  }

  // ---- console plumbing ------------------------------------------------------

  function write(text, cls = "") {
    if (consoleAdapter) consoleAdapter.write?.(text, cls);
    else pendingWrites.push([text, cls]);
  }

  async function exec(line) {
    if (!line || !String(line).trim()) return;
    if (!consoleAdapter) {
      activateTab("console");
    }
    await consoleAdapter?.exec?.(line);
    scheduleRefresh();
  }

  // ---- toolbar ---------------------------------------------------------------

  const button = (label, title2, onClick) => {
    const b = document.createElement("button");
    b.className = "dbg-btn";
    b.textContent = label;
    b.title = title2;
    b.addEventListener("click", onClick);
    toolbar.append(b);
    return b;
  };

  const gotoInput = document.createElement("input");
  gotoInput.className = "dbg-input mono";
  gotoInput.placeholder = "go to address (Ctrl+G)";
  gotoInput.spellcheck = false;
  gotoInput.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    const v = toBig(gotoInput.value);
    if (v !== null) followAddr(v);
  });

  const btnRun = button("\u25b6", "Run (F5)", () => act(() => session.resume?.() ?? session.continueExecution?.()));
  const btnPause = button("\u23f8", "Pause", () => act(async () => { session.pause?.(); }));
  const btnInto = button("\u21b3", "Step Into (F11)", () => act(() => session.stepInto()));
  const btnOver = button("\u21b4", "Step Over (F10)", () => act(() => session.stepOver()));
  const btnOut = button("\u21b2", "Step Out (Shift+F11)", () => act(() => session.stepOut()));
  const btnRunTo = button("\u25c9", "Run To Cursor", () =>
    act(() => session.runTo(disasm.selected)));
  toolbar.append(gotoInput);
  let btnClose = null;
  if (closable) btnClose = button("\u00d7", "Close", () => opts.onClose?.());

  let acting = false;
  async function act(fn) {
    if (!session.paused || acting) return;
    acting = true;
    try {
      await fn();
    } catch (e) {
      statusOverride = `${e.message}`;
      renderStatus();
    } finally {
      acting = false;
      await refreshAll();
    }
  }

  // ---- state / refresh ---------------------------------------------------------

  let lastPauseCount = -1;
  let statusOverride = null;
  let refreshSeq = 0;
  let lastRegs = [];

  async function refreshAll() {
    const seq = ++refreshSeq;
    const regs = await session.getRegisters().catch(() => []);
    if (seq !== refreshSeq) return;
    lastRegs = regs;
    registers.update(regs);
    const ripReg = regs.find((r) => /^(rip|eip)$/i.test(r.name));
    const ripVal = ripReg ? ripReg.value : 0n;
    await disasm.syncRip(ripVal);
    if (seq !== refreshSeq) return;
    hex.invalidate();
    await Promise.all([
      stack.refresh(session),
      bpsPanel.refresh(session),
      threads.refresh(session),
      modules.refresh(session),
    ]);
    renderStatus();
  }

  function renderStatus() {
    if (statusOverride && !session.paused) {
      statusbar.textContent = statusOverride;
      return;
    }
    statusOverride = null;
    const ripReg = lastRegs.find((r) => /^(rip|eip)$/i.test(r.name));
    statusbar.textContent = session.paused
      ? `stopped @ 0x${fmtAddr(ripReg?.value ?? 0, 8)}`
      : "running\u2026";
    btnRun.disabled = !session.paused;
    btnPause.disabled = !!session.paused;
    for (const b of [btnInto, btnOver, btnOut, btnRunTo]) b.disabled = !session.paused;
  }

  function scheduleRefresh() {
    // console commands may mutate world state without flipping paused;
    // hosts call shell.refresh() too — debounce lightly.
    setTimeout(() => { void refreshAll(); }, 50);
  }

  // poll pauseCount like upstream (steps coalesce the running state away)
  const pollTimer = setInterval(() => {
    if (session.pauseCount !== undefined && session.pauseCount !== lastPauseCount) {
      lastPauseCount = session.pauseCount;
      void refreshAll();
    }
  }, 120);
  pollTimer.unref?.(); // never hold the process open (node --test)

  const unsubState = session.onStateChange?.(() => void refreshAll());

  // ---- hotkeys ----------------------------------------------------------------

  const onKey = (e) => {
    // never steal keys from code editors or the floating workspace
    if (e.target.closest?.(".kf-monaco-host") || e.target.closest?.(".kf-ws")) return;
    if (e.key === "F5") {
      e.preventDefault();
      if (session.paused) act(() => session.resume?.() ?? session.continueExecution?.());
    } else if (e.key === "F10") {
      e.preventDefault();
      act(() => session.stepOver());
    } else if (e.key === "F11" && !e.shiftKey) {
      e.preventDefault();
      act(() => session.stepInto());
    } else if (e.key === "F11" && e.shiftKey) {
      e.preventDefault();
      act(() => session.stepOut());
    } else if (e.ctrlKey && e.key.toLowerCase() === "g" &&
               !e.target.closest?.(".kf-monaco-host")) {
      e.preventDefault();
      gotoInput.focus();
    }
  };
  window.addEventListener("keydown", onKey);

  // ---- resize grip ---------------------------------------------------------------

  let dragging = false;
  const onMove = (e) => {
    if (!dragging) return;
    applyWidth(window.innerWidth - e.clientX);
  };
  const onUp = () => {
    dragging = false;
    document.body.style.userSelect = "";
  };
  grip.addEventListener("mousedown", (e) => {
    e.preventDefault();
    dragging = true;
    document.body.style.userSelect = "none";
  });
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);

  // ---- boot ---------------------------------------------------------------------

  activateTab(initialTab === "console" && tabs.has("console") ? "console" : "disasm");
  void refreshAll();

  const facade = {
    element,
    exec,
    write,
    focus: () => consoleAdapter?.focusTarget?.focus?.(),
    refresh: () => refreshAll(),
    followAddr,
    get paused() { return !!session.paused; },
    get activeTab() { return activeTabId; },
    dispose() {
      clearInterval(pollTimer);
      unsubState?.();
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      for (const v of [disasm, hex, pseudo, cfg, script]) v.dispose?.();
      consoleAdapter?.dispose?.();
      element.remove();
      live.delete(facade);
    },
  };
  live.add(facade);
  return facade;
}
