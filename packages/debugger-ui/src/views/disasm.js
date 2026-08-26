/**
 * views/disasm.js — virtualized disassembly view.
 *
 * UX port of upstream sogen's debugger-view disassembly tab (react-window
 * infinite scroll, breakpoint gutter dots, current-instruction highlight,
 * clickable branch targets, upward self-synchronizing decode) in vanilla JS
 * against the DebugSession contract.
 */

import { toBig, fmtAddr } from "../session.mjs";

const ROW_H = 20;
const INITIAL_COUNT = 256;
const BATCH = 128;
const EDGE_ROWS = 12;
const BACK_WINDOWS = [48, 64, 96, 128, 192];
const MAX_INSNS = 20000;

/**
 * @param {{element: HTMLElement}} _ unused
 * @param {object} opts
 * @param {import("../session.mjs").DebugSession} opts.session
 */
export function createDisasmView(opts) {
  const { session } = opts;

  const element = document.createElement("div");
  element.className = "dbg-disasm";

  const viewport = document.createElement("div");
  viewport.className = "dbg-disasm-viewport";
  const spacer = document.createElement("div");
  spacer.className = "dbg-spacer";
  viewport.append(spacer);
  element.append(viewport);

  let insns = [];
  let ripHex = null;
  /** @type {Set<string>} */
  let bps = new Set();
  let engaged = false;
  let loading = false;
  let disposed = false;

  const followCbs = new Set();
  const onFollow = (cb) => (followCbs.add(cb), () => followCbs.delete(cb));
  const follow = (addr) => { for (const cb of followCbs) cb(addr); };

  // ---- row rendering -------------------------------------------------------

  function renderRow(insn, idx) {
    const isCurrent = ripHex !== null && insn.address === ripHex.replace(/^0x/i, "");
    const hasBp = bps.has(insn.address);
    const row = document.createElement("div");
    row.className = "dbg-row" + (isCurrent ? " current" : "");
    row.style.top = `${idx * ROW_H}px`;

    const dot = document.createElement("button");
    dot.className = "dbg-bp-dot" + (hasBp ? " set" : "");
    dot.title = "Toggle breakpoint";
    dot.addEventListener("click", () => toggleBp(insn.address));
    row.append(dot);

    const addr = document.createElement("span");
    addr.className = "dbg-addr" + (isCurrent ? " current" : "");
    addr.textContent = (isCurrent ? "\u25b6 " : "  ") + insn.address;
    row.append(addr);

    const mnem = document.createElement("span");
    mnem.className = "dbg-mnem";
    mnem.textContent = insn.mnemonic;
    row.append(mnem);

    const ops = document.createElement("span");
    ops.className = "dbg-ops";
    if (insn.branch) {
      const link = document.createElement("button");
      link.className = "dbg-branch";
      link.textContent = insn.operands || "(branch)";
      link.addEventListener("click", () => follow(toBig(insn.branch)));
      ops.append(link);
    } else {
      ops.textContent = insn.operands ?? "";
    }
    if (insn.symbol) {
      const sym = document.createElement("span");
      sym.className = "dbg-symbol";
      sym.textContent = ` ; ${insn.symbol}`;
      ops.append(sym);
    }
    row.append(ops);
    return row;
  }

  function repaint() {
    const height = Math.max(insns.length * ROW_H, viewport.clientHeight || 0);
    spacer.style.height = `${height}px`;
    const top = viewport.scrollTop;
    const bottom = top + (viewport.clientHeight || 400);
    const first = Math.max(0, Math.floor(top / ROW_H) - EDGE_ROWS);
    const last = Math.min(insns.length, Math.ceil(bottom / ROW_H) + EDGE_ROWS);

    for (const el of [...viewport.querySelectorAll(".dbg-row")]) el.remove();
    for (let i = first; i < last; i++) {
      const insn = insns[i];
      if (!insn) continue;
      viewport.append(renderRow(insn, i));
    }

    // edge-triggered extension
    const visFirst = Math.floor(top / ROW_H);
    const visLast = Math.ceil(bottom / ROW_H);
    if (visFirst > EDGE_ROWS) engaged = true;
    if (!loading && insns.length) {
      const nearBottom = visLast >= insns.length - EDGE_ROWS;
      const nearTop = engaged && visFirst <= EDGE_ROWS;
      if (nearBottom || nearTop) {
        loading = true;
        (nearBottom ? extendDown() : extendUp()).finally(() => { loading = false; });
      }
    }
  }

  // ---- data ----------------------------------------------------------------

  async function toggleBp(addressHex) {
    const key = String(addressHex).replace(/^0x/i, "");
    if (bps.has(key)) {
      const list = await session.clearBreakpoint(key).catch(() => null);
      applyBps(list);
    } else {
      const list = await session.setBreakpoint(key).catch(() => null);
      applyBps(list);
    }
  }

  function applyBps(list) {
    bps = new Set((list ?? []).map((b) => String(b.address).replace(/^0x/i, "")));
    repaint();
  }

  async function extendDown() {
    const last = insns[insns.length - 1];
    if (!last) return;
    const nextAddr = BigInt("0x" + last.address) + BigInt(last.size || 1);
    const fetched = await session.disassemble(nextAddr.toString(16), BATCH).catch(() => []);
    const fresh = fetched.filter((i) => BigInt("0x" + String(i.address).replace(/^0x/i, "")) >= nextAddr);
    if (!fresh.length || disposed) return;
    insns = [...insns, ...fresh].slice(-MAX_INSNS);
    repaint();
  }

  async function extendUp() {
    const first = insns[0];
    if (!first) return;
    const firstAddr = BigInt("0x" + first.address);
    if (firstAddr === 0n) return;
    for (const win of BACK_WINDOWS) {
      const probe = firstAddr - BigInt(win);
      if (probe < 0n) continue;
      const fetched = await session.disassemble(probe.toString(16), win).catch(() => []);
      const hit = fetched.findIndex(
        (i) => BigInt("0x" + String(i.address).replace(/^0x/i, "")) === firstAddr);
      if (hit > 0 && !disposed) {
        insns = [...fetched.slice(0, hit), ...insns].slice(0, MAX_INSNS);
        repaint();
        return;
      }
    }
  }

  // ---- public --------------------------------------------------------------

  /** Reset the buffer to `count` instructions decoded from `addr`. */
  async function show(addr, count = INITIAL_COUNT) {
    const big = toBig(addr);
    if (big === null) return;
    insns = await session.disassemble(big.toString(16), count).catch(() => []);
    engaged = false;
    viewport.scrollTop = 0;
    repaint();
  }

  /** Highlight the instruction at `rip` and keep it in view. */
  async function syncRip(rip) {
    const big = toBig(rip);
    ripHex = big === null ? null : fmtAddr(big);
    if (big === null) return repaint();
    const idx = insns.findIndex((i) => i.address === ripHex);
    if (idx < 0) {
      await show(big);
      ripHex = fmtAddr(big);
    }
    const rowIdx = insns.findIndex((i) => i.address === ripHex);
    if (rowIdx >= 0) {
      const y = rowIdx * ROW_H;
      if (y < viewport.scrollTop || y > viewport.scrollTop + (viewport.clientHeight || 400) - ROW_H) {
        viewport.scrollTop = Math.max(0, y - (viewport.clientHeight || 400) / 2);
      }
    }
    repaint();
  }

  async function refresh() {
    const regs = await session.getRegisters().catch(() => []);
    const ripReg = regs.find((r) => /^(rip|eip)$/i.test(r.name));
    applyBps(await session.listBreakpoints().catch(() => []));
    await syncRip(ripReg ? ripReg.value : 0n);
  }

  viewport.addEventListener("scroll", repaint);
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => repaint()).observe(viewport);
  }

  return {
    element,
    show,
    syncRip,
    refresh,
    onFollow,
    get ripHex() { return ripHex; },
    get selected() { return ripHex; },
    dispose() {
      disposed = true;
      element.remove();
    },
  };
}
