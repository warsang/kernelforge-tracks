/**
 * views/hexdump.js — windowed memory hex viewer.
 *
 * Address box + size selector + 16-bytes-per-row grid (hex | ascii) over the
 * DebugSession.readMemory contract. Chunks are cached per pause generation;
 * callers bump `invalidate()` when state changes.
 */

import { toBig, fmtAddr, hexBytes, asciiBytes } from "../session.mjs";

const ROW_BYTES = 16;
const ROW_H = 18;
const CHUNK = 256; // bytes fetched per readMemory call

export function createHexView({ session, base = "00007fff0000", size = 0x1000 }) {
  const element = document.createElement("div");
  element.className = "dbg-hex";

  const bar = document.createElement("div");
  bar.className = "dbg-hex-bar";
  const addrInput = document.createElement("input");
  addrInput.className = "dbg-input mono";
  addrInput.placeholder = "go to address";
  addrInput.spellcheck = false;
  const sizeSel = document.createElement("select");
  sizeSel.className = "dbg-select";
  for (const s of [0x100, 0x1000, 0x10000]) {
    const o = document.createElement("option");
    o.value = String(s);
    o.textContent = `0x${s.toString(16)}`;
    if (s === size) o.selected = true;
    sizeSel.append(o);
  }
  bar.append(addrInput, sizeSel);
  element.append(bar);

  const viewport = document.createElement("div");
  viewport.className = "dbg-hex-viewport";
  const spacer = document.createElement("div");
  spacer.className = "dbg-spacer";
  viewport.append(spacer);
  element.append(viewport);

  let viewBase = toBig(base) ?? 0n;
  let viewSize = size;
  /** @type {Map<number, Uint8Array>} chunkStart -> bytes */
  let chunks = new Map();
  let disposed = false;

  function invalidate() {
    chunks = new Map();
    repaint();
  }

  async function chunk(start) {
    const key = Number(start);
    let c = chunks.get(key);
    if (!c) {
      c = await session
        .readMemory(start.toString(16), CHUNK)
        .catch(() => new Uint8Array(CHUNK));
      chunks.set(key, c);
    }
    return c;
  }

  async function renderRow(rowIdx, top) {
    const rowAddr = viewBase + BigInt(rowIdx * ROW_BYTES);
    const chunkStart = (rowAddr / BigInt(CHUNK)) * BigInt(CHUNK);
    const c = await chunk(chunkStart);
    if (disposed) return null;
    const offInto = Number(rowAddr - chunkStart);

    const row = document.createElement("div");
    row.className = "dbg-row hex";
    row.style.top = `${top}px`;

    const addr = document.createElement("span");
    addr.className = "dbg-addr";
    addr.textContent = fmtAddr(rowAddr);
    row.append(addr);

    const bytesEl = document.createElement("span");
    bytesEl.className = "mono";
    const slice = c.slice(offInto, offInto + ROW_BYTES);
    bytesEl.textContent = hexBytes(slice).padEnd(ROW_BYTES * 3 - 1, " ");
    row.append(bytesEl);

    const asc = document.createElement("span");
    asc.className = "dbg-ascii";
    asc.textContent = asciiBytes(slice);
    row.append(asc);
    return row;
  }

  let paintSeq = 0;
  async function repaint() {
    const seq = ++paintSeq;
    const rows = Math.ceil(viewSize / ROW_BYTES);
    for (const el of [...viewport.querySelectorAll(".dbg-row")]) el.remove();
    spacer.style.height = `${rows * ROW_H}px`;
    const top = viewport.scrollTop;
    const bottom = top + (viewport.clientHeight || 400);
    const first = Math.max(0, Math.floor(top / ROW_H) - 4);
    const last = Math.min(rows, Math.ceil(bottom / ROW_H) + 4);
    for (let i = first; i < last; i++) {
      const row = await renderRow(i, i * ROW_H);
      if (seq !== paintSeq || !row) return;
      viewport.append(row);
    }
  }

  const submit = () => {
    const v = toBig(addrInput.value);
    if (v !== null) {
      viewBase = v;
      invalidate();
      viewport.scrollTop = 0;
      repaint();
    }
  };
  addrInput.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  sizeSel.addEventListener("change", () => {
    viewSize = Number(sizeSel.value);
    viewport.scrollTop = 0;
    repaint();
  });
  viewport.addEventListener("scroll", () => repaint());
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => repaint()).observe(viewport);
  }

  return {
    element,
    show(addr) {
      const v = toBig(addr);
      if (v === null) return;
      viewBase = v;
      invalidate();
    },
    invalidate,
    dispose() {
      disposed = true;
      element.remove();
    },
  };
}
