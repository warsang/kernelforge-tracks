/**
 * views/cfg.js — control-flow graph tab.
 *
 * Vanilla port of upstream sogen's page/src/components/cfg-view.tsx:
 * self-contained SVG renderer (no graph library). Basic blocks are derived
 * client-side from the ordinary disassemble command (classic leaders),
 * laid out in BFS layers, drawn as rounded rects + bezier edges with
 * wheel-zoom / drag-pan, the current-instruction block highlighted.
 *
 * Pure logic (buildBlocks / layoutBlocks) is exported for headless tests;
 * rendering consumes only their output.
 */

import { toBig, fmtAddr } from "../session.mjs";

const MAX_INSNS = 400;
const BLOCK_W = 240;
const LINE_H = 16;
const PAD_X = 10;
const PAD_Y = 8;
const GAP_X = 60;
const GAP_Y = 50;

// ---------------------------------------------------------------------------
// pure core
// ---------------------------------------------------------------------------

const isUncondJmp = (m) => /^jmp\b/.test(m);
const isCondJmp = (m) => /^j(?!mp)/.test(m);
const isRet = (m) => /^(ret|iret|retf|leave)/.test(m);
const endsBlock = (m) => isUncondJmp(m) || isCondJmp(m) || isRet(m);

function targetOf(insn) {
  const t = insn.branch ?? (() => {
    const m = /0x([0-9a-fA-F]+)/.exec(String(insn.operands ?? ""));
    return m ? m[1] : null;
  })();
  return toBig(t);
}

/**
 * Partition a linear instruction stream into basic blocks.
 * @param {Array<{address:string,size:number,mnemonic:string,operands:string,
 *                branch?:string}>} insns ascending by address
 * @returns {Map<bigint,{start:bigint,end:bigint,insns:object[]}>} keyed by start
 */
export function buildBlocks(insns) {
  const byAddr = new Map();
  for (const i of insns) byAddr.set(toBig(i.address) ?? 0n, i);

  /** @type {Set<bigint>} */
  const leaders = new Set();
  if (insns.length) leaders.add(toBig(insns[0].address));
  insns.forEach((insn, k) => {
    const m = insn.mnemonic ?? "";
    const next = insns[k + 1];
    if (endsBlock(m) && next) {
      leaders.add(toBig(next.address));
    }
    const t = targetOf(insn);
    if ((isUncondJmp(m) || isCondJmp(m)) && byAddr.has(t)) leaders.add(t);
  });

  const startsSorted = [...leaders].sort((a, b) => (a < b ? -1 : 1));
  /** @type {Map<bigint,{start,end,insns}>} */
  const blocks = new Map();
  let cur = null;
  const flush = () => {
    if (!cur?.insns.length) return;
    const last = cur.insns[cur.insns.length - 1];
    cur.end = (toBig(last.address) ?? 0n) + BigInt(last.size ?? 1);
    blocks.set(cur.start, cur);
  };
  for (const insn of insns) {
    const a = toBig(insn.address);
    if (leaders.has(a) || !cur) {
      flush();
      cur = { start: a, end: a, insns: [] };
    }
    cur.insns.push(insn);
  }
  flush();

  // successors
  const starts = [...blocks.keys()].sort((a, b) => (a < b ? -1 : 1));
  for (let k = 0; k < starts.length; k++) {
    const b = blocks.get(starts[k]);
    const last = b.insns[b.insns.length - 1];
    const m = last.mnemonic ?? "";
    const t = targetOf(last);
    b.succs = [];
    if (isRet(m)) continue;
    if (isUncondJmp(m)) {
      if (byAddr.has(t)) b.succs.push(t);
    } else if (isCondJmp(m)) {
      if (byAddr.has(t)) b.succs.push(t);
      const fall = starts[k + 1];
      if (fall !== undefined) b.succs.push(fall);
    } else {
      const fall = starts[k + 1];
      if (fall !== undefined) b.succs.push(fall);
    }
  }
  return blocks;
}

/**
 * BFS layering: depth -> row, discovery order -> column.
 * @returns {{nodes: Array<{block,start,x,y,w,h}>, edges: Array<{from,to}>}}
 */
export function layoutBlocks(blocks, entryBig) {
  const entry = blocks.has(entryBig)
    ? entryBig
    : [...blocks.keys()].sort((a, b) => (a < b ? -1 : 1))[0];

  const depth = new Map([[entry, 0]]);
  const orderInLayer = new Map();
  let frontier = [entry];
  while (frontier.length) {
    const next = [];
    for (const s of frontier) {
      const d = depth.get(s);
      for (const t of blocks.get(s)?.succs ?? []) {
        if (!blocks.has(t)) continue;
        if (!depth.has(t)) {
          depth.set(t, d + 1);
          orderInLayer.set(t, (orderInLayer.get(d + 1) ?? -1) + 1);
          next.push(t);
        }
      }
    }
    frontier = next;
  }

  const colCounters = new Map();
  const nodes = [];
  for (const [start, b] of blocks) {
    const d = depth.get(start) ?? 9999;
    const col = colCounters.get(d) ?? 0;
    colCounters.set(d, col + 1);
    const h = PAD_Y * 2 + b.insns.length * LINE_H;
    nodes.push({
      start,
      block: b,
      x: col * (BLOCK_W + GAP_X),
      y: d * (200 + GAP_Y),
      w: BLOCK_W,
      h,
    });
  }
  const edges = [];
  for (const n of nodes) {
    for (const t of n.block.succs ?? []) edges.push({ from: n.start, to: t });
  }
  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// view
// ---------------------------------------------------------------------------

export function createCfgView({ session }) {
  const element = document.createElement("div");
  element.className = "dbg-cfg";
  const viewport = document.createElement("div");
  viewport.className = "dbg-cfg-viewport";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("dbg-cfg-svg");
  const gRoot = document.createElementNS("http://www.w3.org/2000/svg", "g");
  svg.append(gRoot);
  const hint = document.createElement("div");
  hint.className = "dim dbg-cfg-hint";
  hint.textContent = "wheel: zoom · drag: pan · click block header: follow in disassembly";
  viewport.append(svg);
  element.append(hint, viewport);

  let scale = 0.9;
  let panX = 20;
  let panY = 20;
  let nodeByStart = new Map();
  let currentEntry = null;

  const applyTransform = () =>
    gRoot.setAttribute("transform", `translate(${panX},${panY}) scale(${scale})`);

  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    scale = Math.min(2.5, Math.max(0.15, scale * factor));
    applyTransform();
  }, { passive: false });

  let panning = null;
  svg.addEventListener("mousedown", (e) => {
    panning = { x: e.clientX, y: e.clientY, px: panX, py: panY };
  });
  const onMove = (e) => {
    if (!panning) return;
    panX = panning.px + (e.clientX - panning.x);
    panY = panning.py + (e.clientY - panning.y);
    applyTransform();
  };
  const onUp = () => { panning = null; };
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);

  function render(nodes, edges, ripBig) {
    gRoot.innerHTML = "";
    nodeByStart = new Map(nodes.map((n) => [n.start, n]));
    const pos = new Map(nodes.map((n) => [n.start, n]));

    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    defs.innerHTML =
      '<marker id="cfg-arrow" viewBox="0 0 10 10" refX="9" refY="5" ' +
      'markerWidth="7" markerHeight="7" orient="auto-start-reverse">' +
      '<path d="M 0 0 L 10 5 L 0 10 z" fill="#6e7681"/></marker>';
    gRoot.append(defs);

    for (const e of edges) {
      const a = pos.get(e.from);
      const b = pos.get(e.to);
      if (!a || !b) continue;
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      const x1 = a.x + a.w;
      const y1 = a.y + a.h / 2;
      const x2 = b.x;
      const y2 = b.y + b.h / 2;
      const mx = (x1 + x2) / 2;
      path.setAttribute("d",
        `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`);
      path.setAttribute("class", "cfg-edge" +
        (isCondPath(a, e.to) ? " cfg-edge-cond" : ""));
      path.setAttribute("marker-end", "url(#cfg-arrow)");
      gRoot.append(path);
    }

    for (const n of nodes) {
      const grp = document.createElementNS("http://www.w3.org/2000/svg", "g");
      grp.setAttribute("transform", `translate(${n.x},${n.y})`);
      grp.classList.add("cfg-block");
      const containsRip = ripBig !== null &&
        ripBig >= n.block.start && ripBig < n.block.end;
      if (containsRip) grp.classList.add("current");

      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("width", String(n.w));
      rect.setAttribute("height", String(n.h));
      rect.setAttribute("rx", "7");

      const title = document.createElementNS("http://www.w3.org/2000/svg", "text");
      title.setAttribute("class", "cfg-title");
      title.setAttribute("x", String(PAD_X));
      title.setAttribute("y", String(PAD_Y + 9));
      title.textContent = `sub_${fmtAddr(n.block.start, 8)}`;

      const bodyText = document.createElementNS("http://www.w3.org/2000/svg", "text");
      bodyText.setAttribute("class", "cfg-insns");
      bodyText.setAttribute("x", String(PAD_X));
      n.block.insns.slice(0, 14).forEach((insn, k) => {
        const tspan = document.createElementNS(
          "http://www.w3.org/2000/svg", "tspan");
        tspan.setAttribute("x", String(PAD_X));
        tspan.setAttribute("y", String(PAD_Y + 26 + k * LINE_H));
        const ops = insn.branch
          ? `0x${String(insn.branch).replace(/^0x/i, "")}`
          : String(insn.operands ?? "");
        tspan.textContent =
          `${fmtAddr(insn.address, 8)}  ${insn.mnemonic} ${ops}`.slice(0, 34);
        bodyText.append(tspan);
      });
      if (n.block.insns.length > 14) {
        const more = document.createElementNS(
          "http://www.w3.org/2000/svg", "tspan");
        more.setAttribute("x", String(PAD_X));
        more.setAttribute("y", String(PAD_Y + 26 + 14 * LINE_H));
        more.textContent = `… +${n.block.insns.length - 14} more`;
        bodyText.append(more);
      }

      const hit = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      hit.setAttribute("width", String(n.w));
      hit.setAttribute("height", String(n.h));
      hit.setAttribute("fill", "transparent");
      hit.addEventListener("dblclick", () => {
        followCb?.(n.block.start);
      });

      grp.append(rect, title, bodyText, hit);
      gRoot.append(grp);
    }
    applyTransform();
  }

  function isCondPath(fromNode, toStart) {
    const last = fromNode.block.insns[fromNode.block.insns.length - 1];
    return isCondJmp(last?.mnemonic ?? "") && targetOf(last) === toStart;
  }

  async function rebuild(entryBig) {
    currentEntry = entryBig;
    if (!session?.disassemble || entryBig === null) return;
    const insns = await session.disassemble(entryBig.toString(16), MAX_INSNS)
      .catch(() => []);
    if (!insns.length) {
      gRoot.innerHTML = "";
      hint.textContent = "no instructions at this address";
      return;
    }
    hint.textContent = "wheel: zoom · drag: pan · dblclick block header: follow";
    const blocks = buildBlocks(insns);
    let ripBig = null;
    try {
      const regs = await session.getRegisters().catch(() => []);
      const ripReg = regs.find((r) => /^(rip|eip)$/i.test(r.name));
      ripBig = ripReg ? toBig(ripReg.value) : null;
    } catch { /* static */ }
    const { nodes, edges } = layoutBlocks(blocks, entryBig);
    render(nodes, edges, ripBig);
  }

  const followCbs = new Set();
  const followCb = (addr) => { for (const cb of followCbs) cb(addr); };

  return {
    element,
    setEntry(addrBig) {
      const big = typeof addrBig === "bigint" ? addrBig : toBig(addrBig);
      if (big === null) return;
      // skip identical rebuilds (upstream: rebuild only when RIP left blocks)
      if (big === currentEntry) return;
      void rebuild(big);
    },
    onFollow(cb) { return followCbs.add(cb), () => followCbs.delete(cb); },
    dispose() {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      element.remove();
    },
  };
}
