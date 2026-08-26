/**
 * views/panels.js — the simple tabular debugger panels.
 *
 * Registers (two-column grid), Call Stack, Breakpoints, Threads, Modules —
 * each is a header + scrollable list fed by one DebugSession getter, with
 * optional click-to-follow wired by the shell.
 */

import { fmtAddr } from "../session.mjs";

function panelFrame(label) {
  const element = document.createElement("div");
  element.className = "dbg-panel";
  const head = document.createElement("div");
  head.className = "dbg-panel-head";
  head.textContent = label;
  const list = document.createElement("div");
  list.className = "dbg-list";
  element.append(head, list);
  return { element, list };
}

function row(cells, { follow, cls = "" } = {}) {
  const el = document.createElement("div");
  el.className = "dbg-list-row" + (cls ? ` ${cls}` : "");
  for (const c of cells) {
    const span = document.createElement("span");
    if (typeof c === "object") {
      span.textContent = c.text;
      span.className = c.cls ?? "";
    } else {
      span.textContent = c;
    }
    el.append(span);
  }
  if (follow) el.classList.add("followable"), el.addEventListener("click", follow);
  return el;
}

const emptyNote = (list, text) => {
  const el = document.createElement("div");
  el.className = "dim dbg-note";
  el.textContent = text;
  list.append(el);
};

// ---- registers -------------------------------------------------------------

export function createRegistersPanel() {
  const { element, list } = panelFrame("Registers");
  return {
    element,
    update(regs) {
      list.innerHTML = "";
      for (const r of regs ?? []) {
        list.append(row([
          { text: r.name, cls: "dim" },
          { text: String(r.value).replace(/^0x/, "") },
        ], { cls: "mono reg" }));
      }
    },
    dispose() { element.remove(); },
  };
}

// ---- call stack ------------------------------------------------------------

export function createCallStackPanel({ onFollow } = {}) {
  const { element, list } = panelFrame("Call Stack");
  return {
    element,
    async refresh(session) {
      list.innerHTML = "";
      const frames = await session.getCallStack?.().catch(() => null);
      if (!frames?.length) return emptyNote(list, "no frames.");
      for (const f of frames) {
        list.append(row(
          [
            { text: fmtAddr(f.ip), cls: "" },
            { text: f.symbol ?? "", cls: "dim" },
            { text: f.module ?? "?", cls: "dim" },
          ],
          { follow: onFollow && (() => onFollow(f.ip)), cls: "mono" },
        ));
      }
    },
    dispose() { element.remove(); },
  };
}

// ---- breakpoints -----------------------------------------------------------

export function createBreakpointsPanel({ onFollow, onChanged } = {}) {
  const { element, list } = panelFrame("Breakpoints");
  let sessionRef = null;
  return {
    element,
    async refresh(session) {
      sessionRef = session;
      list.innerHTML = "";
      const bps = await session.listBreakpoints?.().catch(() => null);
      if (!bps?.length) return emptyNote(list, "No breakpoints.");
      for (const b of bps) {
        const del = document.createElement("button");
        del.className = "dbg-link danger";
        del.textContent = "remove";
        del.addEventListener("click", async (e) => {
          e.stopPropagation();
          await session.clearBreakpoint(b.address).catch(() => null);
          onChanged?.();
          await this.refresh(sessionRef);
        });
        const r = row(
          [{ text: fmtAddr(b.address) }, { text: b.enabled ? "enabled" : "disabled", cls: "dim" }],
          { follow: onFollow && (() => onFollow(b.address)), cls: "mono" },
        );
        r.append(del);
        list.append(r);
      }
    },
    dispose() { element.remove(); },
  };
}

// ---- threads ---------------------------------------------------------------

export function createThreadsPanel({ onFollow } = {}) {
  const { element, list } = panelFrame("Threads");
  return {
    element,
    async refresh(session) {
      list.innerHTML = "";
      const threads = await session.getThreads?.().catch(() => null);
      if (!threads?.length) return emptyNote(list, "no threads.");
      for (const t of threads) {
        list.append(row(
          [{ text: `tid ${t.id}` }, { text: fmtAddr(t.ip) }],
          {
            follow: onFollow && (() => onFollow(t.ip)),
            cls: "mono" + (t.active ? " active" : ""),
          },
        ));
      }
    },
    dispose() { element.remove(); },
  };
}

// ---- modules ---------------------------------------------------------------

export function createModulesPanel({ onFollow } = {}) {
  const { element, list } = panelFrame("Modules");
  return {
    element,
    async refresh(session) {
      list.innerHTML = "";
      const mods = await session.getModules?.().catch(() => null);
      if (!mods?.length) return emptyNote(list, "no modules.");
      for (const m of mods) {
        list.append(row(
          [
            { text: m.name, cls: "" },
            { text: `${fmtAddr(m.base)} +0x${Number(m.size ?? 0).toString(16)}`, cls: "dim" },
          ],
          {
            follow: onFollow && (() => onFollow(m.entry || m.base)),
            cls: "mono",
          },
        ));
      }
    },
    dispose() { element.remove(); },
  };
}
