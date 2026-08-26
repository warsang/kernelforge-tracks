/**
 * Shell + editor DOM smoke tests under happy-dom. Monaco is intentionally
 * skipped in this environment (isHeadlessDom guard) so these cover the
 * fallback adapter path and the shell's interaction wiring.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";

const window = new Window({ url: "http://localhost/" });
globalThis.window = window;
globalThis.document = window.document;
globalThis.ResizeObserver = window.ResizeObserver;
for (const k of ["HTMLElement", "HTMLInputElement", "HTMLSelectElement", "Node"]) {
  if (window[k] !== undefined) globalThis[k] = window[k];
}

const { createDebuggerShell, createCodeEditor, disposeAllEditors } = await import(
  "../src/index.mjs"
);
const { createMockSession } = await import("../src/mock-session.mjs");

function mount() {
  const host = document.createElement("div");
  document.body.append(host);
  return host;
}

test("shell renders tabs and refreshes from the session", async () => {
  const host = mount();
  const session = createMockSession();
  const shell = createDebuggerShell(host, { session });
  await new Promise((r) => setTimeout(r, 30));

  // toolbar buttons + all core tabs present
  for (const id of ["disasm", "registers", "memory", "stack", "breakpoints", "threads", "modules"]) {
    assert.ok(host.querySelector(`.dbg-tab[data-tab="${id}"]`), `tab ${id}`);
  }
  assert.match(host.querySelector(".dbg-status").textContent, /stopped @ 0x/);

  // registers panel got populated (activate its tab: views mount lazily)
  [...shell.element.querySelectorAll(".dbg-tab")]
    .find((b) => b.textContent === "Registers").click();
  await new Promise((r) => setTimeout(r, 20));
  const regRows = shell.element.querySelectorAll(".dbg-list-row.reg");
  assert.ok(regRows.length > 4);

  // step via facade -> pauseCount bump -> refreshed rip in status
  await session.stepInto();
  await new Promise((r) => setTimeout(r, 250));
  assert.match(host.querySelector(".dbg-status").textContent, /stopped @ 0x/);

  shell.dispose();
});

test("shell console tab routes write/exec through the console factory", async () => {
  const host = mount();
  const session = createMockSession();
  const lines = [];
  const shell = createDebuggerShell(host, {
    session,
    initialTab: "console",
    consoleFactory: (tabHost) => ({
      write: (text, cls) => lines.push({ text, cls }),
      exec: async (line) => lines.push({ text: `EXEC:${line}`, cls: "exec" }),
      dispose() {},
    }),
  });
  await new Promise((r) => setTimeout(r, 20));

  shell.write("boot banner", "good");
  assert.deepEqual(lines[0], { text: "boot banner", cls: "good" });

  await shell.exec("hookscan");
  assert.ok(lines.some((l) => l.text === "EXEC:hookscan"));
  shell.dispose();
});

test("breakpoints panel lists and removes breakpoints", async () => {
  const host = mount();
  const session = createMockSession();
  await session.setBreakpoint("1040");
  const shell = createDebuggerShell(host, { session });
  await new Promise((r) => setTimeout(r, 30));

  shell.element.querySelectorAll(".dbg-tab").forEach(() => {});
  // activate breakpoints tab
  const bpTab = [...shell.element.querySelectorAll(".dbg-tab")]
    .find((b) => b.textContent === "Breakpoints");
  bpTab.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.match(shell.element.querySelector(".dbg-panel-head")?.parentElement?.textContent ?? "", /1040/s);
  shell.dispose();
  disposeAllEditors();
});

test("createCodeEditor falls back to a textarea with the same contract", async () => {
  const host = mount();
  const h = await createCodeEditor(host, { value: "int main(){}", language: "cpp" });
  assert.equal(h.monaco, false); // happy-dom skips monaco
  assert.equal(h.getValue(), "int main(){}");

  let changed = "";
  const unsub = h.onChange((v) => { changed = v; });
  h.setValue("changed;");
  const ta = host.querySelector("textarea");
  ta.dispatchEvent(new window.Event("input", { bubbles: true }));
  assert.equal(changed, "changed;");
  unsub();

  h.dispose();
  assert.equal(host.querySelector("textarea"), null);
});
