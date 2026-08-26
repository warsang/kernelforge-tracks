/**
 * views/pseudocode.js — pyre-style decompiled-C tab.
 *
 * Monaco (read-only) when the host app provides a decompiler client;
 * loud degrade text otherwise (the platform's vendor-absent convention).
 * The client is injected by the shell:
 *
 *   decompiler.decompile(addrHex) -> Promise<{ c: string }>
 *   decompiler.functions() -> Promise<{ count, funcs, rel32 }>
 */

import { createCodeEditor } from "../editor.js";
import { fmtAddr } from "../session.mjs";

const DEGRADE_NOTE =
  "// Ghidra decompiler wasm not vendored yet — pseudocode unavailable.\n" +
  "// Build recipe (pyre pipeline): packages/ghidra-decompiler/vendor/README.md\n" +
  "// Static analysis still works: function boundaries below come from the\n" +
  "// in-repo prologue scanner (!funcs uses the same engine).";

export function createPseudocodeView({ decompiler, language = "c" }) {
  const element = document.createElement("div");
  element.className = "dbg-pseudocode";

  let handle = null;
  let currentAddr = null;
  let functionsHeader = null;

  if (!decompiler) {
    const note = document.createElement("div");
    note.className = "dim dbg-note pad";
    note.textContent =
      "Decompiler engine not vendored yet — pseudocode unavailable. " +
      "See packages/ghidra-decompiler/vendor/README.md for the build recipe. " +
      "Disassembly and static analysis (!funcs) work without it.";
    element.append(note);
    return {
      element,
      async show(addr) { currentAddr = addr; },
      dispose() { element.remove(); },
    };
  }

  const editorHost = document.createElement("div");
  element.append(editorHost);
  const ready = createCodeEditor(editorHost, {
    value: "; decompiling…",
    language,
    readOnly: true,
    minimap: true,
    height: "100%",
  }).then((h) => {
    if (!h.monaco) {
      editorHost.querySelector("textarea")?.classList.add("dbg-pseudo-fallback");
    }
    handle = h;
    return h;
  });

  async function ensureFunctionsHeader() {
    if (functionsHeader !== null) return functionsHeader;
    try {
      const analysis = await decompiler.functions();
      const lines = ["// ---- recovered function boundaries (static scan) ----"];
      for (const f of (analysis?.funcs ?? []).slice(0, 64)) {
        lines.push(`// ${fmtAddr(f.addr ?? f.address ?? f)}${f.size ? ` (${f.size} bytes)` : ""}`);
      }
      functionsHeader = analysis?.count ? lines.join("\n") + "\n\n" : "";
    } catch {
      functionsHeader = "";
    }
    return functionsHeader;
  }

  async function show(addr) {
    currentAddr = addr;
    if (addr === null || addr === undefined) return;
    await ready;
    try {
      const res = await decompiler.decompile(String(addr));
      const header = await ensureFunctionsHeader();
      handle?.setValue(header + (res?.c ?? `// no function at ${fmtAddr(addr)}`));
    } catch (e) {
      const unavailable = e?.name === "DecompilerUnavailableError" ||
        /not vendored/i.test(String(e?.message));
      handle?.setValue(unavailable
        ? DEGRADE_NOTE
        : `// decompile failed @ ${fmtAddr(addr)}: ${e.message}`);
    }
  }

  return {
    element,
    show,
    get current() { return currentAddr; },
    dispose() {
      handle?.dispose();
      element.remove();
    },
  };
}
