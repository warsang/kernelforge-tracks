/**
 * Linux (v86) pane: serial console debugger adapter + editor attach hook.
 */

import { validateLinuxSource, guestBuildSequence } from "./lkm-builder.mjs";

const PROMPT = "guest> ";

/** Debugger adapter over a booted V86LabSession. */
export function createLinuxDebugger(session, out) {
  const linux = session.linux;

  // live-tail the serial stream into the console
  linux.serial.onLine = (line) => write(line);

  function write(text, cls = "") {
    if (typeof out?.write === "function" && !out.appendChild) {
      out.write(text, cls);
      return;
    }
    const el = document.createElement("div");
    if (cls) el.className = cls;
    el.textContent = text;
    out.appendChild(el);
    out.scrollTop = out.scrollHeight;
  }

  return {
    exec(line) {
      const trimmed = line.trim();
      if (!trimmed) return;
      write(`${PROMPT}${trimmed}`, "prompt");
      try { linux.sendLine(trimmed); } catch (e) { write(`error: ${e.message}`, "err"); }
    },
    write,
  };
}

/**
 * Attach the module editor UI for linux labs.
 * @param {{h: Function, lab: object, getSession: () => object|null,
 *          status: (text: string, cls?: string) => void}} ui
 */
export function attachLinuxEditor(ui) {
  const { h, lab } = ui;
  const starter =
    (lab.starterFiles?.[0]?.content) ||
    `// Write your kernel module here\n#include <linux/module.h>\n\nstatic int __init mod_init(void)\n{\n    pr_info("KFFLAG: hello from your module\\n");\n    return 0;\n}\nmodule_init(mod_init);\nMODULE_LICENSE("GPL");\n`;

  const editor = h("textarea", { class: "code-editor", rows: 16, spellcheck: "false" }, starter);
  const shipBtn = h("button", { class: "primary" }, "Ship & Load Module");

  shipBtn.addEventListener("click", () => {
    const src = editor.value;
    const v = validateLinuxSource(src);
    if (!v.ok) {
      for (const e of v.errors) ui.status("✗ " + e, "err");
      return;
    }
    ui.status("✓ source validated — shipping to guest…", "good");
    const session = ui.getSession();
    if (!session?.linux) {
      ui.status("boot the guest first (Boot / Reset)", "err");
      return;
    }
    (async () => {
      await session.linux.injectFile("/root/lab/student.c", new TextEncoder().encode(src));
      for (const line of guestBuildSequence("student")) {
        session.linux.sendLine(line);
      }
      ui.status("✓ shipped; build+insmod running — watch the console", "good");
    })().catch((e) => ui.status(`ship failed: ${e.message}`, "err"));
  });

  return h("div", { class: "lkm-editor" }, editor, h("div", { class: "controls" }, shipBtn));
}
