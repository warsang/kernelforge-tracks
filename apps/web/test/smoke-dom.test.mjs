/**
 * First-paint smoke test: executes the real app module graph (Vite transform
 * pipeline included) against a DOM. Guards the entire class of "blank page"
 * regressions that pure file-serving checks cannot see.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";
import { createServer } from "vite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(root, "..");

test("app boots: shell renders, lesson opens, lab card present", async () => {
  const window = new Window({ url: "http://localhost:5173/" });
  window.document.body.innerHTML = '<div id="app"></div>';

  // Globals main.js expects at import time
  globalThis.window = window;
  globalThis.document = window.document;
  for (const k of ["HTMLElement", "HTMLInputElement", "HTMLSelectElement", "Node", "customElements"]) {
    if (window[k] !== undefined) globalThis[k] = window[k];
  }
  // Dev flag defaults, mirroring index.html. main.js reads flags via the
  // vite define-replacement of window.process.env; give that object a home.
  window.process = { env: {
    KF_FLAG_M1L1F1: "FLAG{kfprobe}",
    KF_FLAG_M1L1F2: "FLAG{312}",
    KF_FLAG_M1L2F1: "FLAG{0x40003d90}",
  } };

  const server = await createServer({
    root: webRoot,
    server: { middlewareMode: true },
    logLevel: "error",
  });
  try {
    await server.ssrLoadModule("/src/main.js");
    await new Promise((r) => setTimeout(r, 50)); // let async init settle

    const doc = window.document;
    const lessons = [...doc.querySelectorAll("button.lesson")];
    assert.ok(lessons.length >= 3, `expected >=3 lesson buttons, got ${lessons.length}`);
    assert.match(doc.querySelector(".points").textContent, /0 flags · 0 pts/);

    // open the first (unlocked) lesson -> lab card with boot controls renders
    lessons.find((b) => !b.className.includes("locked")).click();
    assert.ok(doc.body.textContent.includes("Boot / Reset"), "lab runner not rendered");
    assert.ok(doc.querySelector("select"), "backend picker missing");
    assert.ok(doc.querySelectorAll(".flag").length >= 2, "flag prompts missing");
  } finally {
    await server.close();
  }
});
