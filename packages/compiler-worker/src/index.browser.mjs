/**
 * Unified compile entry for apps/web.
 *
 * Strategy: in-browser WASM clang (browsercc fork) when available, automatic
 * fallback to the /api/compile server bridge (dev convenience, weak devices).
 * The rest of the app only ever calls `compileDriverSource`.
 */

import { BrowserCompiler } from "@kernelforge/compiler-worker/browser.client.mjs";

let browserCompiler = null;
let wasmBroken = false;

function getBrowserCompiler() {
  if (!browserCompiler) browserCompiler = new BrowserCompiler();
  return browserCompiler;
}

/** Kick off WASM toolchain preload; never throws. */
export function warmupCompiler() {
  try {
    getBrowserCompiler().warmup().catch(() => { wasmBroken = true; });
  } catch {
    wasmBroken = true;
  }
}

/**
 * @param {string} source C source
 * @returns {Promise<{objBytes: Uint8Array, via: "wasm"|"server"}>}
 */
export async function compileDriverSource(source) {
  if (!wasmBroken) {
    try {
      const objBytes = await getBrowserCompiler().compileSource(source);
      return { objBytes, via: "wasm" };
    } catch (e) {
      // fall through to server bridge; remember wasm is broken this session
      console.warn("[compiler] wasm path failed, falling back to server:", e?.message);
      wasmBroken = true;
    }
  }

  const resp = await fetch("/api/compile", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ source }),
  });
  if (!resp.ok) {
    let msg = `compile API ${resp.status}`;
    try { msg = (await resp.json()).error ?? msg; } catch {}
    throw new Error(msg);
  }
  const { objBase64 } = await resp.json();
  const bin = atob(objBase64);
  const objBytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return { objBytes, via: "server" };
}
