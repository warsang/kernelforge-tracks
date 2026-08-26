/**
 * Shim adapter: pyre wasm build -> @kernelforge/ghidra-decompiler contract.
 *
 * This file is OURS (versioned at packages/ghidra-decompiler/vendor/shim.mjs).
 * tools/build-ghidra-wasm.mjs stages it next to the untracked pyre artifacts:
 *
 *   apps/web/public/vendor/ghidra/
 *     decompiler-wasm.mjs      <- this shim (copy)
 *     pyre_decompiler.js       <- emscripten ES6 loader (build output)
 *     pyre_decompiler.wasm     <- compiled Ghidra decompiler engine
 *     specs/manifest.json      <- SLEIGH spec inventory (pyre specs/dist)
 *     specs/x86/data/languages/*
 *
 * Exported shape is exactly what src/wrapper.mjs probes for:
 *   export function decompile(imageBytes, baseHex, funcHex): string
 * (sync string return; async bring-up happens once at module load.)
 *
 * Bridge: Ghidra C++ decompiler (Apache-2.0) via pyre's extern "C" API —
 * pyre_init/add_spec_dir/create/add_region/decompile/free_string/destroy.
 */

import PyreDecompiler from "./pyre_decompiler.js";

const LANG_ID = "x86:LE:64:default:windows"; // Visual Studio cspec (PE targets)
const SPEC_BASE = new URL("./specs/", import.meta.url);

function mkdirp(FS, dir) {
  let cur = "";
  for (const part of dir.split("/").filter(Boolean)) {
    cur += "/" + part;
    try { FS.mkdir(cur); } catch { /* EEXIST */ }
  }
}

async function stageSpecs(mod) {
  const FS = mod.FS;
  try { FS.mkdir("/spec"); } catch { /* EEXIST */ }
  const res = await fetch(new URL("manifest.json", SPEC_BASE));
  if (!res.ok) throw new Error(`spec manifest fetch failed: ${res.status}`);
  const manifest = await res.json();
  for (const entry of manifest.files ?? []) {
    if (!String(entry.path).startsWith("x86/")) continue; // one processor slice
    const fileRes = await fetch(new URL(entry.path, SPEC_BASE));
    if (!fileRes.ok) throw new Error(`spec fetch failed: ${entry.path}`);
    const bytes = new Uint8Array(await fileRes.arrayBuffer());
    const virt = "/spec/" + entry.path;
    mkdirp(FS, virt.slice(0, virt.lastIndexOf("/")));
    FS.writeFile(virt, bytes);
  }
  const rc = mod.ccall("pyre_add_spec_dir", "number", ["string"],
    ["/spec/x86/data/languages"]);
  if (rc !== 0) throw new Error(`pyre_add_spec_dir failed (${rc})`);
}

const mod = await PyreDecompiler({
  locateFile: (p) => new URL(p, import.meta.url).href,
});
await stageSpecs(mod);

function parseAddr(s) {
  const t = String(s ?? "").trim().replace(/^0x/i, "").replace(/[`_\s]/g, "");
  if (!t || !/^[0-9a-fA-F]+$/.test(t)) return null;
  try { return BigInt.asUintN(64, BigInt("0x" + t)); } catch { return null; }
}

/**
 * Decompile the function at funcHex out of a flat image mapped at baseHex.
 * Mirrors wrapper.mjs's call shape: sync in, C text out. Recoverable errors
 * come back embedded as a comment so the UI always shows something.
 */
export function decompile(imageBytes, baseHex, funcHex) {
  const base = parseAddr(baseHex);
  const func = parseAddr(funcHex);
  if (base === null || func === null) return "/* decompile error: bad address */";
  const u8 = imageBytes instanceof Uint8Array ? imageBytes : new Uint8Array(imageBytes ?? []);

  const handle = mod.ccall("pyre_create", "number", ["string"], [LANG_ID]);
  if (!handle) return "/* decompile error: engine create failed (specs missing?) */";
  try {
    if (u8.length > 0) {
      const ptr = mod._malloc(u8.length);
      try {
        mod.HEAPU8.set(u8, ptr);
        mod.ccall("pyre_add_region", "number",
          ["number", "bigint", "number", "number"],
          [handle, base, ptr, u8.length]);
      } finally {
        mod._free(ptr);
      }
    }
    const cstr = mod.ccall("pyre_decompile", "number",
      ["number", "bigint", "string"], [handle, func, ""]);
    if (!cstr) return "/* decompile error: engine returned null */";
    const text = mod.UTF8ToString(cstr);
    mod.ccall("pyre_free_string", null, ["number"], [cstr]);
    return text;
  } finally {
    mod.ccall("pyre_destroy", null, ["number"], [handle]);
  }
}

export default { decompile };
