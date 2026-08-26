/**
 * Integration: the staged pyre/Ghidra wasm actually decompiles.
 *
 * Skips cleanly when the artifact hasn't been vendored yet
 * (`npm run vendor:ghidra` — see ../vendor/README.md), so CI and fresh
 * clones stay green while still proving the engine end-to-end everywhere
 * it IS staged.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const staged = path.resolve(here, "../../../apps/web/public/vendor/ghidra/decompiler-wasm.mjs");

export const artifactPresent = () => fs.existsSync(staged);

test("ghidra wasm decompiles x86-64 code to pseudo-C", { skip: !artifactPresent() && "artifact not staged — run npm run vendor:ghidra" }, async () => {
  // Web-environment stubs: the emscripten module is compiled for
  // worker,web; under node we present just enough web shape, and bridge
  // spec fetches (file:// URLs derived from import.meta.url) to the FS.
  globalThis.window ??= {};
  globalThis.location ??= { href: "http://localhost:5173/" };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const u = String(input instanceof URL ? input.href : input);
    if (!u.startsWith("file://")) return realFetch(input);
    const data = fs.readFileSync(new URL(u).pathname);
    const buf = () => Promise.resolve(
      data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
    return {
      ok: true, status: 200,
      arrayBuffer: buf,
      json: async () => JSON.parse(data.toString("utf8")),
      text: async () => data.toString("utf8"),
    };
  };
  try {
    const mod = await import(pathToFileURL(staged));

    // int answer(void) { return 42; }
    const code = Uint8Array.from([0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]);
    const c = mod.decompile(code, "0x401000", "0x401000");
    assert.match(c, /FUN_401000|answer/, "no function frame in output");
    assert.match(c, /0x2a|42/, "constant not recovered");
  } finally {
    globalThis.fetch = realFetch;
  }
});
