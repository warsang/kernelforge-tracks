/**
 * Ghidra native decompiler — wasm wrapper.
 *
 * The decompiler proper is Ghidra's C++ engine (Apache-2.0) compiled to
 * WebAssembly; see vendor/README.md for the pinned build recipe. Without the
 * vendored artifact every entry point throws DecompilerUnavailableError so
 * callers degrade loudly (platform convention) instead of faking output.
 */

let cached = null;
let probed = false;

export class DecompilerUnavailableError extends Error {
  constructor() {
    super(
      "ghidra-decompiler wasm not vendored. Build Ghidra's native decompiler " +
      "for wasm (see packages/ghidra-decompiler/vendor/README.md). " +
      "Static analysis (!funcs, E9 resolution) works without it.",
    );
    this.name = "DecompilerUnavailableError";
  }
}

/**
 * Probe order:
 *   1. ./decompiler-wasm.mjs      — node/dev override next to this file
 *   2. /vendor/ghidra/...         — staged artifact (tools/build-ghidra-wasm.mjs
 *                                   copies vendor/shim.mjs there; vite serves
 *                                   public/ identically in dev and prod)
 * Specifiers are assembled from parts so bundlers never statically resolve a
 * missing vendor file.
 */
const PROBES = [
  "./decompiler-" + "wasm.mjs",
  "/vendor/ghidra/decompiler-" + "wasm.mjs",
];

/** @returns {Promise<object|null>} the vendored module, or null when absent */
export async function loadDecompiler() {
  if (probed) return cached;
  for (const specifier of PROBES) {
    const mod = await import(/* @vite-ignore */ specifier).catch(() => null);
    if (mod && typeof mod.decompile === "function") {
      cached = mod;
      break;
    }
  }
  probed = true;
  return cached;
}

/**
 * Decompile one function.
 * @param {Uint8Array} imageBytes flat bytes of the executable extent
 * @param {bigint} baseAddr VA of imageBytes[0]
 * @param {bigint} funcAddr VA of the function entry
 * @returns {Promise<{c: string, addr: bigint}>} pseudo-C and normalized entry
 */
export async function decompile(imageBytes, baseAddr, funcAddr) {
  const mod = await loadDecompiler();
  if (!mod) throw new DecompilerUnavailableError();
  const c = mod.decompile(imageBytes, baseAddr.toString(), funcAddr.toString());
  return { c, addr: funcAddr };
}
