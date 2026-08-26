/**
 * client.mjs — browser-facing decompiler client for the debugger shell's
 * Pseudocode tab.
 *
 * Shape mirrors pyre (MIT): a lazy engine hosting the wasm Ghidra
 * decompiler, JSON in/out, per-function requests. The wasm itself is still
 * a documented vendor step (vendor/README.md — pyre-based build pipeline);
 * until it lands, decompile() rejects with DecompilerUnavailableError and
 * the tab renders the platform's loud-degrade notice while the function
 * LIST keeps working via the static boundary scanner.
 *
 * Engine-agnostic from the shell's perspective:
 *   createDecompilerClient({ readImage: (addr, size) => Uint8Array|null,
 *                            extent: {base: bigint, size: number} })
 *   .decompile(addrHex) -> Promise<{c: string}>
 */

import { analyzeExtent } from "./boundaries.mjs"; // stays
import { decompile as decompileRaw, loadDecompiler, DecompilerUnavailableError } from "./wrapper.mjs";

export function createDecompilerClient({ readImage, extent }) {
  let cachedAnalysis = null;

  /** Function list via the static boundary scanner (works without wasm). */
  async function functions() {
    if (cachedAnalysis) return cachedAnalysis;
    const bytes = readImage(extent.base, Number(extent.size));
    cachedAnalysis = bytes
      ? analyzeExtent(
        { read: (_a, len) => bytes.slice(0, Number(len)), canRead: () => true },
        extent.base,
        extent.size,
      )
      : { count: 0, funcs: [], rel32: [] };
    return cachedAnalysis;
  }

  async function decompile(addrHex) {
    const addr = BigInt("0x" + String(addrHex).replace(/^0x/i, ""));
    const mod = await loadDecompiler();
    if (!mod) throw new DecompilerUnavailableError();
    const size = Number(extent.size);
    const bytes = readImage(extent.base, size);
    if (!bytes) throw new Error("image unreadable");
    return decompileRaw(bytes, extent.base, addr);
  }

  return {
    decompile,
    functions,
    available: () => loadDecompiler().then((m) => !!m),
    get extent() { return extent; },
  };
}
