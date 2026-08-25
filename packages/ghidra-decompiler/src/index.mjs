import { findFunctions, resolveRel32 } from "./boundaries.mjs";

export {
  findFunctions, resolveRel32, writeFunctionGrid, SIGS as PROLOGUE_SIGS,
} from "./boundaries.mjs";
export { decompile, loadDecompiler, DecompilerUnavailableError } from "./wrapper.mjs";

/**
 * Convenience used by debugger commands: analyze a mapped module extent.
 * Reports recovered boundaries plus rel32 transfer sites sitting on boundary
 * edges (extent start or right after a RET/INT3) — i.e., patched prologues.
 */
export function analyzeExtent(mem, start, len) {
  const funcs = findFunctions(mem, start, len);
  const targets = [];
  const bytes = Array.from(mem.read(start, Number(len)));
  let edge = true; // extent start counts as an edge
  let mapped = false;
  let sawC3CC = false;
  for (let off = 0; off < bytes.length; off++) {
    const isMapped = mem.canRead(start + BigInt(off), 1);
    if (isMapped && !mapped) edge = true;
    else if (isMapped) edge = sawC3CC;
    else edge = false;
    mapped = isMapped;

    if (edge && isMapped && (bytes[off] === 0xe9 || bytes[off] === 0xe8)) {
      const t = resolveRel32(mem, start + BigInt(off));
      if (t !== null) targets.push({ site: start + BigInt(off), target: t });
    }
    sawC3CC = isMapped && (bytes[off] === 0xc3 || bytes[off] === 0xcc);
  }
  return { count: funcs.length, funcs, rel32: targets };
}
