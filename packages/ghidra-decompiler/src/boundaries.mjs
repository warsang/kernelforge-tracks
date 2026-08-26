/**
 * Function boundary recovery over mapped memory — the static half of the
 * analysis pane.
 *
 * Heuristics (documented, deterministic, unit-tested):
 *  - PROLOGUE signatures: the regular first-instruction patterns clang/MSVC
 *    emit for x64 Windows targets. A signature hit that follows a RET
 *    (or starts the extent) is a function candidate.
 *  - E9/E8 rel32 resolution: target = site + 5 + sign-extended rel32.
 *
 * The decompilation itself lives in wrapper.mjs behind the vendored Ghidra
 * native decompiler wasm; boundaries work with or without it.
 */

export const SIGS = [
  // mov [rsp+imm8], reg (MSVC/clang shadow-space spill)
  [0x48, 0x89, 0x5c, 0x24], [0x48, 0x89, 0x4c, 0x24], [0x48, 0x89, 0x54, 0x24],
  [0x48, 0x89, 0x74, 0x24], [0x48, 0x89, 0x7c, 0x24],
  // push rbx/rbp/rsi/rdi with REX prefix
  [0x40, 0x53], [0x40, 0x55], [0x40, 0x56], [0x40, 0x57],
  // frame-pointer setups
  [0x55, 0x48, 0x89, 0xe5], [0x48, 0x89, 0x6c, 0x24],
];

function matchesAt(bytes, off) {
  outer: for (const sig of SIGS) {
    if (off + sig.length > bytes.length) continue;
    for (let i = 0; i < sig.length; i++) {
      if (bytes[off + i] !== sig[i]) continue outer;
    }
    return sig.length;
  }
  return 0;
}

/**
 * Scan [start, start+len) for function candidates.
 * Edges: extent start, first MAPPED byte after sparse zeros (code pages get
 * materialized contiguously in our worlds), or any byte following RET/INT3.
 * @returns {{start: bigint, len: number}[]} ordered, non-overlapping
 */
export function findFunctions(mem, start, len) {
  const bytes = Array.from(mem.read(start, Number(len)));
  const found = [];
  let edge = true;        // extent start counts as a boundary edge
  let mapped = false;
  let sawC3CC = false;
  for (let off = 0; off < bytes.length; off++) {
    const isMapped = mem.canRead(start + BigInt(off), 1);
    if (isMapped && !mapped) edge = true;      // first mapped byte
    else if (isMapped) edge = sawC3CC;         // byte after ret/int3
    else edge = false;
    mapped = isMapped;

    const sigLen = isMapped ? matchesAt(bytes, off) : 0;
    if (sigLen && edge) {
      found.push({ start: start + BigInt(off), len: sigLen });
      // consume signature bytes; next edge decision resumes after them
      for (let k = 0; k < sigLen && off < bytes.length; k++, off++) {
        /* skip */
      }
      sawC3CC = false;
      continue;
    }
    sawC3CC = bytes[off] === 0xc3 || bytes[off] === 0xcc;
  }
  return found;
}

/**
 * Resolve an E9 jmp rel32 (or E8 call rel32) at addr.
 * @returns {bigint|null} target address, or null when bytes are not rel32
 */
export function resolveRel32(mem, addr) {
  const b = mem.read(addr, 5);
  if (b[0] !== 0xe9 && b[0] !== 0xe8) return null;
  const raw = Number(b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24));
  const rel = BigInt(raw | 0); // sign-extend
  return addr + 5n + rel;
}

/**
 * Deterministic code-fill helper for scenario worlds: lays down a grid of
 * 16-byte pseudo-functions (prologue + filler + ret). Used so labs have a
 * byte-stable .text to analyze. NOT used by grading paths directly.
 */
export function writeFunctionGrid(mem, start, len, seed = 0xa5a5a5a5) {
  let state = seed >>> 0;
  const next = () => {
    state |= 0; state = (state + 0x6D2B79F5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const block = new Uint8Array(16);
  for (let off = 0; off + 16 <= len; off += 16) {
    block[0] = 0x48; block[1] = 0x89; block[2] = 0x5c; block[3] = 0x24;
    block[4] = (next() * 256) | 0;
    for (let i = 5; i < 15; i++) block[i] = [0x48, 0x89, 0x6c, 0x24, 0x40, 0x53][i % 6];
    block[15] = 0xc3;
    mem.write(start + BigInt(off), block);
  }
}

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
