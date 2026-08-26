/**
 * DebugSession — the backend-agnostic debugger contract.
 *
 * Every track backend (sogen wasm, v86 RSP/gdbserver, ntsim kernel engine,
 * the in-package mock) implements this exact surface; every shell view
 * consumes only it. The verb set mirrors upstream sogen's page debugger API
 * (page/src/debugger/api.ts) so a wasm-core adapter drops in without UI
 * changes.
 *
 * Address convention: hex strings WITHOUT 0x prefix at the edges (sogen
 * protocol shape), BigInt accepted everywhere via toBig(). All registers are
 * named lowercase x64/i386 names ("rip"/"eip", "rax"…). Sessions are
 * paused-only for introspection: reads issued while running may resolve null.
 *
 * @typedef {Object} Insn
 * @property {string} address   hex, no 0x
 * @property {number} size      bytes
 * @property {string} mnemonic
 * @property {string} operands  decoded operand string
 * @property {string} [symbol]  symbol comment if resolvable
 * @property {string} [branch]  hex target when the instruction transfers
 * @property {number[]} [bytes] raw encoding
 *
 * @typedef {Object} Reg        { name: string, value: hex string, size: number }
 * @typedef {Object} ModuleInfo { name, base: hex, size: number, entry: hex }
 * @typedef {Object} ThreadInfo { id: number, ip: hex, active: boolean }
 * @typedef {Object} StackFrame { ip: hex, sp: hex, module?: string, symbol?: string }
 * @typedef {Object} BreakpointInfo { address: hex, type: number, enabled: boolean, hitCount?: number }
 * @typedef {Object} MemoryRegion { base: hex, size: number, label?: string }
 */

/** Parse hex-string | Number | bigint into an unsigned BigInt. */
export function toBig(v) {
  if (typeof v === "bigint") return BigInt.asUintN(64, v);
  if (typeof v === "number") return BigInt.asUintN(64, BigInt(Math.trunc(v)));
  const t = String(v ?? "").trim().replace(/^0x/i, "").replace(/[`_\s]/g, "");
  if (!t || !/^[0-9a-fA-F]+$/.test(t)) return null;
  try {
    return BigInt.asUintN(64, BigInt("0x" + t));
  } catch {
    return null;
  }
}

/** Format a BigInt VA as fixed-width hex (no 0x), sogen-style. */
export function fmtAddr(v, pad = 12) {
  const b = typeof v === "bigint" ? BigInt.asUintN(64, v) : toBig(v);
  return (b ?? 0n).toString(16).padStart(pad, "0");
}

export function hexBytes(bytes) {
  return [...(bytes ?? [])].map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

export function asciiBytes(bytes) {
  return [...(bytes ?? [])]
    .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
    .join("");
}

/** True when a session accepts introspection commands right now. */
export function isPaused(session) {
  return !!session && session.paused === true;
}
