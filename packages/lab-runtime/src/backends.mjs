/**
 * CPU backend resolution for ntsim labs.
 *
 * "js" (default)  — deterministic JsInterpreter, zero extra dependencies.
 * "hybrid"        — JS front + automatic one-way handoff to Unicorn on
 *                   unimplemented opcodes (speed of JS, coverage of QEMU).
 * "unicorn"       — pure high-fidelity QEMU-based emulation (WASM-only).
 *                   WASM bundle (~1MB, GPLv2) is dynamically imported so it
 *                   never loads unless a lab explicitly opts in.
 */

export const BACKENDS = ["js", "hybrid", "unicorn"];

/**
 * Resolve a backend factory by name.
 * @param {"js"|"hybrid"|"unicorn"} [kind]
 * @returns {Promise<(mem: object) => Promise<object>|object>} factory taking
 *   a SparseMemory and returning a CpuBackend (async for unicorn/hybrid).
 */
export async function resolveBackend(kind = "js") {
  if (!BACKENDS.includes(kind)) {
    throw new Error(`unknown backend "${kind}" (expected one of ${BACKENDS.join(", ")})`);
  }
  if (kind === "unicorn") {
    const { createUnicornBackend } = await import("@kernelforge/ntsim-unicorn");
    return (mem) => createUnicornBackend(mem);
  }
  if (kind === "hybrid") {
    const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
    return (mem) => HybridCpuBackend.create(mem);
  }
  const { JsInterpreter } = await import("@kernelforge/ntsim/src/cpu.mjs");
  return (mem) => new JsInterpreter(mem);
}
