/**
 * @kernelforge/debugger-ui — track-agnostic debugger shell.
 *
 * Exports:
 *   createDebuggerShell  docked panel: disasm/registers/memory/stack/bps/
 *                        threads/modules/pseudocode/console + hotkeys
 *   disposeShells        lesson re-render housekeeping
 *   createCodeEditor     Monaco service (textarea fallback), all code surfaces
 *   disposeAllEditors
 *   createMockSession    contract-test/demo session
 *   session helpers      toBig/fmtAddr/hexBytes/asciiBytes/isPaused
 */

export {
  toBig, fmtAddr, hexBytes, asciiBytes, isPaused,
} from "./session.mjs";
export { MockSession, createMockSession } from "./mock-session.mjs";
export { createDebuggerShell, disposeShells } from "./shell.js";
export { createCodeEditor, disposeAllEditors } from "./editor.js";
export { createDisasmView } from "./views/disasm.js";
export { createHexView } from "./views/hexdump.js";
export {
  createRegistersPanel,
  createCallStackPanel,
  createBreakpointsPanel,
  createThreadsPanel,
  createModulesPanel,
} from "./views/panels.js";
export { createPseudocodeView } from "./views/pseudocode.js";
