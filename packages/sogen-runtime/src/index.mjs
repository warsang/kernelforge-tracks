/**
 * @kernelforge/sogen-runtime — windows-userland track runtime.
 *
 * Session API mirrors the upstream sogen emulator surface (createApplication,
 * module list, memory R/W, hooks, snapshots) so the vendored WASM core can
 * replace the JS reference backend without touching labs or the console.
 */

import { buildSauerWorld } from "./world.mjs";
import { buildTbmWorld, TBM_CONSTANTS } from "./ac.mjs";
import { buildEtwUserWorld, ETW_USER_CONSTANTS } from "./etw.mjs";

export { SAUER_CONSTANTS, SENDINPUT_PROLOGUE, buildSauerWorld } from "./world.mjs";
export { TBM_CONSTANTS } from "./ac.mjs";
export { ETW_USER_CONSTANTS, buildEtwUserWorld } from "./etw.mjs";
export { SogenConsole, parseNum } from "./console.mjs";
export { createStaticDebugSession } from "./backend-static.mjs";
export {
  probeAssets, createWasmClient, DebugCommandKind, DebuggerUnavailableError,
  createSogenDebugSession,
} from "./backend-wasm.mjs";

/**
 * Boot a userland lab session by scenario world id.
 * @param {"sauer-recon"|"sauer-hook"|"tbm-ac"|"etw-blind"} worldId
 */
export function createSogenSession(worldId) {
  switch (worldId) {
    case "sauer-recon":
      return { world: buildSauerWorld({ hooked: false }), engine: null };
    case "sauer-hook":
      return { world: buildSauerWorld({ hooked: true }), engine: null };
    case "tbm-ac":
      return { world: buildTbmWorld(), engine: null };
    case "etw-blind":
      return { world: buildEtwUserWorld(), engine: null };
    default:
      throw new Error(`unknown sogen world "${worldId}"`);
  }
}
