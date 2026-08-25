/**
 * @kernelforge/sogen-runtime — windows-userland track runtime.
 *
 * Session API mirrors the upstream sogen emulator surface (createApplication,
 * module list, memory R/W, hooks, snapshots) so the vendored WASM core can
 * replace the JS reference backend without touching labs or the console.
 */

import { buildSauerWorld } from "./world.mjs";
import { buildTbmWorld, TBM_CONSTANTS } from "./ac.mjs";

export { SAUER_CONSTANTS, SENDINPUT_PROLOGUE, buildSauerWorld } from "./world.mjs";
export { TBM_CONSTANTS } from "./ac.mjs";
export { SogenConsole, parseNum } from "./console.mjs";

/**
 * Boot a userland lab session by scenario world id.
 * @param {"sauer-recon"|"sauer-hook"|"tbm-ac"} worldId
 */
export function createSogenSession(worldId) {
  switch (worldId) {
    case "sauer-recon":
      return { world: buildSauerWorld({ hooked: false }), engine: null };
    case "sauer-hook":
      return { world: buildSauerWorld({ hooked: true }), engine: null };
    case "tbm-ac":
      return { world: buildTbmWorld(), engine: null };
    default:
      throw new Error(`unknown sogen world "${worldId}"`);
  }
}
