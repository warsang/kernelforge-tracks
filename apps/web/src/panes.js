/**
 * Pane registry: lab.kind -> presentation/behavior overrides for the lab
 * card. Tracks add new lab kinds by registering here instead of editing
 * main.js core flow.
 *
 * def shape (all optional):
 *   backends?: [{value,label}]         options for the CPU/backend select
 *   noDump?: boolean                   skip tryLoadDumpWorld() on boot
 *   createDebugger?(session, host)     debugger factory over the booted
 *                                      session (default: kernel kd engine)
 */

import { createSogenDebugger } from "./sogen-debugger.js";
import { createLinuxDebugger, attachLinuxEditor } from "./linux-pane.js";

const panes = new Map();

export function registerPane(kind, def) {
  panes.set(kind, def);
}

export function paneFor(kind) {
  return panes.get(kind) ?? null;
}

// --- ntsim family: default flow (kernel sessions + kd engine) -------------
registerPane("windbg", {});
registerPane("ntsim", {});
registerPane("compiler", {});

// --- windows-userland: sogen reference-backend sessions --------------------
registerPane("sogen", {
  backends: [
    { value: "js", label: "Emulator: sogen reference backend (deterministic)" },
  ],
  noDump: true,
  createDebugger: (session, host) => createSogenDebugger(session, host),
});

// --- linux-kernel: v86 buildroot guest --------------------------------------
registerPane("linux", {
  backends: [
    { value: "v86", label: "Guest: v86 i386 Linux (buildroot)" },
  ],
  noDump: true,
  rawBoot: true, // no ntsim CPU factory involved
  createDebugger: (session, host) => createLinuxDebugger(session, host),
  attachEditor: attachLinuxEditor,
});
