/**
 * TryBypassMe-style userland anti-cheat harness (m14 world "tbm-ac").
 *
 * A deterministic plain-JS model of the classic ring-3 AC vector set made
 * famous by the UnknownCheats TryBypassMe crackme series and documented in
 * ssno's TAC teardown: process/window blacklists, multi-method debugger
 * detection (PEB.BeingDebugged, NtGlobalFlag, ProcessDebugPort), runtime
 * XOR-encrypted stats with shadow-copy canaries, and a CRC-guarded AC
 * thread. Everything is inspectable through the console — the student's
 * job is to make !godmode pass WITHOUT tripping a tick.
 *
 * Layout:
 *   game.exe base 0x00400000 (image metadata only)
 *   PEB          0x00500000  (+0x2 BeingDebugged, +0xBC NtGlobalFlag)
 *   stats        0x00600100  {ammo@+0, health@+4} stored XOR-encrypted
 *   statsShadow  0x00600200  shadow copy the AC canary diffs against
 *   acThread     0x00600300  AC loop prologue covered by CRC
 */

import { mulberry32 } from "./rand.mjs";

export const TBM_CONSTANTS = {
  peb: 0x00500000n,
  beingDebugged: 0x00500002n,
  ntGlobalFlag: 0x005000bcn,
  stats: 0x00600100n,
  statsShadow: 0x00600200n,
  acThread: 0x00600300n,
  vectors: [
    "process-blacklist",
    "window-title-scan",
    "debugger-detection",
    "stat-canary-shadow",
    "code-crc-thread",
  ],
  godmodeSecret: "kf-tbm-godmode",
};

export function buildTbmWorld({ seed = 0xc0ffee } = {}) {
  const rng = mulberry32(seed);
  const xorKey = rng() * 0xffffffff >>> 0;
  const mem = {
    beingDebugged: 0,
    ntGlobalFlag: 0,
    debugPort: 0,
    processes: ["tbm_game.exe", "explorer.exe", "cheatengine-x86_64.exe"],
    windows: ["TryBypassMe", "Cheat Engine 7.5"],
    statsPlain: { ammo: 30, health: 100 },
    statsEnc: null, // set below
    statsShadowEnc: null,
    crcBad: false,
    events: [],
  };

  const enc = (v) => (v ^ xorKey) >>> 0;
  mem.statsEnc = { ammo: enc(mem.statsPlain.ammo), health: enc(mem.statsPlain.health) };
  mem.statsShadowEnc = { ...mem.statsEnc };

  const ac = {
    /** Re-evaluate every vector; returns {passed, tripped:[], log[]} */
    tick() {
      const tripped = [];
      const log = [];
      if (mem.processes.some((p) => /cheat/i.test(p))) {
        tripped.push("process-blacklist");
        log.push("AC: blacklisted process name visible");
      }
      if (mem.windows.some((t) => /cheat/i.test(t))) {
        tripped.push("window-title-scan");
        log.push("AC: blacklisted window title visible");
      }
      if (mem.beingDebugged || (mem.ntGlobalFlag & 0x70) || mem.debugPort) {
        tripped.push("debugger-detection");
        log.push(`AC: debug artifacts (BeingDebugged=${mem.beingDebugged}, ` +
          `NtGlobalFlag=0x${mem.ntGlobalFlag.toString(16)}, DebugPort=${mem.debugPort})`);
      }
      if (mem.statsEnc.ammo !== mem.statsShadowEnc.ammo ||
          mem.statsEnc.health !== mem.statsShadowEnc.health) {
        tripped.push("stat-canary-shadow");
        log.push("AC: live stats diverge from shadow copy");
      }
      if (mem.crcBad) {
        tripped.push("code-crc-thread");
        log.push("AC: AC-thread CRC mismatch");
      }
      return { passed: tripped.length === 0, tripped, log };
    },

    /** Win condition: clean tick + god-tier stats set through the game API. */
    godmode() {
      const t = this.tick();
      if (!t.passed) return { ok: false, ...t };
      if (mem.statsPlain.ammo < 9000 || mem.statsPlain.health < 9000) {
        return { ok: false, tripped: [], log: ["AC: stats not god-tier (use !setstat)"] };
      }
      mem.events.push("godmode granted");
      return { ok: true, tripped: [], log: [`AC: all ${TBM_CONSTANTS.vectors.length} vectors quiet`, `secret=${TBM_CONSTANTS.godmodeSecret}`] };
    },
  };

  return { ac: true, engine: ac, mem, xorKey };
}
