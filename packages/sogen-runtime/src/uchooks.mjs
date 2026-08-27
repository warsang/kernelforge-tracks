/**
 * Userland hooking deep cuts ("m27"): VTable swaps, MS hot-patch slots,
 * and debug-register (DRx) hooks — modeled in one plain-JS process world
 * with three modes over shared constants.
 *
 *   vtable   : an entity-shaped object whose +0x00 vtable pointer gets
 *              re-pointed at a cheat-owned fake table; !callview routes
 *              through whichever slot0 is live right now.
 *   hotpatch : cl_calcspread carries the classic MS hot-patchable prologue
 *              (5xNOP + MOV EDI,EDI); an E9 into the sled is the atomic
 *              install the technique exists for.
 *   drx      : modeled DR0/DR7 arm against cl_sendinput; every replayed
 *              frame batch trips the breakpoint without touching .text,
 *              and !drxaudit is the anticheat counter-read that catches it.
 *
 * Teaching anchor: PatchGuard never looks at ring 3. Detection lives with
 * anticheat integrity threads (pointer containment vs module ranges),
 * on-disk diffing for the sled, and GetThreadContext DR audits.
 */
import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";

export const UCHOOKS_CONSTANTS = {
  objectVa: 0x02100400n,
  vtableHonest: 0x005e1000n,
  vtableFake: 0x02100800n,
  getViewFn: 0x00451050n,
  calcSpreadFn: 0x00452060n,
  cheatStub: 0x0046f020n,
  hotpatchSledNops: 5,
  sendInputFn: 0x004532a0n,
  secrets: {
    vtable: "kf-vtable-restored",
    hotpatch: "kf-hotpatch-restored",
    drx: "kf-drx-clean",
  },
};

const PROLOGUE = [0x48, 0x89, 0x5c, 0x24, 0x08]; // generic MSVC frame setup

export function buildUcHooksWorld(mode = "vtable") {
  const C = UCHOOKS_CONSTANTS;
  const mem = new SparseMemory();
  const ensure = (va) => mem.ensurePage(va & ~0xfffn);

  // ---- code pages ---------------------------------------------------------
  // honest GetViewAngles
  ensure(C.getViewFn);
  mem.write(C.getViewFn, [...PROLOGUE, 0x33, 0xc0, 0xc3]);
  // hot-patchable CalcSpread: [NOP x5][MOV EDI,EDI][xor eax,eax; ret]
  ensure(C.calcSpreadFn);
  mem.write(C.calcSpreadFn,
    [0x90, 0x90, 0x90, 0x90, 0x90, 0x8b, 0xff, 0x33, 0xc0, 0xc3]);
  // cheat stub: rewrite pitch then hand back (behavior modeled, not executed)
  ensure(C.cheatStub);
  mem.write(C.cheatStub, [...PROLOGUE, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);

  // ---- honest vtable ------------------------------------------------------
  ensure(C.vtableHonest);
  mem.w64(C.vtableHonest, C.getViewFn);
  mem.w64(C.vtableHonest + 8n, 0x00451100n);

  // ---- entity-shaped object ----------------------------------------------
  ensure(C.objectVa);
  mem.w64(C.objectVa, C.vtableHonest);

  let hookedOnce = false;
  let healedAnnounced = false;
  let drTripsTotal = 0;
  let auditedFlagged = false;

  const dr = { dr0: 0n, dr7: 0n };

  // pristine snapshot for hookscan (taken after honest seeding)
  const pristine = new Map();
  for (const [k, v] of mem.pages.entries()) pristine.set(k, Uint8Array.from(v));

  const world = {
    kind: `uc-hooks-${mode}`,
    uchooks: true,
    mode,
    mem,
    constants: C,
    modules: [
      { name: "game.exe", base: 0x00400000n, size: 0x90000 },
      { name: "ntdll.dll", base: 0x77400000n, size: 0x190000 },
    ],

    /** diff live vs pristine across all pages -> array of {addr, orig, live} */
    hookscan() {
      const diffs = [];
      for (const [k, live] of mem.pages.entries()) {
        const orig = pristine.get(k);
        if (!orig) continue;
        const base = BigInt("0x" + k);
        for (let i = 0; i < 4096; i++) {
          if (live[i] !== orig[i]) {
            diffs.push({ addr: base + BigInt(i), orig: orig[i], live: live[i] });
            if (diffs.length > 512) return diffs;
          }
        }
      }
      return diffs;
    },

    // ------------------------------------------------------------ vtable
    callView() {
      const vt = mem.u64(C.objectVa);
      const fn = mem.u64(vt);
      if (fn === C.getViewFn) {
        const line = "callview: view angles passthrough OK (pitch 12.5)";
        let out = [line];
        if (hookedOnce && !healedAnnounced && mode === "vtable") {
          healedAnnounced = true;
          out.push(`object integrity restored secret=${C.secrets.vtable}`);
        }
        return out.join("\n");
      }
      hookedOnce = true;
      return [
        `callview: vtable ${vt.toString(16)} slot0 -> ${fn.toString(16)} (FOREIGN)`,
        "  pitch 12.5 -> REWRITTEN to 84.2 (aim assist)",
      ].join("\n");
    },

    // ---------------------------------------------------------- hotpatch
    spreadTest() {
      const site = C.calcSpreadFn;
      const b = Array.from(mem.read(site, 8));
      if (b[0] === 0xe9) {
        const rel = (b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24)) >>> 0;
        const target = site + 5n + BigInt(rel);
        hookedOnce = true;
        return [
          `spreadtest: calcspread @ 0x${site.toString(16)} detoured via sled`,
          `  E9 -> 0x${target.toString(16)}; spread 2.400 -> REWRITTEN to 0.010`,
        ].join("\n");
      }
      const honest = [
        "spreadtest: calcspread honest (spread 2.400)",
      ];
      if (hookedOnce && !healedAnnounced && mode === "hotpatch") {
        healedAnnounced = true;
        honest.push(`prologue restored from the sled secret=${C.secrets.hotpatch}`);
      }
      return honest.join("\n");
    },

    // --------------------------------------------------------------- drx
    /** Arm DR0 as an execute breakpoint (RW=00 LEN=1, DR7 L0/G0 enable). */
    drSet(va) {
      dr.dr0 = BigInt(va);
      dr.dr7 = 0x00000003n | 0x00030000n; // L0|G0 local+global enable, RW00 LEN... teaching bits
      return `DR0=0x${dr.dr0.toString(16)} DR7=0x${dr.dr7.toString(16)} (execute bp armed)`;
    },
    drClear() {
      const was = dr.dr0 !== 0n;
      dr.dr0 = 0n; dr.dr7 = 0n;
      return was ? "debug registers cleared" : "debug registers already clear";
    },
    /** Replay n frames through cl_sendinput; each trips an armed DR0 match. */
    frameTest(n) {
      let trips = 0;
      for (let i = 0; i < n; i++) {
        if (dr.dr0 === C.sendInputFn && (dr.dr7 & 0x3n)) trips++;
      }
      drTripsTotal += trips;
      const lines = [`frametest: replayed ${n} packet(s)`];
      if (trips > 0) {
        lines.push(`  #DB raised ${trips} time(s) at DR0=0x${dr.dr0.toString(16)} — handler read/modifed regs, no bytes touched`);
      } else {
        lines.push("  no breakpoints matched");
      }
      return lines.join("\n");
    },
    /** Anticheat counter-move: read the modeled thread context. */
    drxAudit() {
      if ((dr.dr0 !== 0n || dr.dr7 !== 0n)) {
        auditedFlagged = true;
        return [
          "drxaudit: GetThreadContext -> nonzero DR0/DR7",
          "AC VERDICT: FLAGGED (hardware breakpoints are not stealthy by themselves)",
        ].join("\n");
      }
      const lines = ["drxaudit: DR0-DR7 all zero"];
      if (auditedFlagged && drTripsTotal > 0 && mode === "drx") {
        lines.push(`used-and-cleared acknowledged secret=${C.secrets.drx}`);
      }
      return lines.join("\n");
    },
    get drState() { return { ...dr }; },
    get trips() { return drTripsTotal; },
  };

  // vtable mode seeds the cheat's fake table (heap-resident)
  if (mode === "vtable") {
    ensure(C.vtableFake);
    mem.w64(C.vtableFake, C.cheatStub);
    mem.w64(C.vtableFake + 8n, 0x00451100n);
    mem.w64(C.objectVa, C.vtableFake); // the swap already happened
  }

  return world;
}
