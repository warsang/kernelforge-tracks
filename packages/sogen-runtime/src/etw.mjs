/**
 * ETW userland blindfolding world ("etw-blind") — m26.l1.
 *
 * A plain-JS model of a game process whose telemetry flows through the
 * ntdll wrapper layer: EtwEventWrite validates the caller's RegHandle and
 * builds the event before it ever reaches the kernel. Patch those bytes
 * with `xor eax,eax; ret` (31 C0 C3) or null the RegHandle and every event
 * dies QUIETLY — no crash, no log line, just a telemetry gap.
 *
 * Layout:
 *   ntdll.dll            base 0x77400000 (stub page materialized)
 *     EtwEventWrite      0x7749e2a0   prologue: 48 89 5c 24 08 ...
 *   heap
 *     providerTable      0x00680100   { u32 regHandle } x 2 providers
 *
 * Teaching anchor: none of this is visible to PatchGuard (userland).
 * What catches it in the real world: EDR self-protection re-checking
 * ntdll .text against a clean remap, direct-syscall designs that skip the
 * wrappers entirely, and consumer-side gap alarms.
 */
import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";

export const ETW_USER_CONSTANTS = {
  ntdllBase: 0x77400000n,
  etwEventWrite: 0x7749e2a0n,
  providerTable: 0x00680100n,
  pristinePrologue: [0x48, 0x89, 0x5c, 0x24, 0x08],
  providers: [
    { name: "SauerGame", handle: 0xe7000001 },
    { name: "AC-Telemetry", handle: 0xe7000002 },
  ],
  restoreSecret: "kf-etw-restored",
};

/** MSVC-ish body behind the prologue; ends in a modeled success return. */
const EVENTWRITE_BODY = [
  ...ETW_USER_CONSTANTS.pristinePrologue,
  0x33, 0xc0,             // xor eax, eax
  0xc3,                   // ret
];

export function buildEtwUserWorld() {
  const C = ETW_USER_CONSTANTS;
  const mem = new SparseMemory();

  // materialize the ntdll stub page holding EtwEventWrite
  const page = C.etwEventWrite & ~0xfffn;
  mem.ensurePage(page);
  mem.write(C.etwEventWrite, EVENTWRITE_BODY);

  // provider registration table (RegHandles the game cached at startup)
  mem.ensurePage(C.providerTable & ~0xfffn);
  C.providers.forEach((p, i) => {
    mem.w32(C.providerTable + BigInt(i * 8), p.handle);
  });

  let emitted = 0;
  let delivered = 0;
  let suppressed = 0;
  let healAnnounced = false;
  const log = [];

  function livePatched() {
    const b = Array.from(mem.read(C.etwEventWrite, 3));
    if (b[0] === 0x31 && b[1] === 0xc0 && b[2] === 0xc3) return true; // xor eax,eax; ret
    if (b[0] === 0xc2 || b[0] === 0xc3) return true;                  // bare ret forms
    return false;
  }

  return {
    kind: "etw-blind",
    etw: true,
    mem,
    constants: C,
    modules: [
      { name: "ntdll.dll", base: C.ntdllBase, size: 0x190000 },
      { name: "kernel32.dll", base: 0x76b80000n, size: 0x110000 },
    ],

    /** Modeled game telemetry: emit n events through the LIVE wrapper path. */
    emitEvents(n) {
      for (let i = 0; i < n; i++) {
        emitted++;
        const prov = C.providers[emitted % C.providers.length];
        const handle = mem.u32(
          C.providerTable + BigInt((emitted % C.providers.length) * 8));
        if (livePatched()) {
          suppressed++;
          log.push(`event#${emitted} ${prov.name}: DROPPED (wrapper patched)`);
        } else if (handle === 0) {
          suppressed++;
          log.push(`event#${emitted} ${prov.name}: dropped (RegHandle NULL)`);
        } else {
          delivered++;
          log.push(`event#${emitted} ${prov.name}: delivered`);
        }
      }
      return { emitted, delivered, suppressed };
    },

    /** !etwtrace: provider handles + recent events + gap summary. */
    trace() {
      const lines = ["ETW user-mode trace:"];
      C.providers.forEach((p, i) => {
        const h = mem.u32(C.providerTable + BigInt(i * 8));
        lines.push(`  ${p.name.padEnd(16)} RegHandle=0x${h.toString(16).padStart(8, "0")}` +
          (h === 0 ? "  (NULL!)" : ""));
      });
      lines.push(...log.slice(-6).map((l) => `  ${l}`));
      lines.push(`  totals: delivered=${delivered} suppressed=${suppressed}`);
      if (!livePatched() && delivered > 0 && suppressed === 0 &&
          C.providers.every((_, i) => mem.u32(C.providerTable + BigInt(i * 8)) !== 0)) {
        lines.push(`  telemetry honest end-to-end secret=${C.restoreSecret}`);
        healAnnounced = true;
      }
      void healAnnounced;
      return lines.join("\n");
    },

    /** True when the wrapper bytes differ from the pristine prologue. */
    isPatched: livePatched,

    resetCounters() {
      emitted = delivered = suppressed = 0;
      log.length = 0;
    },
  };
}
