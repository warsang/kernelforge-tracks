/**
 * Sauerbraten headless target — synthetic game-process world.
 *
 * This is the REFERENCE backend for the windows-userland track: a plain-JS
 * model of a game process under a sogen-style userspace emulator (module
 * list, materialized image/heap pages, pristine snapshots, modeled actions).
 * The real sogen WASM core is a drop-in upgrade behind the same session API
 * (see vendor/README.md); every lab constant below is pinned and mirrored in
 * packages/course-content/src/catalog.mjs comments.
 *
 * Layout (all BigInt at the edges):
 *   sauerbraten.exe  base 0x00400000 size 0x90000 (.text RVA 0x1000 size 0x88000)
 *     cl_sendinput       0x004532a0
 *     cheat stub         0x0046f010   (sauer-hook world only)
 *   ntdll/kernel32/user32/opengl32 — registered metadata only (uncommitted)
 *   heap             0x02100000..0x02112000
 *     entity array   0x02100010, stride 0x40, 6 entries
 *       entity struct: +0x00 vtable:u64, +0x08 type:i32, +0x0c team:i32,
 *                      +0x10 x/y/z:f32, +0x24 health:i32, +0x28 armor:i32,
 *                      +0x2c name:char[16]
 *       local player = index 3 ("kfgamer") => 0x021000d0, health +0x24
 *     decoys          ~7 stale dwords == initial health scattered in heap
 */
import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { mulberry32 } from "./rand.mjs";

export const SAUER_CONSTANTS = {
  imageBase: 0x00400000n,
  imageSize: 0x90000,
  textRva: 0x1000,
  textSize: 0x88000,
  clSendInput: 0x004532a0n,
  cheatStub: 0x0046f010n,
  heapBase: 0x02100000n,
  heapSize: 0x12000,
  entityArray: 0x02100010n,
  entityStride: 0x40,
  entityCount: 6,
  playerIndex: 3,
  healthOffset: 0x24,
  inputSecret: "kf-input-restored",
};

const MODULES = [
  { name: "sauerbraten.exe", base: 0x00400000n, size: 0x90000 },
  { name: "ntdll.dll", base: 0x77400000n, size: 0x190000 },
  { name: "kernel32.dll", base: 0x76b80000n, size: 0x110000 },
  { name: "user32.dll", base: 0x75a80000n, size: 0xa0000 },
  { name: "opengl32.dll", base: 0x6f800000n, size: 0x80000 },
];

const ENTITY_NAMES = ["bot_alpha", "bot_bravo", "bot_charlie", "kfgamer", "bot_delta", "bot_echo"];

/** Original 10-byte prologue of cl_sendinput (MSVC-style x64 frame setup). */
export const SENDINPUT_PROLOGUE = [0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10];

function fillText(mem, rng) {
  const base = SAUER_CONSTANTS.imageBase;
  const textStart = base + BigInt(SAUER_CONSTANTS.textRva);
  const block = new Uint8Array(16);
  for (let off = 0; off < SAUER_CONSTANTS.textSize; off += 16) {
    const addr = textStart + BigInt(off);
    if (addr === SAUER_CONSTANTS.clSendInput) {
      // canonical prologue + tail so the function reads like its neighbors
      mem.write(addr, [...SENDINPUT_PROLOGUE, 0x48, 0x89, 0x74, 0x24, 0x18, 0xc3]);
      continue;
    }
    for (let i = 0; i < 16; i++) {
      block[i] = i === 15 ? 0xc3 : (i % 5 === 4 ? (rng() * 256) | 0 : [0x48, 0x89, 0x5c, 0x24, 0x40, 0x53][i % 6]);
    }
    mem.write(addr, block);
  }
}

function applyDetour(mem) {
  const site = SAUER_CONSTANTS.clSendInput;
  const stub = SAUER_CONSTANTS.cheatStub;
  const rel = Number(stub - (site + 5n)) >>> 0;
  mem.write(site, [0xe9, rel & 0xff, (rel >>> 8) & 0xff, (rel >>> 16) & 0xff, (rel >>> 24) & 0xff]);
}

function writeStub(mem) {
  const stub = SAUER_CONSTANTS.cheatStub;
  // plausible stub body: read pitch ptr, rewrite, jump back to site+5
  const body = [
    0x48, 0x8b, 0x42, 0x08, // mov rax,[rdx+8]
    0xb9, 0x66, 0x66, 0xa6, 0x42, // mov ecx,0x42a66666
    0x89, 0x08, // mov [rax],ecx
  ];
  mem.write(stub, body);
  const backTo = SAUER_CONSTANTS.clSendInput + 5n;
  const here = stub + BigInt(body.length) + 5n;
  const rel = Number(backTo - here) >>> 0;
  mem.write(stub + BigInt(body.length), [0xe9, rel & 0xff, (rel >>> 8) & 0xff, (rel >>> 16) & 0xff, (rel >>> 24) & 0xff]);
}

function writeEntities(mem) {
  const C = SAUER_CONSTANTS;
  const arr = C.entityArray;
  const vtables = [0x005e12a0n, 0x005e12a0n, 0x005e12a0n, 0x005e1b40n, 0x005e12a0n, 0x005e12a0n];
  for (let i = 0; i < C.entityCount; i++) {
    const e = arr + BigInt(i * C.entityStride);
    mem.w64(e, vtables[i]);
    mem.w32(e + 8n, i === C.playerIndex ? 1 : 0);           // type
    mem.w32(e + 0xcn, i % 2 === 0 ? 0 : 1);                  // team
    mem.w32(e + 0x10n, 0x41f00000 + i);                      // x float-ish
    mem.w32(e + 0x14n, 0x42340000 + i);                      // y
    mem.w32(e + 0x18n, 0x42700000 + i);                      // z
    mem.w32(e + 0x24n, 100);                                 // health
    mem.w32(e + 0x28n, 50 + i);                              // armor
    mem.writeAnsi(e + 0x2cn, ENTITY_NAMES[i], 16);
  }
}

function writeDecoys(mem, rng) {
  // stale full-health copies elsewhere on the heap so the first scan is noisy
  let placed = 0;
  while (placed < 7) {
    const addr = SAUER_CONSTANTS.heapBase + 0x10000n + BigInt(((rng() * 0x1000) | 0) & ~3);
    if (!mem.canRead(addr, 4)) mem.ensurePage(addr & ~0xfffn);
    if (mem.u32(addr) === 0) {
      mem.w32(addr, 100);
      placed++;
    }
  }
}

/**
 * Build the emulated game-process world.
 * @param {{hooked?: boolean}} opts sauer-hook passes hooked:true
 */
export function buildSauerWorld({ hooked = false } = {}) {
  const mem = new SparseMemory();
  const rng = mulberry32(0x005a1e57);

  // materialize headers page + .text + heap
  mem.ensurePage(SAUER_CONSTANTS.imageBase);
  mem.write(SAUER_CONSTANTS.imageBase, [0x4d, 0x5a, 0x90, 0x00]); // 'MZ'
  fillText(mem, rng);

  if (hooked) {
    // the cheat DLL's stub predates our baseline; only the prologue patch
    // is a live modification for hookscan to find.
    writeStub(mem);
  }

  // pristine snapshot BEFORE any hook application (hookscan baseline)
  const pristine = new Map();
  for (const p of mem.pages.entries()) pristine.set(p[0], Uint8Array.from(p[1]));

  if (hooked) applyDetour(mem);

  for (let off = 0; off < SAUER_CONSTANTS.heapSize; off += 0x1000) {
    mem.ensurePage(SAUER_CONSTANTS.heapBase + BigInt(off));
  }
  writeEntities(mem);
  writeDecoys(mem, rng);

  return {
    kind: hooked ? "sauer-hook" : "sauer-recon",
    mem,
    modules: MODULES.map((m) => ({ ...m })),
    constants: SAUER_CONSTANTS,

    /** diff live vs pristine across all pages -> array of {addr, orig, live} */
    hookscan() {
      const diffs = [];
      const keys = new Set([...mem.pages.keys()]);
      for (const k of keys) {
        const live = mem.pages.get(k);
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

    /** scenario action: local player takes n damage (bots unaffected). */
    damage(n) {
      const e = SAUER_CONSTANTS.entityArray +
        BigInt(SAUER_CONSTANTS.playerIndex * SAUER_CONSTANTS.entityStride);
      const addr = e + BigInt(SAUER_CONSTANTS.healthOffset);
      const cur = mem.u32(addr);
      const next = Math.max(0, cur - n);
      mem.w32(addr, next);
      return next;
    },

    health() {
      const e = SAUER_CONSTANTS.entityArray +
        BigInt(SAUER_CONSTANTS.playerIndex * SAUER_CONSTANTS.entityStride);
      return mem.u32(e + BigInt(SAUER_CONSTANTS.healthOffset));
    },

    /**
     * Modeled engine behavior gate: replay a scripted input batch through
     * cl_sendinput's LIVE bytes. Detoured => angles rewritten (aim assist).
     * Pristine  => honest path, prints the module secret.
     */
    inputTest() {
      const site = SAUER_CONSTANTS.clSendInput;
      const live = Array.from(mem.read(site, 5));
      const detoured = live[0] === 0xe9;
      if (detoured) {
        const rel = (live[1] | (live[2] << 8) | (live[3] << 16) | (live[4] << 24)) >>> 0;
        const target = site + 5n + BigInt(rel);
        return {
          honest: false,
          lines: [
            `inputtest: replaying 16 packets through cl_sendinput @ 0x${site.toString(16)}...`,
            `  packet[0] yaw 12.500 pitch -12.400 -> angles REWRITTEN to pitch 84.200`,
            `  detour ACTIVE (E9 -> 0x${target.toString(16)})`,
          ],
        };
      }
      return {
        honest: true,
        lines: [
          `inputtest: replaying 16 packets through cl_sendinput @ 0x${site.toString(16)}...`,
          `  packet[0] yaw 12.500 pitch -12.400 -> passthrough OK`,
          `  control flow honest; engine all-clear: ${SAUER_CONSTANTS.inputSecret}`,
        ],
      };
    },
  };
}
