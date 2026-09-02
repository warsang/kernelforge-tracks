# @kernelforge/halfix-lab

Browser runtime for the Halfix x86 emulator (Win10 22H2 lab), mirroring `packages/v86-lab`.

## Contents

- `src/disk.mjs` — chunked 256 KiB disk backend with **Phase 6 fix** (widen 32-bit `|0`/`>>>0` to `Number`/`BigInt`). Provides IndexedDB chunk store + synthetic >4 GiB tester.
- `src/session.mjs` — WASM session wrapper (`bootHalfixSession`, `HalfixSession`, `buildConf`, `probeHalfixBundle`). WASM-only in webUI; native `vendor/halfix` binary is used offline for Phases 0/3/4.

## Quick start (native first, per spec)

```bash
# Phase 0 — toolchain check (must pass before browser work)
node -v        # >=20
gcc --version  # or clang
python3 --version  # >=3.10 for emscripten
emcc --version # 6.0.8

# Build native debug + release
cd vendor/halfix
node makefile.js
node makefile.js release

# Phase 6 patch is already in packages/halfix-lab/src/disk.mjs
# and vendor/halfix/runtime.js + libhalfix.js (see diff below)

# Phase 7 — WASM
node makefile.js emscripten --enable-wasm release
node ../../tools/copy-halfix-artifacts.mjs
```

## Phase 6 — 4 GiB fix (required before final deploy)

Original `vendor/halfix/runtime.js` and `libhalfix.js` used:

```js
chunk = (offset / 262144) | 0          // 32-bit signed truncation
blockoffs = (_url_to_blkid(i) << 18) >>> 0
file.slice((blockBase << 18) >>> 0, ...)
```

For 20 GiB `win10.img` this wraps at 4 GiB (`16384 * 256 KiB`). Fixed to:

```js
chunk = Math.floor(offset / 262144)          // Number-safe to 2^53
// or BigInt(offset / 262144n) for >2^53
```

Test before touching real image:

```js
import { ingestFile, readRange, writeRange, chunkIndex } from "@kernelforge/halfix-lab";
await ingestFile("synthetic-6g", sparse6gFile);
await writeRange("synthetic-6g", 6*1024*1024*1024, new Uint8Array([1,2,3]));
(await readRange("synthetic-6g", 6*1024*1024*1024, 3))[0] === 1 // true
```

## WASM disk serving (Phase 7)

Do **not** bundle `win10.img` as a static asset. Use `File` API + IndexedDB:

```js
const file = input.files[0]; // 20 GiB raw
await ingestFile("win10", file, (done,total)=>{});
const session = await bootHalfixSession({ ramMb: 2048, canvas, disk:{imageId:"win10"}, isoFile });
await session.start();
```

Optional remote URL (Internet Archive / Hugging Face) is streamed via `Range: bytes=` into same store — see `apps/web/src/halfix.js`.

## Config (Phase 1 + 2)

- **RAM**: 1024-2048 MB (valid 1-3584 MB). Default 2048 MB.
- **BIOS**: Bochs `bios.bin` (patched) + `vgabios.bin` — mandatory for ATAPI CD boot; SeaBIOS is buggy in Halfix (`compatibility.md`).
- **CPU tier**: `src/cpu/ops/misc.c` — enable `ATOM_N270_SUPPORT` (default) or `P4_SUPPORT` for FXSAVE/SSE2 (Windows 7/10). Spec’s Phase 1 asks for P4/Core Duo; Atom already exposes SSE2 and is sufficient.

## Native vs WASM

| Build | MIPS | Use |
|---|---|---|
| native `halfix` | 70-100 | Phase 0/3/4 debug, SSE #GP(0) repro |
| WASM `halfix.wasm` | 10-30 | Final deploy (`apps/web`) |

Always get native working before WASM.

## Synthetic test (Phase 6 step 3)

```
npm run test --workspace @kernelforge/halfix-lab
```

Runs `test/disk-chunk.test.mjs` — verifies >4 GiB indexing in Node; browser test is in `apps/web` devtools console via `verifyDiskBackend()`.
