# sogen-runtime vendor — WASM core provenance

Status: **JS glue vendored, 90 MB payload boot-fetched** (never committed).

## What is vendored in-repo

| file | lives at | sha256 |
|---|---|---|
| worker loader (`emulator-worker.js`) | `apps/web/public/sogen/emulator-worker.js` | `534513dea1fe8d6e44e2f780cbc712fecb677b97ff0e68240af1b6ae7fd6555c` |
| emscripten glue, 32-bit (`analyzer.js`) | `apps/web/public/sogen/32/analyzer.js` | `94ac9331d4c1349dcbd87425c6e9dc8c892d420e1fa0c3b41c8c6a9438a1a06f` |

Both pulled from the sogen.dev production deploy:
`https://sogen.dev/emulator-worker.js`, `https://sogen.dev/32/analyzer.js`
(last-modified `Tue, 25 Aug 2026 07:20:17 GMT`). Upstream project:
github.com/momo5502/sogen @ main (GPL-2.0) — obligations identical to the
Unicorn vendor row in docs/legal.md (source offer + rebuild recipe below).

## Wasm payload — git LFS (2026-08-26)

| file | size | sha256 |
|---|---|---|
| `apps/web/public/sogen/32/analyzer.wasm` | 90,132,854 bytes | `883249f7d2c6b92656198daf08683ea865b1094fcab24e8719aa4a52b2f8be3c` |

Tracked via git LFS (`.gitattributes`) — plain clones pull it automatically.
Environments without LFS can still boot-fetch: `npm run vendor:sogen`
(tools/fetch-sogen-wasm.mjs, pinned sha256; override via `SOGEN_WASM_URL`).

## Rebuild from source (upstream recipe)

```bash
git clone https://github.com/momo5502/sogen && cd sogen
git submodule update --init --recursive
cmake --preset emscripten        # cmake/toolchain/emscripten.cmake
cmake --build --preset emscripten
# outputs page/public/emulator-worker.js + page/public/{32,64}/analyzer.{js,wasm}
```

Record any re-vendor here with commit hash + all four sha256s.

## Integration state

- Worker lifecycle (run/log/end messages), asset probe, and session flip:
  `src/backend-wasm.mjs` (+ `resolveSogenBackend` in src/index.mjs).
- Debugger verb channel (Flatbuffers DebugCommand envelope → JSON payloads,
  kinds 0–13 per upstream docs/debugger/ARCHITECTURE.md): transport is wired;
  the Flatbuffers encoder/decoder is the remaining milestone — tracked in
  backend-wasm.mjs as `debugCommand()`, loud-degrades to the static session
  until it lands.
