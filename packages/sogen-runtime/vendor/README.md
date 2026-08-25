# Vendor: sogen WASM core (upgrade path)

The reference backend (`src/world.mjs`) is a deterministic plain-JS model of a
game process. The **real** sogen core (https://github.com/momo5502/sogen,
GPL-2.0) runs actual PE images against real system DLLs and replaces it behind
the same session API.

## What to vendor

1. Pin an upstream commit (record it here + in `vendor/BUILD-NOTES`).
2. Build the emscripten target:
   ```
   git clone --recurse-submodules https://github.com/momo5502/sogen.git
   cd sogen && cmake --preset=release-wasm   # see upstream wiki/Build-Instructions
   ```
3. Copy the produced `emulator-worker.js` (+ `.wasm`) into this directory.
4. Implement `src/backend-wasm.mjs`: spawn the worker, speak its Flatbuffers
   debugger protocol (upstream `page/src/emulator.ts` is the reference
   client), and adapt it to this package's session shape:

   ```js
   // target API the labs already use:
   session.mem.read/write/u32/w32      -> worker msg: mem_read/mem_write
   session.modules                     -> worker msg: module_list
   session.hookscan()                  -> snapshot + diff over module ranges
   ```

5. Flip `src/index.mjs#resolveBackend()` to prefer the wasm bundle with a
   lazy dynamic import; keep the JS backend as test/differential fallback
   (same policy as `packages/ntsim-unicorn`).

## License notes

- sogen core is GPL-2.0. Vendoring + distribution triggers the same source
  obligations already documented for `packages/ntsim-unicorn`; keep this
  directory's LICENSE notice intact.
- The emulation root ships Wine-derived DLLs (LGPL) — built by
  `tools/build-wine-root.mjs`, never committed from a real Windows install.
