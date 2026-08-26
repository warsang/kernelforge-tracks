# Vendor: Ghidra native decompiler → wasm

The analysis pane decompiles with **Ghidra's C++ decompiler engine**
(`ghidra/Features/Decompiler/src/decompile/cpp`, Apache-2.0) compiled to
WebAssembly. Static-analysis commands (!funcs, rel32 resolution) work without
the artifact; `!decomp` and the debugger shell's Pseudocode tab degrade
loudly until it is vendored.

## Build recipe — pyre pipeline (adopted 2026-08)

[pyre](https://github.com/ant4g0nist/pyre) (MIT) ships a maintained,
docker-contained build of exactly this artifact; we adopt its pipeline:

```bash
git clone https://github.com/ant4g0nist/pyre && cd pyre
# option A: local emsdk
./decompiler-wasm/build.sh            # -> decompiler-wasm/dist/pyre_decompiler.{js,wasm}
# option B: hermetic docker (emsdk + JDK + gradle)
docker build -t pyre-dev -f docker/Dockerfile .
docker run --rm -it -v "$PWD":/work -w /work -p 5173:5173 pyre-dev
#   then, inside: ./decompiler-wasm/build.sh
```

Stage SLEIGH specs for x86-64 from any Ghidra install:

```bash
./specs/stage-specs.sh /path/to/ghidra   # -> specs/dist/x86/data/languages/*.{sla,ldefs,cspec,pspec}
```

### Adapter shim (drop at packages/ghidra-decompiler/src/decompiler-wasm.mjs)

pyre's bridge speaks worker-JSON; our wrapper contract is an emscripten
MODULARIZE export:

```js
export function decompile(imageBytes: Uint8Array, baseHex: string, funcHex: string): string
```

Wrap `pyre_decompiler.js`: mount the staged specs under `/spec` (lazy FS),
register the image bytes as a single-region LoadImage, call through to
Ghidra's `decompile(funcAddr)`, return the generated C. Keep the wrapper's
signature so `src/wrapper.mjs` and `src/client.mjs` need no changes.

## Provenance record

- pyre commit: `835d7dd871304966165339d8cc7ae2deb0d00789` (cloned 2026-08-26)
- ghidra source tag used for SLEIGH specs: pyre `specs/dist` snapshot at the
  commit above (x86 `.sla` version 4.6); staged verbatim
- emcc version: Emscripten 6.0.8 (Homebrew), python 3.14 host
- sha256:
  - `decompiler-wasm.mjs` (shim copy): `a0a7856f1c92e329ebe23b1d0d4c56553dc95db4c826cc752effa1d2f759bb6e`
  - `pyre_decompiler.js`: `b997f3c40e95a63b5ff2d5a81f65d9157aa661c7f8b948e717798146d47cc8e0`
  - `pyre_decompiler.wasm`: `d64440f27f7186b018e4278ba03b757ff37b278d967a609112f72e74cbc9a595`
  - `specs/x86/data/languages/x86-64.sla`: `7df34cf9c3f3173346811fa88132ecc48a6c1de6a45ecb607c053abacea78e83`

Rebuild: `npm run vendor:ghidra` (tools/build-ghidra-wasm.mjs). The shim is
versioned at `vendor/shim.mjs`; artifacts under
`apps/web/public/vendor/ghidra/` stay untracked (.gitignore).
Integration test: `packages/ghidra-decompiler/test/wasm-integration.test.mjs`
(auto-skips while artifacts are absent).

## License

Apache-2.0 (upstream Ghidra); pyre tooling MIT. Keep upstream NOTICE text
alongside the vendor directory; inventory lives in docs/legal.md.
