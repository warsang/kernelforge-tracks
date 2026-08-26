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

## Provenance record (fill on vendor)

- pyre commit:
- ghidra source tag used for SLEIGH specs:
- emcc version:
- sha256 (decompiler-wasm.mjs / .wasm / x86-64.sla):

## License

Apache-2.0 (upstream Ghidra); pyre tooling MIT. Keep upstream NOTICE text
alongside the vendor directory; inventory lives in docs/legal.md.
