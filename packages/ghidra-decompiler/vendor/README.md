# Vendor: Ghidra native decompiler → wasm

The analysis pane decompiles with **Ghidra's C++ decompiler engine**
(`ghidra/Features/Decompiler/src/decompile/cpp`, Apache-2.0) compiled to
WebAssembly. Static-analysis commands (!funcs, rel32 resolution) work without
the artifact; `!decomp` degrades loudly until it is vendored.

## Build recipe (pinned)

1. Source: https://github.com/NationalSecurityAgency/ghidra — record the
   release tag here when vendoring.
2. Emscripten the standalone decompiler:
   ```
   git clone --depth 1 --branch <TAG> https://github.com/NationalSecurityAgency/ghidra
   cd ghidra/Features/Decompiler/src/decompile/cpp
   # swap the makefile toolchain for emcc, or use a community wasm port if
   # the pinned tag ships one; the binary target is `decompile` (sleigh + pdg)
   emmake make decompile
   ```
3. Produce `vendor/decompiler-wasm.mjs`: an emscripten MODULARIZE wrapper
   exposing
   ```
   export function decompile(imageBytes: Uint8Array, baseHex: string, funcHex: string): string
   ```
   Initialize SLEIGH with the x86-64 Windows .sla/.pspec from the same build.
4. Record provenance in this file: ghidra tag, emcc version, sha256 of the
   produced artifacts.

## License

Apache-2.0. Keep the upstream NOTICE text alongside the vendor directory;
the platform's license inventory lives in docs/legal.md.
