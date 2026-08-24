# browsercc fork — kernelforge

Fork of [BertalanD/browsercc](https://github.com/BertalanD/browsercc) (MIT)
that emits **native x86-64 code** (PE/COFF for Windows kernel drivers,
ELF for Linux) instead of only WebAssembly.

## Changes vs upstream

1. `build.sh`: `-DLLVM_TARGETS_TO_BUILD="X86;WebAssembly"` (X86 added;
   wasm kept so upstream demos and future lessons keep working).
2. Planned next: mingw-w64 headers subset + lld-link driver link mode
   (`/subsystem:native` / `/driver`) so `clang --target=x86_64-windows-gnu`
   produces real `.sys` objects fully client-side.
3. This repo's `packages/compiler-worker` wraps the built artifacts behind
   the same interface as the server compile bridge, so `apps/web` needs no
   code changes when the WASM path ships.

## Building

Requires Docker:

```bash
npm run build:container   # emsdk image (~10 min first time)
npm run build:wasm        # LLVM+clang+lld -> dist/*.js|*.wasm (long; X86 adds size)
```

Artifacts land in `dist/`: clang.js/wasm, lld.js/wasm, sysroot.tar.
