# kernelforge-tracks
Track runtimes + course content for KernelForge.

- `@kernelforge/sogen-runtime` - Windows userland track (JS reference world + wasm-core) - GPL-2.0
- `@kernelforge/v86-lab` - Linux track: v86 i386 buildroot + GDB RSP bridge - BSD-2-Clause / GPL-2.0
- `@kernelforge/course-content` - module catalog, flag hashes, starters - MIT
- `@kernelforge/lab-runtime` - flag checker, progress reducer, IndexedDB - MIT

Sogen wasm: 90M `apps/web/public/sogen/32/analyzer.wasm` via Git LFS, fetched by `tools/fetch-sogen-wasm.mjs` (sha256 pin).
v86: vendor `v86.wasm` 2M + `seabios.bin` (BSD).
