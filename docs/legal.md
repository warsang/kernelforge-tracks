# Legal inventory — vendored engines & artifacts

Status: 2026-08 (phases 2–3 + ghidra pane). Update on every vendor bump.

| component | upstream | license | our obligations |
|---|---|---|---|
| Unicorn/QEMU wasm | AlexAltea/unicorn.js @ pinned commit (packages/ntsim-unicorn) | GPL-2.0 | source offer when distributing publicly; rebuild recipe in package README |
| sogen core (planned vendor) | momo5502/sogen @ pinned commit (packages/sogen-runtime/vendor) | GPL-2.0 | same policy as unicorn; keep JS reference backend as test fallback |
| Wine DLLs (emulation root) | winehq, built by tools/build-wine-root.mjs from a local WINEPREFIX | LGPL-2.1 | attribution; ship manifest with sha256s; never redistribute Microsoft DLLs |
| Sauerbraten engine | sauerbraten/Cube 2 engine | ZLIB | commercial OK; ZERO stock media — official installer link only |
| v86 | copy/v86 @ pinned commit (packages/v86-lab/vendor) | BSD-2-Clause (core) | attribution; BIOS blobs per upstream packaging terms |
| buildroot guest kernel + kfvillain | kernel.org 6.6.x + overlay/root/lab/kfvillain.c | GPL-2.0 | sources stay in-repo; image artifacts never committed |
| Ghidra decompiler engine | NationalSecurityAgency/ghidra (Features/Decompiler cpp), wasm wrapper | Apache-2.0 | keep NOTICE alongside vendor dir; record tag/emcc version/sha256 |
| Vergilius struct tables | vergiliusproject (scraped by ntsim-assets) | CC0 | none |

## Standing policies

- **Vendored wasm**: pinned upstream commit + provenance README + rebuild
  recipe in the package's `vendor/` dir; lazy-loaded so bundles never load
  unless a lab needs them; loud degradation when absent.
- **No proprietary binaries**: Windows DLLs, game media, and dump files are
  never committed. Students BYO where legally required; platform defaults to
  Wine-derived roots.
- **Educational/defensive framing** throughout; the responsible-use policy
  ships with the platform.
