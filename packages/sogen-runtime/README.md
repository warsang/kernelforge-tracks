# @kernelforge/sogen-runtime

Windows-userland track runtime: a sogen-shaped userspace emulation session
(module list, process memory, pristine snapshots, modeled game actions) with a
deterministic plain-JS reference backend, plus the kd-style console engine the
userland labs are solved in.

- Labs target a headless Sauerbraten process model (`sauer-recon`,
  `sauer-hook` worlds).
- The real sogen WASM core (GPL-2.0, browser-native) is a drop-in upgrade —
  see `vendor/README.md`.
- World constants are pinned in `SAUER_CONSTANTS` and mirrored in the course
  catalog comments; changing them breaks flags.
