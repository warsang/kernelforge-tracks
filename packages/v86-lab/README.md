# @kernelforge/v86-lab

Linux-kernel track runtime: a real i386 buildroot guest booted by v86 inside
the browser tab, plus the pure-JS lab harness around it.

- `src/serial.mjs` — line-buffered UART capture + KFFLAG secret extraction
  (fully unit-tested; the guest is never faked in tests).
- `src/session.mjs` — lazy v86 bundle loading with instructive soft-degrade;
  file injection (9p) and shell-line sending for in-guest module builds.
- `src/seeds.mjs` — per-lab guest seeds; single source of truth shared with
  `overlay/` and instructor notes.
- `scripts/build-buildroot.sh` — builds bzImage + rootfs (kprobes on, KASLR
  off); artifacts are never committed. See `vendor/README.md`.
