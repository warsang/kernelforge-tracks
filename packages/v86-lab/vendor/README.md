# Vendor: v86 + buildroot guest image (linux-kernel track)

The linux track boots a **real i386 Linux kernel** via
[v86](https://github.com/copy/v86) inside the browser tab. Nothing about the
guest is simulated by our code: real syscalls, real scheduler, real module
loader. This directory holds the vendored emulator bundle and (as a build
artifact, never committed) the guest image.

## What to vendor

| artifact | source | license |
|---|---|---|
| `v86-bundle-lib.js` (+ wasm) | upstream v86 at the pinned commit below | BSD-2-Clause (core); see upstream `LICENSE` for BIOS blobs |
| `seabios.bin`, `vgabios.bin` | bundled with v86 releases | LGPLv3 (Seabios) |
| `artifacts/bzImage` (+ rootfs.ext2) | built by `scripts/build-buildroot.sh` from OUR buildroot config | GPL-2.0 (kernel) |

Pinned upstream: record the exact v86 commit here when vendoring.

```sh
git clone https://github.com/copy/v86 && cd v86
git checkout <PINNED_COMMIT>
make all            # produces build/libv86.js + wasm
cp build/libv86.js  ../packages/v86-lab/vendor/v86-bundle-lib.js
cp bios/seabios.bin bios/vgabios.bin ../packages/v86-lab/vendor/
```

## Guest image

`scripts/build-buildroot.sh` builds an i386 buildroot with:
- busybox + gcc (module builds happen in-guest)
- kprobes/ftrace enabled, KASLR off (`CONFIG_RANDOMIZE_BASE=n`)
- the lab overlay: `/root/.kflag`, `/root/trigger`, `kfvillain.ko`
  (seed values come from `src/seeds.mjs` — keep them in sync)

Boot state is snapshotted after init so student sessions start in ~seconds.

## License notes

Kernel modules we author (kfvillain) are GPL-2.0; the build script keeps
their sources in-repo under `overlay/`. v86 core is BSD-2 — attribution in
docs/legal.md. BIOS blobs are not modified or redistributed beyond what
upstream release packaging already permits.
