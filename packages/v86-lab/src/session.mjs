/**
 * v86 lab session — boots a real i386 Linux kernel inside the browser tab.
 *
 * The vendored v86 bundle (vendor/) is lazy-loaded; without it every entry
 * point throws an instructive error instead of failing silently. Node tests
 * exercise everything except the emulator itself (serial harness, seeds,
 * module staging), mirroring the platform's soft-degrade conventions.
 */

import { SerialCapture } from "./serial.mjs";
import { GdbSession } from "./gdb-session.mjs";

let cachedBundle = null;

/**
 * Resolve the vendored v86 bundle, or null with a clear reason.
 * The bundle file is produced by scripts/build-buildroot.sh's sibling step —
 * see vendor/README.md for the pinned upstream + rebuild recipe.
 */
export async function resolveV86() {
  if (cachedBundle !== null) return cachedBundle;
  try {
    // opaque specifier: bundlers must not try to resolve a missing vendor file
    const spec = new URL("../vendor/v86-bundle-" + "lib.js", import.meta.url).href;
    cachedBundle = await import(/* @vite-ignore */ `${spec}`).catch(() => null);
  } catch {
    cachedBundle = null;
  }
  return cachedBundle;
}

export class BundleMissingError extends Error {
  constructor() {
    super(
      "v86 wasm bundle not vendored. Run packages/v86-lab/scripts/build-buildroot.sh " +
      "(see vendor/README.md) — the linux track needs a real guest image.",
    );
    this.name = "BundleMissingError";
  }
}

export class ImageMissingError extends Error {
  constructor() {
    super(
      "guest bzImage not found under vendor/artifacts/. Build it with " +
      "packages/v86-lab/scripts/build-buildroot.sh.",
    );
    this.name = "ImageMissingError";
  }
}

/**
 * Fetch the vendored guest image relative to the app origin.
 * @param {(url: string) => Promise<Response>} [fetchImpl]
 */
export async function fetchGuestImage(fetchImpl = globalThis.fetch) {
  const res = await fetchImpl("vendor/artifacts/bzImage").catch(() => null);
  if (!res || !res.ok) throw new ImageMissingError();
  return res.arrayBuffer();
}

/** Fetch the ext2 rootfs disk (built alongside bzImage). */
export async function fetchRootfs(fetchImpl = globalThis.fetch) {
  const res = await fetchImpl("vendor/artifacts/rootfs.ext2").catch(() => null);
  if (!res || !res.ok) throw new ImageMissingError();
  return res.arrayBuffer();
}

/**
 * Boot a linux lab session.
 * @param {object} opts
 * @param {string} opts.worldId        lkm-hello | syscall-trace | task-hide
 * @param {ArrayBufferLike} [opts.image] bzImage bytes (vendored artifact)
 * @param {ArrayBufferLike} [opts.rootfs] ext2 rootfs bytes (hda)
 * @param {ArrayBufferLike} [opts.snapshot] saved v86 state for fast boot
 * @param {object} [opts.v86]          pre-resolved bundle (tests inject mocks)
 */
export async function bootLinuxSession({ worldId, image, rootfs, snapshot, v86 }) {
  if (!worldId) throw new Error("bootLinuxSession: worldId required");

  // Explicit `v86: null` forces the missing-bundle path (deterministic in
  // tests); otherwise lazily resolve whatever is vendored.
  const bundle = v86 !== undefined ? v86 : await resolveV86();
  if (!bundle) throw new BundleMissingError();

  const serial = new SerialCapture();
  // NB: the vendored bundle's V86 is a constructor — calling it without `new`
  // throws "Cannot add property cpu_is_running, object is not extensible"
  // (strict-mode `this` is undefined inside the CPU class).
  const emulator = await new bundle.V86({
    bios: { url: "vendor/seabios.bin" },
    vga_bios: { url: "vendor/vgabios.bin" },
    bzimage: { buffer: image },
    hda: rootfs ? { buffer: rootfs, async: false } : undefined,
    cmdline: "console=ttyS0 tsc=reliable root=/dev/sda rw init=/sbin/init",
    uart1: true,
    autostart: true,
    // wasm sits next to the vendored bundle; served by the app origin
    wasm_path: "vendor/v86.wasm",
  });

  // wire UART output into the capture harness
  emulator.add_listener("serial0-output-byte", (byte) => {
    serial.push(new Uint8Array([byte]));
  });

  return new V86LabSession(emulator, serial, worldId);
}

export class V86LabSession {
  constructor(emulator, serial, worldId) {
    this.emulator = emulator;
    this.serial = serial;
    this.worldId = worldId;
  }

  /** Push a file into the guest via the 9p mount (used for staged modules). */
  async injectFile(guestPath, bytes) {
    await this.emulator.create_file("/" + guestPath.replace(/^\//, ""), bytes);
  }

  /** Type a command into the guest console (shell over ttyS0). */
  sendLine(line) {
    for (const ch of line + "\n") {
      this.emulator.serial0_send(ch.charCodeAt(0));
    }
  }

  async destroy() {
    try { await this.emulator.destroy(); } catch { /* already gone */ }
  }

  /**
   * Attach a GDB RSP session to the guest's gdbserver over ttyS1.
   * The guest must have started it first: `gdbserver /dev/ttyS1 <target>`.
   * Requires the buildroot image to include gdb-server (see
   * scripts/build-buildroot.sh — BR2_PACKAGE_GDB_SERVER).
   */
  async attachGdb() {
    const emu = this.emulator;
    const transport = {
      send: (bytes) => {
        for (const b of bytes) {
          if (typeof emu.serial1_send === "function") emu.serial1_send(b);
          else if (emu.bus) emu.bus.send("serial1-input", b);
          else throw new Error("v86: no uart1 tx path on this bundle");
        }
      },
      onReceive: (cb) => {
        emu.add_listener?.("serial1-output-byte", (byte) => cb(byte));
      },
    };
    return GdbSession.attach(transport);
  }
}
