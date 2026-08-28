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
      "packages/v86-lab/scripts/build-buildroot.sh and copy with tools/copy-v86-artifacts.mjs " +
      "(or npm run build --workspace @kernelforge/web). See packages/v86-lab/vendor/README.md.",
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

/** Fetch the CPIO initrd (built alongside bzImage). */
export async function fetchRootfs(fetchImpl = globalThis.fetch) {
  const res = await fetchImpl("vendor/artifacts/rootfs.cpio").catch(() => null);
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
    initrd: rootfs ? { buffer: rootfs } : undefined,
    cmdline: "console=ttyS0 tsc=reliable noapic root=/dev/ram0 rw init=/sbin/init",
    memory_size: 256 * 1024 * 1024, // 256MB — enough for kernel + initrd
    uart1: true,
    autostart: true,
    // 9p filesystem for host->guest file injection (student module source).
    // Without this, emulator.create_file() rejects; see injectFile fallback.
    filesystem: {},
    // wasm sits next to the vendored bundle; served by the app origin
    wasm_path: "vendor/v86.wasm",
  });

  // wire UART output into the capture harness
  emulator.add_listener("serial0-output-byte", (byte) => {
    serial.push(new Uint8Array([byte]));
  });

  const session = new V86LabSession(emulator, serial, worldId);

  // If this is a real boot (not a mock injected by tests), wait for the
  // guest shell to be ready. Buildroot's getty on ttyS0 prints
  // "buildroot login:" and expects "root" (no password); the overlay's
  // S99kflag also prints "guest ready ~#" once lab-init finishes. We
  // handle both so the prompt the student sees is immediately usable and
  // `gdb start` probes are not lost to a login prompt.
  // Tests that inject `v86: null` or a mock bundle skip this (they use a
  // fake image and never produce real serial output).
  const isRealBoot = bundle && image && typeof image.byteLength === "number" && image.byteLength > 1024;
  if (isRealBoot) {
    try {
      await session.waitForShell({ timeoutMs: 120_000 });
    } catch (e) {
      // Non-fatal: boot still succeeded, but shell may not be ready yet.
      // The web console will still tail serial output; commands may need a
      // manual `root` login. Log for debugging but don't throw.
      console.warn("[v86] waitForShell timeout:", e.message);
    }
  }

  return session;
}

export class V86LabSession {
  constructor(emulator, serial, worldId) {
    this.emulator = emulator;
    this.serial = serial;
    this.worldId = worldId;
  }

  /**
   * Wait until the guest shell is interactive.
   * Handles the buildroot `buildroot login:` prompt by auto-sending `root`
   * (no password) and then waits for a shell prompt (`#` or `guest ready`).
   * The overlay's S99kflag prints `guest ready ~#` once decoys and villains
   * are done; a real root shell's PS1 is `~ #` or `# `.
   */
  async waitForShell({ timeoutMs = 120_000 } = {}) {
    const start = Date.now();
    let loginSent = false;
    let lastLoginCheck = 0;

    const isShellPromptLine = (line) => {
      const t = line.replace(/\r/g, "").trim();
      if (!t) return false;
      // Lab marker is not a shell prompt — it just signals lab-init done
      if (t.includes("guest ready")) return false;
      // Real shell: `~ #`, `/ #`, `#`, `buildroot:~#`
      if (t === "#" || t.endsWith("#") || /[~\/] #$/.test(t) || t === "~ #" || t.endsWith(" #")) return true;
      // Also handle `~ #` without newline yet (buffer)
      return false;
    };
    const hasShellPrompt = (raw) => {
      const tail = raw.slice(-4096);
      const lines = tail.split("\n");
      // Check last 8 lines for a prompt
      for (let i = lines.length - 1; i >= Math.max(0, lines.length - 8); i--) {
        if (isShellPromptLine(lines[i])) return true;
      }
      // Fallback: check for prompt without newline at end (partial buffer)
      const last = lines[lines.length - 1]?.replace(/\r/g, "").trim() ?? "";
      if (last.endsWith("#") || last.includes("~ #")) return true;
      return false;
    };

    // Phase 1: wait for lab-init to finish (guest ready). This is the signal
    // that the kernel, S99kflag overlay, and kfvillain have all loaded. We
    // must not return before this, otherwise probes race the boot.
    while (Date.now() - start < timeoutMs) {
      const raw = this.serial.text + "\n" + this.serial.buffer;
      if (raw.includes("guest ready")) break;
      await new Promise((r) => setTimeout(r, 300));
    }

    // Phase 2: wait for login / askfirst prompt and auto-login. Some builds
    // autologin via inittab (`getty -a root` or `login -f root` or
    // `askfirst:/bin/sh`), so login may never appear — that's fine, we just
    // proceed to prompt wait. `askfirst` prints `Please press Enter to
    // activate this console` and waits for a newline.
    const loginDeadline = Date.now() + 10000;
    let askFirstSent = false;
    while (Date.now() < loginDeadline && Date.now() - start < timeoutMs) {
      const raw = this.serial.text + "\n" + this.serial.buffer;
      const lower = raw.toLowerCase();
      if (lower.includes("login:")) {
        if (Date.now() - lastLoginCheck > 800) {
          lastLoginCheck = Date.now();
          if (!loginSent) {
            await this.sendLine("root");
            loginSent = true;
            await new Promise((r) => setTimeout(r, 1200));
            break;
          }
        }
      }
      if (!askFirstSent && (lower.includes("press enter") || lower.includes("activate this console"))) {
        await this.sendLine("");
        askFirstSent = true;
        await new Promise((r) => setTimeout(r, 800));
        // After pressing Enter, askfirst spawns sh, which will print its PS1
        continue;
      }
      // If we already have a shell prompt, no need to login
      if (hasShellPrompt(raw)) break;
      await new Promise((r) => setTimeout(r, 300));
    }

    // Phase 3: wait for an actual shell prompt (`#`). This is the only
    // reliable signal that `sh` is ready to accept `echo probe` etc.
    while (Date.now() - start < timeoutMs) {
      const raw = this.serial.text + "\n" + this.serial.buffer;
      if (hasShellPrompt(raw)) {
        await new Promise((r) => setTimeout(r, 500));
        // Re-check stability
        const raw2 = this.serial.text + "\n" + this.serial.buffer;
        if (hasShellPrompt(raw2)) return;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error("timeout waiting for guest shell prompt (#)");
  }

  /** Push a file into the guest (used for staged modules). */
  async injectFile(guestPath, bytes) {
    const normalized = "/" + guestPath.replace(/^\//, "");
    // Prefer the host 9p filesystem when available (v86 CreateBinaryFile).
    // Falls back to a serial heredoc so the labs work even without a 9p
    // kernel driver (the guest's initrd rootfs is not the same as the 9p
    // share). Keep the 9p attempt first because it is atomic for large files.
    if (typeof this.emulator.create_file === "function") {
      try {
        await this.emulator.create_file(normalized, bytes);
        // Also mirror via serial heredoc when a 9p mount is not configured
        // in the guest (no CONFIG_NET_9P): the file lives in the host fs,
        // not at guest's /root/lab. Verify by trying to read back via serial
        // is too racy, so we always also stream it over ttyS0.
      } catch {
        // create_file rejected (no filesystem option or path parent missing)
      }
    }
    // Serial heredoc fallback — works on any guest with a shell on ttyS0.
    // Uses a random delimiter to avoid colliding with file contents.
    const text = typeof bytes === "string" ? bytes : new TextDecoder().decode(bytes);
    const delim = "__KF_EOF_" + Math.random().toString(36).slice(2, 8) + "__";
    // Ensure parent dir exists (guest overlay already does, but be safe)
    const dir = normalized.split("/").slice(0, -1).join("/") || "/";
    await this.sendLine(`mkdir -p ${dir}`);
    await this.sendLine(`cat > ${normalized} <<'${delim}'`);
    // Stream the file line-by-line over the emulated UART.
    // Throttle to ~64 chars per tick so the guest's 16550 FIFO does not drop.
    for (const line of text.split("\n")) {
      await this.sendLine(line);
    }
    await this.sendLine(delim);
    // Brief yield so the guest shell can flush the heredoc before the next
    // command (caller immediately sends guestBuildSequence).
    await new Promise((r) => setTimeout(r, 120));
  }

  /** Type a command into the guest console (shell over ttyS0). */
  async sendLine(line) {
    for (const ch of line + "\n") {
      this.emulator.serial0_send(ch);
      // Yield per-char so the 16550 16-byte FIFO doesn't overflow on long lines
      // (e.g. `which gdbserver ...` or heredoc delimiters). 20ms is safe for
      // v86's 16550 16-byte FIFO at 115200 baud in the browser event loop
      // and avoids the `ps` -> `p` / `echo` -> `oheoY` truncation seen with
      // 2-10ms under load (the shell's line discipline is slow to drain).
      await new Promise((r) => setTimeout(r, 20));
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
