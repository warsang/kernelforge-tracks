/**
 * @kernelforge/halfix-lab — browser session wrapper around halFix WASM
 *
 * Mirrors packages/v86-lab/src/session.mjs pattern but for halFix:
 *  - lazy WASM bundle loading (halfix.wasm + libhalfix.js)
 *  - chunked disk backend (disk.mjs) with IndexedDB/File API
 *  - canvas framebuffer plumbing
 *
 * WASM-only in webUI — native builds (node makefile.js) are dev-local
 * and not exposed here. This keeps the browser bundle small and respects
 * the spec's "native first, WASM second" discipline.
 */

import { chunkIndex, CHUNK_SIZE } from "./disk.mjs";

let cachedModule = null;

export class BundleMissingError extends Error {
  constructor() {
    super(
      "Halfix WASM bundle not built. Build it with:\n" +
        "  cd vendor/halfix && node makefile.js emscripten --enable-wasm release\n" +
        "  node tools/copy-halfix-artifacts.mjs\n" +
        "See vendor/halfix/docs + packages/halfix-lab/README.md"
    );
    this.name = "BundleMissingError";
  }
}

export class ImageMissingError extends Error {
  constructor(which) {
    super(
      `Halfix ${which} not loaded. Drop a file in the Halfix tool or choose a remote URL.\n` +
        "Windows 10 22H2 x86 needs a 20 GiB raw image (qemu-img create -f raw win10.img 20G)\n" +
        "plus a valid ISO (see tools/fetch-win10-iso.mjs)."
    );
    this.name = "ImageMissingError";
  }
}

/**
 * Probe whether the Halfix WASM bundle is served.
 * Checks vendor/halfix/halfix.wasm via fetch without loading it.
 */
export async function probeHalfixBundle(fetchImpl = globalThis.fetch) {
  try {
    const res = await fetchImpl("/vendor/halfix/halfix.wasm", { method: "HEAD" });
    if (res.ok) return { ok: true };
    // Fallback: try libhalfix.js
    const r2 = await fetchImpl("/vendor/halfix/libhalfix.js", { method: "HEAD" });
    if (r2.ok) return { ok: true };
    // Also try relative (for some hosting bases)
    const r3 = await fetchImpl("vendor/halfix/halfix.wasm", { method: "HEAD" });
    if (r3.ok) return { ok: true };
    return { ok: false, missing: ["halfix.wasm", "libhalfix.js"] };
  } catch (e) {
    return { ok: false, error: e.message, missing: ["halfix.wasm"] };
  }
}

/**
 * Resolve the vendored WASM glue (libhalfix.js). Lazy, cached.
 * libhalfix.js is an IIFE that registers window.Halfix, not an ES module,
 * so we must load it via <script> rather than import(). Vite cannot transform
 * files under /public (they are copied as-is), hence the previous approach
 * triggered “Failed to load url /vendor/halfix/libhalfix.js”.
 * We try <script> first, then fetch+eval fallback (for COEP/CORP blocking).
 */
export async function resolveHalfix() {
  if (cachedModule !== null) return cachedModule;
  if (typeof window !== "undefined" && window.Halfix) {
    cachedModule = { Halfix: window.Halfix };
    return cachedModule;
  }
  if (typeof document === "undefined") {
    // Node / test environment — no DOM, cannot load browser glue
    return null;
  }
  // Try <script> tag
  try {
    await new Promise((resolve, reject) => {
      const existing = document.querySelector('script[src*="libhalfix"]');
      if (existing) {
        if (window.Halfix) return resolve();
        let tries = 0;
        const iv = setInterval(() => {
          if (window.Halfix) { clearInterval(iv); resolve(); }
          else if (++tries > 100) { clearInterval(iv); reject(new Error("Halfix load timeout (existing tag)")); }
        }, 50);
        existing.addEventListener("error", () => { clearInterval(iv); reject(new Error("Failed to load libhalfix.js (existing)")); });
        return;
      }
      const s = document.createElement("script");
      s.src = "/vendor/halfix/libhalfix.js";
      s.async = true;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error("Failed to load /vendor/halfix/libhalfix.js"));
      document.head.appendChild(s);
    });
    if (window.Halfix) {
      cachedModule = { Halfix: window.Halfix };
      return cachedModule;
    }
  } catch (e) {
    console.warn("[halfix] <script> load failed:", e.message, "— trying fetch+eval fallback");
  }
  // Fallback: fetch text and eval in window context (bypasses COEP/CORP issues)
  try {
    const res = await fetch("/vendor/halfix/libhalfix.js");
    if (!res.ok) throw new Error(`fetch ${res.status}`);
    const text = await res.text();
    // Execute in global scope — libhalfix expects `global` to be window
    // eslint-disable-next-line no-new-func
    const fn = new Function("window", "global", "document", text + "\n; return typeof Halfix !== 'undefined' ? Halfix : (typeof window.Halfix !== 'undefined' ? window.Halfix : null);");
    const Halfix = fn(window, window, document);
    if (Halfix || window.Halfix) {
      cachedModule = { Halfix: Halfix || window.Halfix };
      return cachedModule;
    }
  } catch (e) {
    console.warn("[halfix] fetch+eval fallback failed:", e.message);
  }
  cachedModule = null;
  return cachedModule;
}

/**
 * Build the Halfix .conf text for a browser session.
 * Mirrors vendor/halfix/default.conf but with Windows 10–tuned defaults
 * (Bochs BIOS, 2048M RAM, APIC/ACPI/PCI on, boot order CD → HD).
 */
export function buildConf({
  ramMb = 1024,
  vgaMb = 4,
  bios = "/vendor/halfix/bios.bin",
  vgaBios = "/vendor/halfix/vgabios.bin",
  hdaFile = "win10.img",
  hdaType = "hd",
  hdaInserted = true,
  cdaFile = "win10-22h2-x86.iso",
  cdaType = "cd",
  cdaInserted = true,
  bootOrder = "cd", // cd first for install; after install switch to "hd"
  pci = true,
  apic = true,
  acpi = true,
} = {}) {
  const lines = [];
  lines.push(`bios=${bios}`);
  lines.push(`vgabios=${vgaBios}`);
  lines.push(`memory=${ramMb}M`);
  lines.push(`vgamemory=${vgaMb}M`);
  lines.push(`pci=${pci ? 1 : 0}`);
  lines.push(`apic=${apic ? 1 : 0}`);
  lines.push(`acpi=${acpi ? 1 : 0}`);
  lines.push(`pcivga=0`);
  lines.push(`now=${Date.now()}`);
  lines.push(`floppy=0`);
  lines.push(``);
  // ata0-master — hard disk
  lines.push(`[ata0-master]`);
  lines.push(`inserted=${hdaInserted ? 1 : 0}`);
  lines.push(`type=${hdaType}`);
  lines.push(`driver=normal`);
  lines.push(`file=${hdaFile}`);
  lines.push(``);
  // ata0-slave — CD-ROM (ISO)
  lines.push(`[ata0-slave]`);
  lines.push(`inserted=${cdaInserted && cdaFile ? 1 : 0}`);
  lines.push(`type=${cdaType}`);
  if (cdaFile) lines.push(`file=${cdaFile}`);
  lines.push(``);
  lines.push(`[ata1-master]`);
  lines.push(`inserted=0`);
  lines.push(`type=none`);
  lines.push(``);
  lines.push(`[ata1-slave]`);
  lines.push(`inserted=0`);
  lines.push(`type=none`);
  lines.push(``);
  lines.push(`[boot]`);
  if (bootOrder === "cd") {
    lines.push(`a=cd`);
    lines.push(`b=hd`);
    lines.push(`c=none`);
  } else {
    lines.push(`a=hd`);
    lines.push(`b=cd`);
    lines.push(`c=none`);
  }
  lines.push(``);
  // cpu quirk for NT-era limit (not needed for Win10, kept 0)
  lines.push(`[cpu]`);
  lines.push(`cpuid_limit_winnt=0`);
  lines.push(``);
  return lines.join("\n");
}

/**
 * Minimal lab-capable Halfix session (WASM).
 * This is the browser counterpart to the native `./halfix` binary.
 *
 * Usage (from halFix.js Tools page):
 *   const session = await bootHalfixSession({
 *     ramMb: 2048,
 *     canvas: document.getElementById("halfix-vga"),
 *     disk: { imageId: "win10", size: 20*GiB },
 *     isoFile: File | null,
 *     onSpeed: (mips) => ...,
 *     onLog: (line) => ...,
 *   });
 *   await session.start();
 */
export class HalfixSession {
  constructor({ ramMb = 1024, canvas = null, disk = null, hddFile = null, isoFile = null, onLog = null, onSpeed = null } = {}) {
    this.ramMb = ramMb;
    this.canvas = canvas;
    this.disk = disk;
    this.hddFile = hddFile || null;
    this.isoFile = isoFile || null;
    this.onLog = onLog || (() => {});
    this.onSpeed = onSpeed || (() => {});
    this._halfix = null;
    this._running = false;
    this._startedAt = null;
  }

  /**
   * Boot (init WASM module). Throws BundleMissingError if not built.
   * When bundle missing, caller should soft-degrade to instructions UI.
   */
  async boot() {
    const mod = await resolveHalfix();
    if (!mod) throw new BundleMissingError();

    // The actual Emscripten module is loaded via libhalfix.js which expects
    // a global Module and canvas; we delegate to Halfix class in libhalfix.js
    const Halfix = mod.Halfix || mod.default?.Halfix || globalThis.Halfix;
    if (!Halfix) throw new BundleMissingError();

    // Decide HDD backend:
    // - If hddFile is provided (user just dropped file) and no IndexedDB yet, use File backend (file!0)
    // - If disk meta exists (ingested), prefer IndexedDB (idb:<imageId>) — survives reload, no File needed
    // This fixes “no File handle in this tab after reload” by using idb: backend.
    let hdaFile, hdaIsFile = false;
    if (!this.disk) {
      hdaFile = "none";
    } else if (this.hddFile instanceof File) {
      // HDD File is available in this tab — use File backend (fastest for first boot)
      // We will pass it as hda: File via opts so libhalfix's getParameterByName pushes it to _cache
      hdaFile = null; // signal to use File via opts, not string
      hdaIsFile = true;
    } else {
      // No File handle in this tab, but disk meta exists in IndexedDB — use idb backend
      hdaFile = `idb:${this.disk.imageId}`;
    }
    // ISO is still File-based (4 GiB, user must re-drop after reload if needed; could be made idb too)
    const cdaIsFile = this.isoFile instanceof File;
    const cdaFile = cdaIsFile ? null : (this.isoFile ? this.isoFile : null); // null means use File via opts, string means idb/path
    // Build conf string for logging (actual Halfix will rebuild its own conf from opts, but we log ours)
    const conf = buildConf({
      ramMb: this.ramMb,
      hdaFile: hdaFile || (hdaIsFile ? "file:via File handle" : "none"),
      cdaFile: cdaFile || (cdaIsFile ? "file:via File handle" : null),
    });

    // Build Halfix opts — pass Files or idb: strings so libhalfix's
    // getParameterByName will handle _cache/FileImage vs IndexedDBImage.
    // Mapping (see libhalfix.js buildDrive):
    //  hda/cda → ata0-master, hdb/cdb → ata0-slave, hdc/cdc → ata1-master, hdd/cdd → ata1-slave
    // HDD (ata0-master) as HD → hda, CD (ata0-slave) as CD → cdb (not cda!)
    const opts = {
      canvas: this.canvas,
      mem: this.ramMb,
      bios: "/vendor/halfix/bios.bin",
      vgabios: "/vendor/halfix/vgabios.bin",
      // WASM glue is served at /vendor/halfix/halfix.js (copied by copy-halfix-artifacts);
      // libhalfix.js defaults to "halfix.js" at page root, so we must override.
      emulator: "/vendor/halfix/halfix.js",
      fast: 0,
      reportSpeed: (mips) => this.onSpeed(mips),
    };
    if (hdaIsFile && this.hddFile) {
      opts.hda = this.hddFile; // ata0-master HD
    } else if (hdaFile && hdaFile !== "none") {
      opts.hda = hdaFile; // e.g. "idb:halfix-win10"
    }
    if (cdaIsFile && this.isoFile) {
      opts.cdb = this.isoFile; // ata0-slave CD (drvid "b", so cdb not cda)
    } else if (cdaFile && cdaFile !== "none") {
      // cdaFile is already a string like "idb:..." or path; map to cdb
      opts.cdb = cdaFile;
    }
    // Keep _fileCache for backward compat if halfix.js set it
    if (this._fileCache && this._fileCache.length) {
      // Also expose as global fallback
      if (typeof globalThis !== "undefined") globalThis._halfix_file_cache = this._fileCache;
      // If opts.hda/cda not yet set and _fileCache has files, use them
      if (!opts.hda && this._fileCache[0] instanceof File) opts.hda = this._fileCache[0];
      if (!opts.cda && this._fileCache[1] instanceof File) opts.cda = this._fileCache[1];
      else if (!opts.cda && this._fileCache[0] instanceof File && !opts.hda) opts.cda = this._fileCache[0];
    }

    this._halfix = new Halfix(opts);
    this.onLog(`[halfix] conf:\n${conf}`);
    return this;
  }

  /** Start emulation loop */
  async start() {
    if (!this._halfix) await this.boot();
    this._running = true;
    this._startedAt = Date.now();
    return new Promise((resolve, reject) => {
      try {
        this._halfix.init((err) => {
          if (err) {
            this.onLog(`[halfix] init failed: ${err.message}`, "err");
            reject(err);
            return;
          }
          this.onLog(`[halfix] running at ${this.ramMb} MiB, MIPS ~10-30 (browser) vs 70-100 native`, "dim");
          this._halfix.run();
          resolve(this);
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  pause() {
    if (this._halfix) this._halfix.pause(true);
    this._running = false;
  }

  resume() {
    if (this._halfix) this._halfix.pause(false);
    this._running = true;
    if (this._halfix) this._halfix.run();
  }

  async destroy() {
    try {
      this._halfix?.pause(true);
    } catch {}
    this._running = false;
  }

  // For testing: expose config builder
  static buildConf = buildConf;
}

/**
 * Convenience: boot a session from high-level args (used by halFix.js)
 */
export async function bootHalfixSession(opts) {
  const s = new HalfixSession(opts);
  await s.boot();
  return s;
}

/**
 * Chunk arithmetic sanity check — used by health-check UI before boot.
 * Returns { ok, detail }.
 */
export function verifyDiskBackend() {
  const tests = [
    { off: 0, expect: 0 },
    { off: CHUNK_SIZE - 1, expect: 0 },
    { off: CHUNK_SIZE, expect: 1 },
    { off: 4 * 1024 * 1024 * 1024, expect: 16384 }, // 4 GiB / 256 KiB
    { off: 6 * 1024 * 1024 * 1024, expect: 24576 },
    { off: 16 * 1024 * 1024 * 1024, expect: 65536 },
    { off: 20 * 1024 * 1024 * 1024, expect: 81920 },
  ];
  for (const t of tests) {
    const got = chunkIndex(t.off);
    if (got !== t.expect) {
      return { ok: false, detail: `chunkIndex(${t.off}) = ${got}, expected ${t.expect}` };
    }
    // 32-bit buggy version should fail beyond 4 GiB
    const buggy = (t.off / CHUNK_SIZE) | 0;
    if (t.off >= 4 * 1024 * 1024 * 1024 && buggy === t.expect) {
      // if buggy matches, our test expectation is wrong — shouldn't happen
    }
  }
  return { ok: true, detail: "chunk indexing OK (Number-safe, >4 GiB)" };
}
