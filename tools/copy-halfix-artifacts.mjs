#!/usr/bin/env node
/**
 * copy-halfix-artifacts.mjs — static-site pipeline for the Halfix track
 *
 * Mirrors tools/copy-v86-artifacts.mjs but for Halfix:
 *   vendor/halfix/{bios.bin,vgabios.bin,libhalfix.js,halfix.js,halfix.wasm,runtime.js,*files.json}
 * → apps/web/public/vendor/halfix/*
 * → apps/web/dist/vendor/halfix/*   (post-build)
 *
 * Build Halfix first (Phase 7):
 *   cd vendor/halfix && node makefile.js emscripten --enable-wasm release
 *
 * Then run this script (or `npm run build --workspace @kernelforge/web` which calls it).
 * Idempotent: missing source files only warn.
 */

import { cp, mkdir, stat, readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");

// Halfix vendor layout (git submodule at vendor/halfix)
const HALFIX_SRC = path.join(repo, "vendor/halfix");
// Fallback: if someone builds Halfix inside packages/halfix-lab/vendor
const HALFIX_SRC_ALT = path.join(repo, "packages/halfix-lab/vendor/halfix");

const DST = path.join(repo, "apps/web/public/vendor/halfix");
const DIST = path.join(repo, "apps/web/dist/vendor/halfix");

// Core files that must be served for the WASM tool to work
const CORE_FILES = [
  "bios.bin",
  "vgabios.bin",
  "libhalfix.js",
  "runtime.js",
  "index.html", // reference, not strictly needed
];

// WASM outputs (produced by `node makefile.js emscripten --enable-wasm release`)
const WASM_FILES = [
  "halfix.js",
  "halfix.wasm",
  "halfix.wasm.map",
];

// Optional but useful for debugging
const EXTRA_FILES = [
  "bios.bin.gz", // not used but present in some builds
  "default.conf",
];

async function resolveSrc() {
  try {
    await stat(path.join(HALFIX_SRC, "bios.bin"));
    return HALFIX_SRC;
  } catch {}
  try {
    await stat(path.join(HALFIX_SRC_ALT, "bios.bin"));
    return HALFIX_SRC_ALT;
  } catch {}
  return HALFIX_SRC; // default for warn messages
}

async function sha12(p) {
  try {
    const buf = await readFile(p);
    return createHash("sha256").update(buf).digest("hex").slice(0, 12);
  } catch {
    return null;
  }
}

async function ensureDir(d) {
  await mkdir(d, { recursive: true });
}

async function copyIfExists(name, srcDir) {
  const src = path.join(srcDir, name);
  const dst = path.join(DST, name);
  const dist = path.join(DIST, name);
  try {
    await stat(src);
  } catch {
    return false; // not found — caller will warn if CORE_FILE
  }
  await ensureDir(DST);
  await cp(src, dst);
  const hash = await sha12(dst);
  const st = await stat(dst);
  const rel = path.relative(repo, dst);
  console.log(`[copy-halfix] ${name} → ${rel}  ${(st.size / 1024).toFixed(1)} KiB  sha256:${hash}`);
  try {
    await stat(path.dirname(DIST));
    await ensureDir(DIST);
    await cp(src, dist);
  } catch {}
  return true;
}

const srcDir = await resolveSrc();
let ok = 0;
let missingCore = [];

for (const f of CORE_FILES) {
  const found = await copyIfExists(f, srcDir);
  if (found) ok++;
  else missingCore.push(f);
}

let wasmOk = 0;
for (const f of WASM_FILES) {
  const found = await copyIfExists(f, srcDir);
  if (found) { ok++; wasmOk++; }
  // also check build/ folder (some makefile.js versions emit to build/)
  if (!found) {
    const alt = path.join(srcDir, "build", f);
    try {
      await stat(alt);
      await ensureDir(DST);
      await cp(alt, path.join(DST, f));
      const hash = await sha12(path.join(DST, f));
      const st = await stat(path.join(DST, f));
      console.log(`[copy-halfix] ${f} (from build/) → public/vendor/halfix/${f}  ${(st.size / 1024).toFixed(1)} KiB  sha256:${hash}`);
      try { await ensureDir(DIST); await cp(alt, path.join(DIST, f)); } catch {}
      ok++; wasmOk++;
    } catch {}
  }
}

for (const f of EXTRA_FILES) {
  await copyIfExists(f, srcDir);
}

// Also copy docs/rombios.patch reference for Phase 6 patch review
try {
  const patchSrc = path.join(srcDir, "docs/rombios.patch");
  await stat(patchSrc);
  await ensureDir(DST);
  await cp(patchSrc, path.join(DST, "rombios.patch"));
} catch {}

if (missingCore.length) {
  console.warn(`[copy-halfix] missing core files: ${missingCore.join(", ")} — expected at ${srcDir}`);
  console.warn("  If you haven't cloned Halfix yet: git submodule update --init vendor/halfix");
}

if (wasmOk === 0) {
  console.warn("[copy-halfix] WASM not built — Halfix tool will show 'WASM bundle not built' with instructions.");
  console.warn("  Build it: cd vendor/halfix && node makefile.js emscripten --enable-wasm release");
  console.warn("  Then re-run: node tools/copy-halfix-artifacts.mjs");
} else {
  console.log(`[copy-halfix] WASM present (${wasmOk}/${WASM_FILES.length} files) — browser tool can boot.`);
}

if (ok > 0) {
  console.log(`[copy-halfix] done (${ok} files). Fetch from same origin: fetch("vendor/halfix/halfix.wasm")`);
} else {
  console.warn("[copy-halfix] no files copied — check vendor/halfix exists and is built.");
}
