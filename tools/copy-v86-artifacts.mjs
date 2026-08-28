#!/usr/bin/env node
/**
 * copy-v86-artifacts.mjs — static-site pipeline for the v86 track.
 *
 * Copies the buildroot guest image from its build location
 *   packages/v86-lab/artifacts/{bzImage,rootfs.cpio,boot-state.bin}
 * to the app's public dir so `vite dev` and `vite build` serve it as a
 * static asset under the same origin:
 *   apps/web/public/vendor/artifacts/{bzImage,rootfs.cpio}
 *
 * This mirrors how copy.sh/v86 serves `images/linux.iso` — no server code,
 * just `fetch("vendor/artifacts/bzImage").arrayBuffer()`. Without this step
 * a Pages deploy 404s with ImageMissingError.
 *
 * Idempotent: missing source files only warn (CI may not have run
 * build-buildroot.sh yet); existing files are overwritten.
 * SHA256 is logged so deploys can verify the guest version.
 */
import { cp, mkdir, stat, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");
const srcDir = path.join(repo, "packages/v86-lab/artifacts");
const dstDir = path.join(repo, "apps/web/public/vendor/artifacts");
const distDir = path.join(repo, "apps/web/dist/vendor/artifacts");
const FILES = ["bzImage", "rootfs.cpio", "boot-state.bin"];

// also mirror the v86 vendor files and browsercc wasm so `public/vendor`
// is self-contained even though `apps/web/public/vendor` is no longer a
// symlink to `packages/v86-lab/vendor` (see .gitignore).
const V86_VENDOR_SRC = path.join(repo, "packages/v86-lab/vendor");
const V86_VENDOR_DST = path.join(repo, "apps/web/public/vendor");
const BROWSERCC_SRC = path.join(repo, "vendor/browsercc/dist");
const BROWSERCC_DST = path.join(repo, "apps/web/public/vendor/browsercc/dist");
const BROWSERCC_DIST_DST = path.join(repo, "apps/web/dist/vendor/browsercc/dist");

async function sha256(p) {
  try {
    const buf = await readFile(p);
    return createHash("sha256").update(buf).digest("hex").slice(0, 12);
  } catch {
    return null;
  }
}

async function copyOne(name) {
  const src = path.join(srcDir, name);
  const dst = path.join(dstDir, name);
  try {
    await stat(src);
  } catch {
    console.warn(`[copy-v86-artifacts] skip ${name}: not found at ${src}`);
    console.warn(`  build it with: ./packages/v86-lab/scripts/build-buildroot.sh`);
    return false;
  }
  await mkdir(dstDir, { recursive: true });
  await cp(src, dst);
  const hash = await sha256(dst);
  const st = await stat(dst);
  console.log(`[copy-v86-artifacts] ${name} -> ${path.relative(repo, dst)}  ${(st.size/1048576).toFixed(1)} MB  sha256:${hash}`);
  // also mirror into dist if it already exists (post-vite build hook)
  try {
    await stat(path.dirname(distDir));
    await mkdir(distDir, { recursive: true });
    await cp(src, path.join(distDir, name));
    console.log(`[copy-v86-artifacts] mirrored to ${path.relative(repo, path.join(distDir, name))}`);
  } catch {}
  return true;
}

let ok = 0;
for (const f of FILES) if (await copyOne(f)) ok++;

// mirror v86 vendor files (seabios, vgabios, v86.wasm, bundle) if public/vendor is a real dir
try {
  await mkdir(V86_VENDOR_DST, { recursive: true });
  for (const name of ["seabios.bin", "vgabios.bin", "v86.wasm", "v86-bundle-lib.js"]) {
    try { await cp(path.join(V86_VENDOR_SRC, name), path.join(V86_VENDOR_DST, name)); } catch {}
    try {
      await mkdir(path.join(repo, "apps/web/dist/vendor"), { recursive: true });
      await cp(path.join(V86_VENDOR_SRC, name), path.join(repo, "apps/web/dist/vendor", name));
    } catch {}
  }
} catch {}

// mirror browsercc dist (clang.js, lld.js, headers-manifest.json etc.)
try {
  await mkdir(BROWSERCC_DST, { recursive: true });
  await mkdir(BROWSERCC_DIST_DST, { recursive: true });
  let copied = 0;
  for (const name of ["clang.js", "lld.js", "headers-manifest.json", "linux-headers-manifest.json"]) {
    try { await cp(path.join(BROWSERCC_SRC, name), path.join(BROWSERCC_DST, name)); copied++; } catch {}
    try { await cp(path.join(BROWSERCC_SRC, name), path.join(BROWSERCC_DIST_DST, name)); } catch {}
  }
  if (copied) console.log(`[copy-v86-artifacts] browsercc ${copied} files -> public/vendor/browsercc/dist + dist/vendor/browsercc/dist`);
} catch {}

if (ok === 0) {
  console.warn("[copy-v86-artifacts] no artifacts copied — v86 labs will show ImageMissingError until the image is built.");
  console.warn("  This is expected on CI without a Linux builder; the rest of the site still builds.");
} else {
  console.log(`[copy-v86-artifacts] done (${ok}/${FILES.length} files). The site is now self-contained (fetch vendor/artifacts/* from the same origin, like copy.sh/v86).`);
}
