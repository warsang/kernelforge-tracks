#!/usr/bin/env node
/**
 * save-boot-state.mjs — boot the guest once headless, snapshot v86 state.
 *
 * Produces vendor/artifacts/boot-state.bin so student sessions restore in
 * seconds instead of waiting for the full kernel boot. Run after
 * build-buildroot.sh:
 *
 *   node scripts/save-boot-state.mjs
 *
 * Uses Node 22+ (v86 runs in Node via its fs backend).
 */

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = path.join(here, "..");

async function main() {
  const bundle = await import(path.join(pkg, "vendor/v86-bundle-lib.js"));
  const bzImage = await readFile(path.join(pkg, "artifacts/bzImage"));
  console.log(`[save-boot-state] bzImage ${bzImage.length} bytes; booting...`);

  let serialText = "";
  const emulator = await bundle.V86({
    bios: { buffer: (await readFile(path.join(pkg, "vendor/seabios.bin"))).buffer },
    vga_bios: { buffer: (await readFile(path.join(pkg, "vendor/vgabios.bin"))).buffer },
    bzimage: { buffer: bzImage.buffer.slice(bzImage.byteOffset, bzImage.byteOffset + bzImage.byteLength) },
    cmdline: "console=ttyS0 tsc=reliable",
    uart1: true,
    autostart: true,
    wasm_path: path.join(pkg, "vendor/v86.wasm"),
    disable_keyboard: true,
    disable_mouse: true,
  });

  emulator.add_listener("serial0-output-byte", (byte) => {
    serialText += String.fromCharCode(byte);
    process.stdout.write(String.fromCharCode(byte));
  });

  // Wait for the shell prompt marker emitted by the lab overlay init.
  const waitFor = async (marker, timeoutMs) => {
    const t0 = Date.now();
    while (!serialText.includes(marker)) {
      if (Date.now() - t0 > timeoutMs) throw new Error(`timeout waiting for "${marker}"`);
      await new Promise((r) => setTimeout(r, 500));
    }
  };
  await waitFor("~#", 10 * 60_000);

  // quiesce then snapshot
  await new Promise((r) => setTimeout(r, 2000));
  const state = emulator.save_state();
  const out = path.join(pkg, "artifacts/boot-state.bin");
  await writeFile(out, Buffer.from(await state));
  console.log(`\n[save-boot-state] wrote ${out}`);
  emulator.destroy();
}

main().catch((e) => { console.error(e); process.exit(1); });
