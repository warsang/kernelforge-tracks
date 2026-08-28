/**
 * Headless boot test: real bzImage through v86 in Node, waiting for a shell
 * prompt over the serial console. This is the exact path the browser lab
 * uses; if it works here, the track is live.
 */
import { readFile } from "fs/promises";
import path from "path";
import { resolveV86 } from "../src/session.mjs";

const pkg = process.cwd();
const bundle = await resolveV86();
if (!bundle?.V86) { console.error("no bundle"); process.exit(1); }

const bz = await readFile(path.join(pkg, "artifacts/bzImage"));
const initrd = await readFile(path.join(pkg, "artifacts/rootfs.cpio"));
console.log(`bzImage: ${bz.length} bytes, initrd: ${initrd.length} bytes`);

let out = "";
const emu = await new bundle.V86({
  bios: { buffer: (await readFile(path.join(pkg, "vendor/seabios.bin"))).buffer },
  vga_bios: { buffer: (await readFile(path.join(pkg, "vendor/vgabios.bin"))).buffer },
  bzimage: { buffer: bz.buffer.slice(bz.byteOffset, bz.byteOffset + bz.byteLength) },
  initrd: { buffer: initrd.buffer.slice(initrd.byteOffset, initrd.byteOffset + initrd.byteLength) },
  cmdline: "console=ttyS0 tsc=reliable noapic root=/dev/ram0 rw init=/sbin/init",
  memory_size: 256 * 1024 * 1024, // 256MB — enough for kernel + initrd
  uart1: true,
  autostart: true,
  wasm_path: path.join(pkg, "vendor/v86.wasm"),
  disable_keyboard: true,
  disable_mouse: true,
  disable_speaker: true,
});
emu.add_listener("serial0-output-byte", (b) => {
  out += String.fromCharCode(b);
  process.stdout.write(String.fromCharCode(b));
});

// wait for login prompt, then send root (buildroot auto-logs in)
const t0 = Date.now();
while (!/login:/.test(out.slice(-200))) {
  if (Date.now() - t0 > 180_000) {
    console.error("\nTIMEOUT waiting for login prompt");
    emu.destroy();
    process.exit(1);
  }
  await new Promise((r) => setTimeout(r, 500));
}
console.log("\n=== LOGIN PROMPT DETECTED, sending root ===");
out = "";
emu.serial0_send("root\n");
await new Promise((r) => setTimeout(r, 3000));
console.log("--- after login ---");
console.log(out.slice(-300));
emu.destroy();
process.exit(0);
