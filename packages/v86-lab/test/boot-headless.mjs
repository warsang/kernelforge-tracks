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
console.log(`bzImage: ${bz.length} bytes`);

let out = "";
const emu = await new bundle.V86({
  bios: { buffer: (await readFile(path.join(pkg, "vendor/seabios.bin"))).buffer },
  vga_bios: { buffer: (await readFile(path.join(pkg, "vendor/vgabios.bin"))).buffer },
  bzimage: { buffer: bz.buffer.slice(bz.byteOffset, bz.byteOffset + bz.byteLength) },
  cmdline: "console=ttyS0 tsc=reliable",
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

// wait for login/shell prompt (buildroot auto-logs in as root on console)
const t0 = Date.now();
while (!/(~ #|\(none\) login:)/.test(out.slice(-200))) {
  if (Date.now() - t0 > 180_000) {
    console.error("\nTIMEOUT waiting for prompt");
    emu.destroy();
    process.exit(1);
  }
  await new Promise((r) => setTimeout(r, 500));
}
console.log("\n=== BOOT OK, sending probe ===");
out = "";
emu.serial0_send("uname -a && cat /proc/version\n");
await new Promise((r) => setTimeout(r, 3000));
const tail = out.split("\n").filter((l) => l.includes("Linux version") || l.includes("(none)")).slice(0, 3);
console.log(tail.join("\n"));
emu.destroy();
process.exit(tail.length ? 0 : 2);
