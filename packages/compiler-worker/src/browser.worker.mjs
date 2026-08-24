/**
 * Browser-side compiler worker: wraps the browsercc fork (clang/lld in WASM)
 * behind the exact interface apps/web uses today for server compiles.
 *
 * Interface parity with POST /api/compile:
 *   input:  { source: string }
 *   output: { objBase64: string }          (x64 COFF object, real clang bytes)
 *
 * The worker owns its clang instance (reused across jobs) inside a
 * DedicatedWorkerGlobalScope; the main thread talks to it via transferable
 * messages. Falls back to reporting upstream stderr verbatim on errors.
 */

/// <reference lib="webworker" />

let clangMod = null;
let lldMod = null;

const SYSROOT_URL = new URL("../../vendor/browsercc/dist/sysroot.tar", import.meta.url);

async function getModules() {
  if (!clangMod || !lldMod) {
    const [{ default: Clang }, { default: LLD }] = await Promise.all([
      import(/* webpackIgnore: true */ "../../vendor/browsercc/dist/clang.js"),
      import(/* webpackIgnore: true */ "../../vendor/browsercc/dist/lld.js"),
    ]);
    let stderr = "";
    clangMod = await Clang({
      thisProgram: "clang",
      printErr: (s) => { stderr += s + "\n"; },
    });
    lldMod = await LLD({ thisProgram: "ld.lld", printErr: () => {} });
    void stderr;
  }
  return { clangMod, lldMod };
}

async function loadSysrootInto(mod) {
  const tarBuf = await (await fetch(SYSROOT_URL)).arrayBuffer();
  const dec = new TextDecoder();
  const u8 = new Uint8Array(tarBuf);
  let off = 0;
  while (off + 512 <= u8.length) {
    const hdr = u8.slice(off, off + 512);
    const name = dec.decode(hdr.slice(0, 100)).replace(/\0.*$/, "");
    if (!name) break;
    const size = parseInt(dec.decode(hdr.slice(124, 136)).replace(/\0.*$/, "").trim(), 8) || 0;
    const contentStart = off + 512;
    if (size > 0 && !name.endsWith("/")) {
      const dir = name.split("/").slice(0, -1).join("/");
      if (dir && !mod.FS.analyzePath(dir).exists) mod.FS.mkdirTree(dir);
      mod.FS.writeFile(name, u8.slice(contentStart, contentStart + size));
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
}

/** Compile C source -> x64 COFF object bytes (real clang, in-browser). */
async function compileToObj(source) {
  const { clangMod: clang } = await getModules();
  const inName = "/work/driver.c";
  const outName = "/work/driver.obj";
  try {
    clang.FS.mkdirTree("/work");
    clang.FS.writeFile(inName, source);
    const code = clang.callMain([
      "--target=x86_64-pc-windows-msvc",
      "-O1", "-ffreestanding", "-fno-stack-protector",
      "-c", inName, "-o", outName,
    ]);
    if (code !== 0) return { ok: false, error: "compilation failed (see stderr)" };
    const obj = clang.FS.readFile(outName, { encoding: "binary" });
    return { ok: true, obj };
  } catch (e) {
    return { ok: false, error: String(e?.message ?? e) };
  }
}

self.onmessage = async (ev) => {
  const { id, op, payload } = ev.data ?? {};
  try {
    if (op === "compile") {
      const res = await compileToObj(payload.source);
      if (!res.ok) {
        self.postMessage({ id, ok: false, error: res.error });
        return;
      }
      // transfer as plain Array (structured clone of typed array is fine)
      self.postMessage({ id, ok: true, objBytes: res.obj });
    } else if (op === "warmup") {
      await getModules();
      self.postMessage({ id, ok: true });
    }
  } catch (e) {
    self.postMessage({ id, ok: false, error: String(e?.message ?? e) });
  }
};
