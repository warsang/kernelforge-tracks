#!/usr/bin/env node
/**
 * KERNELFORGE dev/serve server:
 *  - static files from apps/web + workspace sources (for import maps)
 *  - POST /api/compile {source} -> clang x64 COFF object (base64)
 *    [dev bridge; production swaps in browsercc WASM client-side]
 */

import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";

const execFileP = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const WEB = path.join(ROOT, "apps/web");
const PORT = process.env.PORT ?? 8080;

const MIME = {
  ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript",
  ".css": "text/css", ".json": "application/json", ".wasm": "application/wasm",
  ".png": "image/png", ".svg": "image/svg+xml",
};

// routes /packages/<pkg>/src/... -> workspace sources (import map support)
function resolveStatic(urlPath) {
  if (urlPath.startsWith("/packages/")) {
    return path.join(ROOT, urlPath.slice(1));
  }
  if (urlPath.startsWith("/assets/vergilius/")) {
    return path.join(ROOT, "packages/ntsim-assets/data", urlPath.replace("/assets/", ""));
  }
  const rel = urlPath === "/" ? "/index.html" : urlPath;
  return path.join(WEB, rel);
}

async function handleCompile(req, res) {
  let body = "";
  for await (const chunk of req) body += chunk;
  let source;
  try {
    source = JSON.parse(body).source;
  } catch {
    res.writeHead(400).end("bad json");
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), "kf-compile-"));
  try {
    const cFile = path.join(dir, "driver.c");
    const oFile = path.join(dir, "driver.obj");
    await writeFile(cFile, source);
    try {
      await execFileP("clang", [
        "--target=x86_64-pc-windows-msvc",
        "-O1", "-ffreestanding", "-fno-stack-protector",
        "-c", cFile, "-o", oFile,
      ], { timeout: 15000 });
    } catch (e) {
      res.writeHead(422, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: e.stderr || e.message }));
      return;
    }
    const obj = await readFile(oFile);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ objBase64: obj.toString("base64") }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === "/api/compile" && req.method === "POST") {
    await handleCompile(req, res);
    return;
  }
  try {
    const file = resolveStatic(decodeURIComponent(url.pathname));
    if (!file.startsWith(ROOT)) throw new Error("traversal");
    const data = await readFile(file);
    res.writeHead(200, {
      "content-type": MIME[path.extname(file)] ?? "application/octet-stream",
      // COOP/COEP for future SharedArrayBuffer use:
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp",
    });
    res.end(data);
  } catch {
    res.writeHead(404).end("not found");
  }
});

server.listen(PORT, () => {
  console.log(`KERNELFORGE serving on http://localhost:${PORT}`);
});
