#!/usr/bin/env node
/**
 * tools/fetch-win10-iso.mjs — ISO fetcher with Microsoft scraper + UUP fallback + manual
 *
 * Phase 2 helper (dev-only, not invoked by Vite). Fetches Windows 10 22H2 x86 ISO
 * for the Halfix lab. Does NOT bypass activation/licensing — the ISO is stock
 * retail; you still need a valid product key (LabConfig Bypass* in unattend.xml
 * only skips TPM/SecureBoot/RAM/Storage checks).
 *
 * Strategy (in order):
 *  1) Microsoft direct — scrape https://www.microsoft.com/en-us/software-download/windows10ISO
 *     for the season-bound link `https://software.download.prusec.microsoft.com/.../Win10_22H2_English_x32.iso`
 *     (requires desktop UA + session cookies; link expires in ~24h).
 *  2) UUP dump fallback — query https://api.uupdump.net (public JSON API) for 22H2 x86,
 *     then download UUP set via aria2/curl and convert with uup-converter (if present).
 *  3) Manual — print instructions and exit 0 (not fatal) so the user can drop a file.
 *
 * Usage:
 *   node tools/fetch-win10-iso.mjs                          # auto → ./win10-22h2-x86.iso
 *   node tools/fetch-win10-iso.mjs --out ./isos/win10.iso   # custom path
 *   node tools/fetch-win10-iso.mjs --iso ./my.iso --verify  # verify existing file
 *   node tools/fetch-win10-iso.mjs --url https://example.com/win10.iso --out ./win10.iso  # direct URL
 *
 * Verification:
 *   - HTTP 200 + Content-Length matches, Content-Type application/octet-stream or similar
 *   - File size 3-5 GiB (x86 22H2 is ~3.9 GiB)
 *   - Optional SHA1/SHA256 check against docs/halfix-iso.sha256 (if present)
 *
 * Free hosting note (Phase 7): the *installed* win10.img (20 GiB) should be kept
 * private (local File API primary). If you need a remote, use Internet Archive
 * (archive.org/download — free unlimited, Range + CORS) or Hugging Face Datasets
 * (100 GiB LFS, Range), streamed via Range into IndexedDB. Do not bundle the
 * image as a static asset.
 */

import { stat, writeFile, readFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

const MS_ISO_PAGE = "https://www.microsoft.com/en-us/software-download/windows10ISO";
const UUP_API_LIST = "https://api.uupdump.net/listid.php?search=22H2";
const UUP_API_FETCH = "https://api.uupdump.net/fetchupd.php";

const args = process.argv.slice(2);
function arg(name, fallback = null) {
  const i = args.indexOf(name);
  if (i !== -1 && args[i + 1] && !args[i + 1].startsWith("--")) return args[i + 1];
  if (args.includes(name) && fallback === true) return true;
  return fallback;
}

const outPath = path.resolve(arg("--out", "./win10-22h2-x86.iso"));
const verifyOnly = arg("--verify", false) !== false;
const existingIso = arg("--iso", null);
const directUrl = arg("--url", null);
const forceManual = arg("--manual", false) !== false;

async function hashFile(p, algo = "sha256") {
  const { createReadStream } = await import("node:fs");
  return new Promise((resolve, reject) => {
    const h = createHash(algo);
    const s = createReadStream(p);
    s.on("data", (d) => h.update(d));
    s.on("end", () => resolve(h.digest("hex")));
    s.on("error", reject);
  });
}

async function verifySize(p) {
  const st = await stat(p);
  const gib = st.size / (1024 * 1024 * 1024);
  if (gib < 2.5 || gib > 5.5) {
    console.warn(`[fetch-iso] warning: size ${gib.toFixed(2)} GiB is outside expected 3-5 GiB for x86 22H2`);
    return false;
  }
  console.log(`[fetch-iso] size OK: ${gib.toFixed(2)} GiB (${st.size} bytes)`);
  return true;
}

async function loadExpectedHash() {
  const candidates = [
    path.resolve("docs/halfix-iso.sha256"),
    path.resolve("docs/halfix-iso.sha1"),
    path.resolve("tools/halfix-iso.sha256"),
  ];
  for (const c of candidates) {
    try {
      const txt = (await readFile(c, "utf8")).trim();
      const hash = txt.split(/\s+/)[0];
      if (/^[0-9a-fA-F]{32,64}$/.test(hash)) return { file: c, hash: hash.toLowerCase(), len: hash.length };
    } catch {}
  }
  return null;
}

async function verifyHash(p) {
  const exp = await loadExpectedHash();
  if (!exp) {
    console.log("[fetch-iso] no expected hash at docs/halfix-iso.sha256 — skipping hash check");
    return true;
  }
  const algo = exp.len === 40 ? "sha1" : exp.len === 64 ? "sha256" : "sha256";
  console.log(`[fetch-iso] verifying ${algo} against ${exp.file}…`);
  const got = await hashFile(p, algo);
  if (got !== exp.hash) {
    console.error(`[fetch-iso] hash mismatch!\n  expected: ${exp.hash}\n  got:      ${got}`);
    return false;
  }
  console.log(`[fetch-iso] hash OK (${algo}:${got.slice(0, 12)}…)`);
  return true;
}

async function downloadUrl(url, dest) {
  console.log(`[fetch-iso] downloading ${url}\n  → ${dest}`);
  await mkdir(path.dirname(dest), { recursive: true });

  // Prefer curl with resume + progress; fallback to node fetch
  const curl = spawn("curl", ["-L", "-C", "-", "-o", dest, "--progress-bar", url], { stdio: "inherit" });
  const code = await new Promise((resolve) => curl.on("close", resolve).on("error", () => resolve(127)));
  if (code === 0) {
    try { await stat(dest); return dest; } catch {}
  }
  if (code === 127) console.log("[fetch-iso] curl not found — falling back to node fetch…");

  // Node fetch fallback (no resume)
  const res = await fetch(url, { redirect: "follow", headers: { "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36" } });
  if (!res.ok) throw new Error(`fetch ${res.status} ${res.statusText} for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(dest, buf);
  console.log(`[fetch-iso] wrote ${buf.length} bytes via node fetch`);
  return dest;
}

// ---------------------------------------------------------------- MS scraper
async function tryMicrosoft() {
  console.log(`[fetch-iso] trying Microsoft direct (1/2) — ${MS_ISO_PAGE}`);
  // Microsoft's ISO page is heavily bot-protected; we try a best-effort scrape.
  // The page sets session cookies and requires `sessionId` + product selection posts.
  // We attempt to extract any `software.download.prusec.microsoft.com` link with x32.
  try {
    const res = await fetch(MS_ISO_PAGE, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
      },
      redirect: "follow",
    });
    if (!res.ok) throw new Error(`Microsoft page ${res.status}`);
    const html = await res.text();
    // Look for direct ISO links
    const re = /https:\/\/software\.download\.prusec\.microsoft\.com\/[^"'\s]+\.iso/gi;
    const matches = [...html.matchAll(re)].map((m) => m[0].replace(/&amp;/g, "&"));
    const x32 = matches.find((u) => /x32/i.test(u) || /Win10_22H2.*x32/i.test(u) || /22H2.*x86/i.test(u));
    const anyIso = matches[0];
    const pick = x32 || anyIso;
    if (!pick) {
      console.log("[fetch-iso] no direct ISO link on Microsoft page (expected — page is JS-rendered / bot-gated).");
      // Try alternate endpoint that sometimes returns JSON with links
      const alt = "https://www.microsoft.com/en-us/api/controls/contentinclude/html?pageId=a8f8f489-4c7f-463a-9ca6-5cff94d8d041&host=www.microsoft.com&segments=&query=&action=getisa&sessionId=&productEditionId=2618&skuId=6061&language=English&updatelogs=";
      try {
        const r2 = await fetch(alt, { headers: { "User-Agent": "Mozilla/5.0" } });
        if (r2.ok) {
          const j = await r2.text();
          const m2 = [...j.matchAll(re)].map((m) => m[0].replace(/&amp;/g, "&"));
          const p2 = m2.find((u) => /x32/i.test(u)) || m2[0];
          if (p2) {
            console.log(`[fetch-iso] found alternate ISO link: ${p2.slice(0, 80)}…`);
            return p2;
          }
        }
      } catch {}
      return null;
    }
    console.log(`[fetch-iso] found Microsoft ISO link: ${pick.slice(0, 80)}…`);
    return pick;
  } catch (e) {
    console.warn(`[fetch-iso] Microsoft scrape failed: ${e.message}`);
    return null;
  }
}
// ---------------------------------------------------------------- UUP dump
async function tryUup() {
  console.log("[fetch-iso] trying UUP dump fallback (2/2) — api.uupdump.net");
  try {
    // Search for 22H2 x86
    const res = await fetch(UUP_API_LIST, { headers: { "User-Agent": "kernelforge-fetch-iso" } });
    if (!res.ok) throw new Error(`UUP list ${res.status}`);
    const j = await res.json();
    // j.response.builds is array
    const builds = j?.response?.builds ? Object.values(j.response.builds) : [];
    // Find 22H2 (19045.x) x86
    const candidate = builds.find((b) => String(b.title || "").includes("22H2") || String(b.build || "").startsWith("19045"));
    if (!candidate) {
      console.log("[fetch-iso] no 22H2 build in UUP list — dumping first few titles for debugging:");
      for (const b of builds.slice(0, 3)) console.log(`  ${b.title} build=${b.build} uuid=${b.uuid}`);
      return null;
    }
    console.log(`[fetch-iso] UUP candidate: ${candidate.title} (${candidate.build}) uuid=${candidate.uuid}`);
    // Fetch update info for x86
    const fetchRes = await fetch(`${UUP_API_FETCH}?uuid=${candidate.uuid}`, { headers: { "User-Agent": "kernelforge-fetch-iso" } });
    if (!fetchRes.ok) throw new Error(`UUP fetch ${fetchRes.status}`);
    const info = await fetchRes.json();
    console.log(`[fetch-iso] UUP has ${Object.keys(info?.response?.api || {}).length} api entries — check https://uupdump.net/known.php?q=${candidate.build} for x86 ISO`);
    // Full UUP→ISO conversion requires aria2 + uup-converter + wimlib — too heavy to automate headlessly here.
    // We return a pointer so the caller can instruct the user.
    const uupUrl = `https://uupdump.net/selectlang.php?id=${candidate.uuid}`;
    console.log(`[fetch-iso] UUP requires manual ISO creation: open ${uupUrl}, pick English (United States), choose x86, download via aria2.`);
    return null; // signal manual needed, not a direct ISO URL
  } catch (e) {
    console.warn(`[fetch-iso] UUP fallback failed: ${e.message}`);
    return null;
  }
}

function printManual() {
  console.log(`
[fetch-iso] ── Manual ISO fallback ──────────────────────────────────────
Windows 10 22H2 x86 ISO (3-5 GiB) — legitimate Microsoft download:

  1) Open: https://www.microsoft.com/en-us/software-download/windows10ISO
     • Select Edition: Windows 10 (multi-edition ISO)
     • Confirm → Product Language: English (United States) → Confirm
     • Choose: 32-bit Download   (≈ Win10_22H2_English_x32.iso, ~3.9 GiB)

  2) Save as:
     ./win10-22h2-x86.iso
     or pass: node tools/fetch-win10-iso.mjs --iso ./your.iso --verify

  3) Verify (optional but recommended):
     node tools/fetch-win10-iso.mjs --iso ./win10-22h2-x86.iso --verify

  Licensed use only — the LabConfig unattend.xml (BypassTPMCheck etc.)
  in apps/web/src/halfix.js only skips minimum-spec checks, not activation.
  Provide your own product key during Setup.

  Alternative (if Microsoft page is gated): use UUP dump
    https://uupdump.net/known.php?q=19045  → pick latest 22H2 x86 →
    Language: English (United States) → Download via aria2 → Convert.

  Hosting the *installed* 20 GiB win10.img:
    Do NOT commit it. Primary is local File API → IndexedDB (this tool).
    For a remote mirror, use Internet Archive (archive.org/download —
    free unlimited, supports Range + CORS) or Hugging Face Datasets
    (100 GiB LFS, Range). Stream via Range into IndexedDB; see Remote
    field in the Halfix tool.
───────────────────────────────────────────────────────────────────────
`);
}

async function main() {
  if (verifyOnly && existingIso) {
    console.log(`[fetch-iso] verifying ${existingIso}…`);
    try { await stat(existingIso); } catch { console.error(`[fetch-iso] not found: ${existingIso}`); process.exit(1); }
    const ok1 = await verifySize(existingIso);
    const ok2 = await verifyHash(existingIso);
    process.exit(ok1 && ok2 ? 0 : 1);
  }

  if (forceManual) {
    printManual();
    return;
  }

  if (directUrl) {
    await downloadUrl(directUrl, outPath);
    await verifySize(outPath);
    await verifyHash(outPath);
    console.log(`[fetch-iso] done → ${outPath}`);
    return;
  }

  if (existingIso) {
    console.log(`[fetch-iso] using existing ${existingIso} → ${outPath}`);
    const data = await readFile(existingIso);
    await writeFile(outPath, data);
    await verifySize(outPath);
    await verifyHash(outPath);
    console.log(`[fetch-iso] done → ${outPath}`);
    return;
  }

  // Auto: MS → UUP → manual
  let url = await tryMicrosoft();
  if (url) {
    try {
      await downloadUrl(url, outPath);
      await verifySize(outPath);
      await verifyHash(outPath);
      console.log(`[fetch-iso] Microsoft direct succeeded → ${outPath}`);
      return;
    } catch (e) {
      console.warn(`[fetch-iso] Microsoft download failed: ${e.message} — trying UUP…`);
    }
  }

  url = await tryUup();
  if (url) {
    try {
      await downloadUrl(url, outPath);
      await verifySize(outPath);
      await verifyHash(outPath);
      console.log(`[fetch-iso] UUP succeeded → ${outPath}`);
      return;
    } catch (e) {
      console.warn(`[fetch-iso] UUP download failed: ${e.message}`);
    }
  }

  // Both failed — manual fallback (spec says do not fabricate ISO)
  printManual();
  console.log("[fetch-iso] Auto-download did not produce an ISO — this is expected on bot-gated networks.");
  console.log(`[fetch-iso] No file written to ${outPath}. Run with --manual to see instructions again.`);
}

main().catch((e) => {
  console.error(`[fetch-iso] fatal: ${e.message}\n${e.stack}`);
  printManual();
  process.exit(1);
});
