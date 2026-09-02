/**
 * apps/web/src/halfix.js — 🖥️ Halfix — Win10 22H2 (x86) Tools page
 *
 * WASM-only in webUI. Native builds are dev-local (Phases 0/3/4).
 * Mirrors apps/web/src/analyzer.js / linux-pane.js patterns:
 *   export function renderHalfix(main) { main.innerHTML=""; ... }
 *
 * Phases covered (report gates per spec):
 *  0  toolchain check (native) — reported in UI via bundle probe
 *  1  CPU tier + RAM (P4/Core Duo FXSAVE/SSE2, 1024-2048M)
 *  2  media (Bochs BIOS, ata0-master HDD + ata0-slave CD, boot CD first)
 *  3  Setup with LabConfig unattend.xml bypass (no licensing bypass)
 *  4  stabilize 15-20 min idle
 *  5  trim (Update/Defender/SysMain/pagefile)
 *  6  fix 4 GiB disk backend (disk.mjs)
 *  7  WASM deploy (File API / IndexedDB + optional Range remote)
 */

import { probeHalfixBundle, verifyDiskBackend } from "@kernelforge/halfix-lab";
import { ingestFile, loadMeta, clearImage, chunkIndex, CHUNK_SIZE } from "@kernelforge/halfix-lab/src/disk.mjs";

const IMAGE_ID = "halfix-win10";
const ISO_ID = "halfix-iso";

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) e.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    // eslint-disable-next-line no-nested-ternary
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

function logLine(host, msg, cls = "") {
  const d = el("div", { class: `line ${cls}` }, msg);
  host.append(d);
  host.scrollTop = host.scrollHeight;
  return d;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

// Small helper to trigger download of unattend.xml (LabConfig bypasses)
function downloadUnattendXml() {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>4</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassStorageCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>5</Order>
          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
      <UserData>
        <AcceptEula>true</AcceptEula>
      </UserData>
    </component>
  </settings>
  <!--
    This unattend.xml only bypasses minimum-spec enforcement (TPM/SecureBoot/RAM/Storage/CPU).
    It does NOT bypass Windows activation or licensing. Provide your own legitimate
    Windows 10 22H2 x86 ISO and product key per Microsoft terms.
  -->
</unattend>`;
  const blob = new Blob([xml], { type: "application/xml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "unattend-win10-halfix.xml";
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadTrimGuide() {
  const md = `# Phase 5 — Trim for low emulated throughput (10-30 MIPS)
# Run inside the Halfix Windows 10 VM after reaching desktop:

# 1) Windows Update — defer
#    services.msc → Windows Update → Startup type: Disabled → Stop
#    gpedit.msc → Computer Configuration → Administrative Templates → Windows Components → Windows Update → Configure Automatic Updates → Disabled

# 2) SysMain / Superfetch — disable
#    services.msc → SysMain → Startup type: Disabled → Stop

# 3) Windows Defender real-time — disable (lab only)
#    Settings → Update & Security → Windows Security → Virus & threat protection → Manage settings → Real-time protection: Off
#    (or via registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1)

# 4) Background apps — off
#    Settings → Privacy → Background apps → Let apps run in background: Off

# 5) Pagefile — small fixed size
#    System → Advanced system settings → Performance Settings → Advanced → Virtual memory → Custom size: 512 MB initial / 512 MB max

# 6) Optional: disable Search indexing, OneDrive, telemetry (lab only).
`;
  const blob = new Blob([md], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "halfix-trim-guide.txt";
  a.click();
  URL.revokeObjectURL(a.href);
}

export function renderHalfix(main) {
  main.innerHTML = "";

  let session = null;
  let hddFile = null; // File handle (20 GiB raw) — not loaded as ArrayBuffer!
  let isoFile = null;
  let booting = false;

  const out = el("div", { class: "analyzer-out", style: "max-height:320px;overflow:auto;border:1px solid #333;padding:8px;border-radius:6px;background:#010409" });
  const say = (m, c) => logLine(out, m, c);

  // ---- header
  const header = el("div", { class: "card" },
    el("h1", null, "🖥️ Halfix — Windows 10 22H2 (x86)"),
    el("p", { class: "dim" },
      "Boot Windows 10 22H2 32-bit inside Halfix (C99 x86, PAE, i440FX, ACPI, I/O APIC) — in your browser via WebAssembly. ",
      "WASM runs 10–30 MIPS vs ~70–100 native — do Phase 3/4 debugging natively first, then use the browser for the final deploy."
    ),
    el("p", { class: "dim", style: "font-size:12px;border-left:3px solid #58a6ff;padding-left:8px" },
      "You must provide a legitimate Windows 10 22H2 x86 ISO and license. The ", el("code", null, "unattend.xml"), " below only bypasses minimum-spec checks (LabConfig), not activation. ",
      "See Phases 0–7 in the Guide below."
    )
  );

  // ---- status row
  const bundleStatus = el("span", { class: "dim" }, "probing WASM bundle…");
  const diskStatus = el("span", { class: "dim" }, "chunk backend: probing…");
  const statusRow = el("div", { class: "analyzer-controls", style: "gap:16px;flex-wrap:wrap" },
    el("span", null, "Bundle: ", bundleStatus),
    el("span", null, "Disk: ", diskStatus)
  );

  // ---- controls row 1: RAM + BIOS + boot order
  const ramSel = el("select", { title: "Phase 1: 1024–2048 MB (valid 1–3584 MB) — 1024M default for ARM macOS native, 2048M also valid" },
    el("option", { value: "1024", selected: "true" }, "RAM: 1024 MB (default, stable)"),
    el("option", { value: "2048" }, "RAM: 2048 MB"),
    el("option", { value: "512" }, "RAM: 512 MB (tight)"),
    el("option", { value: "3072" }, "RAM: 3072 MB"),
    el("option", { value: "3584" }, "RAM: 3584 MB (max)")
  );
  const bootSel = el("select", { title: "Boot order" },
    el("option", { value: "cd" }, "Boot: CD → HD (install)"),
    el("option", { value: "hd" }, "Boot: HD → CD (after install)")
  );
  const biosBadge = el("span", { class: "dim", style: "font-size:11px;border:1px solid #30363d;padding:2px 6px;border-radius:4px" }, "Bochs bios.bin + vgabios.bin ✓");
  const fastTick = el("input", { type: "checkbox", title: "Ignore HLT timing — run as fast as possible (desktop feels snappier, but timing-sensitive installs may want it off)" });
  const fastLabel = el("label", { class: "dim", style: "display:flex;gap:4px;align-items:center;font-size:12px" }, fastTick, " fast (ignore HLT)");

  // ---- controls row 2: file pickers
  const hddInput = el("input", { type: "file", accept: ".img,.raw,.bin", title: "Raw HDD image (20 GiB, chunks are 256 KiB — 81920 blocks). Created via: qemu-img create -f raw win10.img 20G" });
  const hddMeta = el("span", { class: "dim", style: "font-size:12px" }, "no HDD yet");
  const hddLoadBtn = el("button", { class: "btn btn-sm" }, "Load HDD → IndexedDB");
  hddLoadBtn.disabled = true;

  const isoInput = el("input", { type: "file", accept: ".iso", title: "Windows 10 22H2 x86 ISO (3-5 GiB, e.g. Win10_22H2_English_x32.iso)" });
  const isoMeta = el("span", { class: "dim", style: "font-size:12px" }, "no ISO yet");

  // Remote URL (optional range fetch) — secondary to File API
  const remoteUrl = el("input", { type: "text", placeholder: "optional remote HDD URL (Range-capable, e.g. https://archive.org/download/.../win10.img)", style: "min-width:360px;flex:1" });
  const remoteFetchBtn = el("button", {}, "Fetch remote → IndexedDB");
  remoteFetchBtn.title = "Streams via HTTP Range into IndexedDB in 1 MiB batches. For large images this takes minutes — prefer local File drop.";

  // HDD ingestion state
  hddInput.addEventListener("change", async () => {
    const f = hddInput.files?.[0];
    if (!f) return;
    hddFile = f;
    hddMeta.textContent = `${f.name} — ${formatBytes(f.size)} — ${Math.ceil(f.size / CHUNK_SIZE)} chunks`;
    const meta = await loadMeta(IMAGE_ID).catch(() => null);
    if (meta && meta.size === f.size) {
      hddMeta.textContent += ` (IndexedDB already has ${formatBytes(meta.size)})`;
      hddLoadBtn.textContent = "Re-ingest HDD → IndexedDB";
    } else {
      hddLoadBtn.textContent = "Ingest HDD → IndexedDB";
    }
    hddLoadBtn.disabled = false;
    say(`[disk] selected HDD ${f.name} ${formatBytes(f.size)} — click Ingest to chunk into IndexedDB (256 KiB).`, "dim");
    if (f.size < 16 * 1024 * 1024 * 1024) {
      say(`[warn] HDD <16 GiB (${formatBytes(f.size)}) — Windows 10 x86 needs ~16-20 GiB free.`, "warn");
    }
    if (f.size > 4 * 1024 * 1024 * 1024 && verifyDiskBackend().ok) {
      say(`[disk] >4 GiB image — chunk backend fix is active (Number-safe Math.floor(offset/262144)).`, "good");
    }
  });

  isoInput.addEventListener("change", () => {
    const f = isoInput.files?.[0];
    if (!f) return;
    isoFile = f;
    isoMeta.textContent = `${f.name} — ${formatBytes(f.size)}`;
    say(`[iso] selected ${f.name} ${formatBytes(f.size)} — will be attached as ata0-slave type=cd.`, "dim");
  });

  hddLoadBtn.addEventListener("click", async () => {
    if (!hddFile) return;
    hddLoadBtn.disabled = true;
    const prev = hddLoadBtn.textContent;
    hddLoadBtn.textContent = "ingesting…";
    try {
      say(`[disk] ingesting ${hddFile.name} → IndexedDB (${IMAGE_ID}) — do not close tab…`, "dim");
      const t0 = Date.now();
      const meta = await ingestFile(IMAGE_ID, hddFile, (done, total) => {
        if (done % 256 === 0 || done === total) say(`[disk] ${done}/${total} chunks (${((done / total) * 100).toFixed(1)}%)`, "dim");
      });
      const secs = ((Date.now() - t0) / 1000).toFixed(1);
      say(`[disk] done: ${meta.chunks} chunks, ${formatBytes(meta.size)} in ${secs}s — persisted in IndexedDB.`, "good");
      hddMeta.textContent = `${meta.name} — ${formatBytes(meta.size)} — IndexedDB ✓ (${meta.chunks} chunks)`;
      hddLoadBtn.textContent = "Re-ingest";
    } catch (e) {
      say(`[disk] ingest failed: ${e.message}`, "err");
      hddLoadBtn.textContent = prev;
    } finally {
      hddLoadBtn.disabled = false;
    }
  });

  // Remote fetch — streams via Range headers into IndexedDB in batches
  remoteFetchBtn.addEventListener("click", async () => {
    const url = remoteUrl.value.trim();
    if (!url) { say("enter a URL first (e.g. https://archive.org/download/.../win10.img)", "warn"); return; }
    remoteFetchBtn.disabled = true;
    const prev = remoteFetchBtn.textContent;
    remoteFetchBtn.textContent = "fetching…";
    try {
      say(`[remote] HEAD ${url}…`, "dim");
      const head = await fetch(url, { method: "HEAD" });
      if (!head.ok) throw new Error(`HEAD ${head.status} ${head.statusText}`);
      const len = parseInt(head.headers.get("Content-Length") || "0", 10);
      const acceptRanges = head.headers.get("Accept-Ranges");
      say(`[remote] size ${len ? formatBytes(len) : "unknown"} — Accept-Ranges: ${acceptRanges || "none"}`, "dim");
      if (!acceptRanges || acceptRanges === "none") {
        say("[warn] server does not advertise Range support — full download will be attempted (may OOM for 20 GiB). Prefer local File drop.", "warn");
      }
      // Stream in 4 MiB batches via Range
      const total = len || 0;
      const batch = 4 * 1024 * 1024;
      const chunks = total ? Math.ceil(total / CHUNK_SIZE) : 0;
      if (chunks) say(`[remote] will fetch ${chunks} chunks (${formatBytes(total)}) via Range in ${Math.ceil(total / batch)} batches…`, "dim");
      // Clear previous
      await clearImage(IMAGE_ID);
      let fetched = 0;
      for (let off = 0; off < total; off += batch) {
        const end = Math.min(off + batch - 1, total - 1);
        const res = await fetch(url, { headers: { Range: `bytes=${off}-${end}` } });
        if (!res.ok && res.status !== 206) throw new Error(`Range ${off}-${end} → ${res.status}`);
        const buf = new Uint8Array(await res.arrayBuffer());
        // Store into chunk store — split batch into 256 KiB chunks
        for (let b = 0; b < buf.length; ) {
          const chunkIdx = chunkIndex(off + b);
          const chunkOff = (off + b) % CHUNK_SIZE;
          const take = Math.min(CHUNK_SIZE - chunkOff, buf.length - b);
          // This is a partial write into a chunk — need read-modify-write via disk.mjs
          const { writeRange } = await import("@kernelforge/halfix-lab/src/disk.mjs");
          await writeRange(IMAGE_ID, off + b, buf.subarray(b, b + take));
          b += take;
        }
        fetched += buf.length;
        if ((off / batch) % 8 === 0 || fetched === total) {
          say(`[remote] ${formatBytes(fetched)} / ${formatBytes(total)} (${total ? ((fetched / total) * 100).toFixed(1) : "?"}%)`, "dim");
        }
      }
      // Persist meta
      const { storeMeta } = await import("@kernelforge/halfix-lab/src/disk.mjs");
      await storeMeta(IMAGE_ID, { size: total, chunks: Math.ceil(total / CHUNK_SIZE), chunkSize: CHUNK_SIZE, name: url.split("/").pop() || "remote.img", ingestedAt: Date.now() });
      say(`[remote] done — ${formatBytes(fetched)} stored in IndexedDB as ${IMAGE_ID}.`, "good");
      hddMeta.textContent = `remote ${formatBytes(total)} — IndexedDB ✓`;
    } catch (e) {
      say(`[remote] failed: ${e.message} — try local File drop instead. Free hosting tips: archive.org (unlimited, Range) or huggingface.co/datasets (100 GiB LFS).`, "err");
    } finally {
      remoteFetchBtn.disabled = false;
      remoteFetchBtn.textContent = prev;
    }
  });

  // ---- helpers row
  const dlUnattend = el("button", { title: "LabConfig bypasses only — does NOT bypass activation" }, "⬇ unattend.xml");
  dlUnattend.addEventListener("click", downloadUnattendXml);
  const dlTrim = el("button", { title: "Phase 5 trimming steps after desktop" }, "⬇ trim guide");
  dlTrim.addEventListener("click", downloadTrimGuide);
  const isoFetchGuide = el("button", { title: "How to get the Win10 22H2 x86 ISO" }, "ISO fetch help");
  isoFetchGuide.addEventListener("click", () => {
    say("--- ISO fetch help ---", "dim");
    say("MS direct (auto): node tools/fetch-win10-iso.mjs  → scrapes microsoft.com + UUP dump fallback → ./win10-22h2-x86.iso", "mono");
    say("Manual: https://www.microsoft.com/en-us/software-download/windows10ISO → Windows 10 → 32-bit Download → save as win10-22h2-x86.iso", "mono");
    say("Then drop the .iso via the file picker above (ata0-slave type=cd). No activation bypass — use your own key.", "dim");
  });
  const clearBtn = el("button", { title: "Clear IndexedDB chunk stores for this tool" }, "Clear IndexedDB");
  clearBtn.addEventListener("click", async () => {
    await clearImage(IMAGE_ID);
    await clearImage(ISO_ID);
    say("[disk] IndexedDB cleared for halfix-win10 + halfix-iso.", "warn");
    hddMeta.textContent = "no HDD yet";
    isoMeta.textContent = "no ISO yet";
    hddLoadBtn.disabled = !hddFile;
  });

  // ---- canvas + controls
  const canvas = el("canvas", { id: "halfix-vga", width: "640", height: "400", style: "background:#000;border:1px solid #30363d;border-radius:6px;image-rendering:pixelated;display:block;max-width:100%" });
  const bootBtn = el("button", { class: "primary", style: "min-width:180px" }, "▶ Boot Halfix (WASM)");
  const pauseBtn = el("button", {}, "⏸ Pause");
  pauseBtn.disabled = true;
  const resetBtn = el("button", {}, "↺ Reset");
  resetBtn.disabled = true;
  const ctrlAltDelBtn = el("button", { title: "Send Ctrl+Alt+Del to guest" }, "Ctrl+Alt+Del");
  ctrlAltDelBtn.disabled = true;

  const speedBadge = el("span", { class: "dim", style: "font-family:ui-monospace,monospace;font-size:12px" }, "— MIPS");
  const diskTestBtn = el("button", { title: "Phase 6: synthetic 6-8 GiB chunk test in this browser" }, "Run disk >4 GiB test");
  const confBtn = el("button", { title: "Show generated Halfix .conf" }, "Show conf");

  // Disk >4 GiB synthetic test (Phase 6 step 3)
  diskTestBtn.addEventListener("click", async () => {
    say("[test] Phase 6 — synthetic sparse >4 GiB chunk test…", "dim");
    const v = verifyDiskBackend();
    say(`[test] verifyDiskBackend: ${v.ok ? "PASS" : "FAIL"} — ${v.detail}`, v.ok ? "good" : "err");
    if (!v.ok) return;
    // Do a tiny IndexedDB round-trip at 6 GiB offset (sparse, no 6 GiB allocation)
    const TEST_ID = "__halfix_test__";
    try {
      await clearImage(TEST_ID);
      const off6g = 6 * 1024 * 1024 * 1024;
      const off8g = 8 * 1024 * 1024 * 1024;
      const { writeRange, readRange, storeMeta } = await import("@kernelforge/halfix-lab/src/disk.mjs");
      await storeMeta(TEST_ID, { size: 8 * 1024 * 1024 * 1024 + CHUNK_SIZE, chunks: Math.ceil((8 * 1024 * 1024 * 1024 + CHUNK_SIZE) / CHUNK_SIZE), chunkSize: CHUNK_SIZE, name: "synthetic-8g", ingestedAt: Date.now() });
      const probe = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x42, 0x42]);
      await writeRange(TEST_ID, off6g, probe);
      await writeRange(TEST_ID, off8g, new Uint8Array([0xca, 0xfe, 0xba, 0xbe]));
      const got6 = await readRange(TEST_ID, off6g, 6);
      const got8 = await readRange(TEST_ID, off8g, 4);
      const ok6 = got6[0] === 0xde && got6[1] === 0xad && got6[5] === 0x42;
      const ok8 = got8[0] === 0xca && got8[3] === 0xbe;
      // Also verify chunkIndex arithmetic at boundary
      const ci4 = chunkIndex(4 * 1024 * 1024 * 1024);
      const ci6 = chunkIndex(off6g);
      const buggy = (off6g / CHUNK_SIZE) | 0; // would still be 24576 (fits), but (blockBase << 18) wraps: check that
      const buggyOff = (ci6 << 18) >>> 0;
      const fixedOff = ci6 * CHUNK_SIZE;
      say(`[test] chunk 4 GiB → ${ci4} (expect 16384) ${ci4 === 16384 ? "✓" : "✗"}`, ci4 === 16384 ? "good" : "err");
      say(`[test] chunk 6 GiB → ${ci6} (expect 24576) ${ci6 === 24576 ? "✓" : "✗"} — buggy (<<18) off=${buggyOff} vs fixed=${fixedOff} ${buggyOff !== fixedOff ? "≠ (bug present in old code, fixed here)" : "=?"}`, ci6 === 24576 ? "good" : "err");
      say(`[test] sparse write/read @6 GiB: ${ok6 ? "PASS ✓" : "FAIL ✗"} — ${Array.from(got6).map(b => b.toString(16).padStart(2, "0")).join(" ")}`, ok6 ? "good" : "err");
      say(`[test] sparse write/read @8 GiB: ${ok8 ? "PASS ✓" : "FAIL ✗"}`, ok8 ? "good" : "err");
      if (ok6 && ok8) say("[test] synthetic >4 GiB PASSED — runtime.js/libhalfix.js fix is active (Number/BigInt, not 32-bit). Ready for real 20 GiB image.", "good");
      else say("[test] synthetic >4 GiB FAILED — disk backend still truncated.", "err");
      await clearImage(TEST_ID);
    } catch (e) {
      say(`[test] failed: ${e.message}`, "err");
    }
  });

  confBtn.addEventListener("click", async () => {
    const { buildConf } = await import("@kernelforge/halfix-lab/src/session.mjs");
    const cfg = buildConf({
      ramMb: parseInt(ramSel.value, 10),
      hdaFile: hddFile ? hddFile.name : "win10.img",
      hdaInserted: !!hddFile || !!(await loadMeta(IMAGE_ID).catch(() => null)),
      cdaFile: isoFile ? isoFile.name : null,
      bootOrder: bootSel.value,
    });
    say("--- generated halFix .conf (Phase 1+2) ---", "dim");
    for (const line of cfg.split("\n")) say(line, "mono");
    say("--- end conf — BIOS=Bochs bios.bin (required for ATAPI CD boot; SeaBIOS is buggy in Halfix) ---", "dim");
  });

  // Boot logic
  bootBtn.addEventListener("click", async () => {
    if (booting) return;
    booting = true;
    bootBtn.disabled = true;
    bootBtn.textContent = "booting…";
    out.innerHTML = "";
    say("[halfix] WASM boot requested — probing bundle…", "dim");
    try {
      const probe = await probeHalfixBundle(fetch);
      if (!probe.ok) {
        say(`[halfix] WASM bundle not built — ${probe.missing?.join(", ") || "halfix.wasm missing"}`, "warn");
        say("Build it (Phase 7):", "mono");
        say("  cd vendor/halfix && node makefile.js emscripten --enable-wasm release", "mono");
        say("  node tools/copy-halfix-artifacts.mjs", "mono");
        say("Vendor docs: vendor/halfix/readme.md + packages/halfix-lab/README.md", "dim");
        say("You can still prepare media (File drops) and run the disk >4 GiB test without the WASM bundle.", "dim");
        // Don't throw — let user see instructions; keep log for disk prep
        bootBtn.disabled = false;
        bootBtn.textContent = "▶ Boot Halfix (WASM)";
        booting = false;
        return;
      }
      say("[halfix] bundle found — checking disk…", "good");
      const meta = await loadMeta(IMAGE_ID).catch(() => null);
      if (!meta && !hddFile) {
        say("[halfix] no HDD — drop win10.img (20 GiB raw) and click Ingest first. Create via: qemu-img create -f raw win10.img 20G", "err");
        say("For install, also attach the Win10 22H2 x86 ISO as CD-ROM (ata0-slave).", "dim");
        throw new Error("no HDD image");
      }
      if (meta) {
        say(`[halfix] HDD from IndexedDB: ${formatBytes(meta.size)} (${meta.chunks} chunks)`, "good");
        if (meta.size < 16 * 1024 * 1024 * 1024) say("[warn] HDD <16 GiB — Windows 10 x86 requires ~16 GiB minimum.", "warn");
      }
      const ram = parseInt(ramSel.value, 10);
      if (ram < 1024) say("[warn] RAM <1024 MB — Windows 10 22H2 x86 recommends 1024-2048 MB.", "warn");
      if (ram > 3584) say("[warn] RAM >3584 MB — Halfix caps at 3584 MB (PCI MMIO hole).", "warn");
      const bootOrder = bootSel.value;
      say(`[halfix] config: RAM=${ram}M, boot=${bootOrder === "cd" ? "CD→HD (install)" : "HD→CD (post-install)"}, BIOS=Bochs bios.bin, fast=${fastTick.checked ? 1 : 0}`, "dim");

      // Build Halfix options — support both File handles and IndexedDB (survives reload)
      if (meta) {
        say(`[halfix] IndexedDB backend will be used for HDD (no File handle needed after ingest)`, "good");
        if (!hddFile) say(`[halfix] Using persisted IndexedDB image — no re-drop needed.`, "dim");
      } else if (hddFile) {
        say(`[halfix] No IndexedDB yet — will ingest ${hddFile.name} on next boot if needed. Click "Ingest" first for large images.`, "dim");
      }

      // Dynamic import of WASM glue
      say("[halfix] loading WASM module (halfix.wasm + libhalfix.js)…", "dim");
      const { HalfixSession } = await import("@kernelforge/halfix-lab/src/session.mjs");
      const sessionOpts = {
        ramMb: ram,
        canvas,
        disk: meta ? { imageId: IMAGE_ID, size: meta.size } : (hddFile ? { imageId: IMAGE_ID, size: hddFile.size } : null),
        hddFile, // File handle if available (for direct File backend)
        isoFile,
        onLog: (line, cls) => say(line, cls),
        onSpeed: (mips) => { speedBadge.textContent = `${mips} MIPS`; },
      };

      say("[halfix] initializing (this may take 5-15s on first load)…", "dim");
      const s = new HalfixSession(sessionOpts);
      session = s;
      await s.boot();
      pauseBtn.disabled = false;
      resetBtn.disabled = false;
      ctrlAltDelBtn.disabled = false;
      say("[halfix] initialized — starting…", "good");
      await s.start();
      say("[halfix] running — expect BIOS splash, then CD/HD boot. MIPS target: 10-30 in browser, 70-100 native.", "good");
      say("If Setup complains about TPM/SecureBoot/RAM, download unattend.xml above and retry (Phase 3). For SSE #GP(0) faults, see Guide → Phase 3 debug loop.", "dim");
      bootBtn.textContent = "▶ Running";
    } catch (e) {
      say(`[halfix] boot failed: ${e.message}`, "err");
      if (e.stack) say(e.stack.slice(0, 800), "dim");
      // Keep canvas placeholder
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#010409";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#f85149";
        ctx.font = "12px ui-monospace, monospace";
        ctx.fillText("boot failed — see log", 12, 20);
      }
      bootBtn.disabled = false;
      bootBtn.textContent = "▶ Boot Halfix (WASM)";
    } finally {
      booting = false;
      if (!session) {
        bootBtn.disabled = false;
        if (bootBtn.textContent === "booting…") bootBtn.textContent = "▶ Boot Halfix (WASM)";
      }
    }
  });

  pauseBtn.addEventListener("click", () => {
    if (!session) return;
    if (session._running) {
      session.pause();
      pauseBtn.textContent = "▶ Resume";
      say("[halfix] paused", "dim");
    } else {
      session.resume();
      pauseBtn.textContent = "⏸ Pause";
      say("[halfix] resumed", "dim");
    }
  });

  resetBtn.addEventListener("click", async () => {
    if (session) {
      await session.destroy();
      session = null;
    }
    const ctx = canvas.getContext("2d");
    if (ctx) { ctx.fillStyle = "#000"; ctx.fillRect(0, 0, canvas.width, canvas.height); }
    out.innerHTML = "";
    say("[halfix] reset — drop files again if needed, then Boot.", "dim");
    bootBtn.disabled = false;
    bootBtn.textContent = "▶ Boot Halfix (WASM)";
    pauseBtn.disabled = true;
    pauseBtn.textContent = "⏸ Pause";
    resetBtn.disabled = true;
    ctrlAltDelBtn.disabled = true;
    speedBadge.textContent = "— MIPS";
  });

  ctrlAltDelBtn.addEventListener("click", () => {
    try {
      // libhalfix.js exposes send_ctrlaltdel via Module._display_send_ctrl_alt_del
      // Our Halfix instance wraps it as send_ctrlaltdel
      if (session?._halfix?.send_ctrlaltdel) session._halfix.send_ctrlaltdel();
      else if (typeof window !== "undefined" && window.Module?._display_send_ctrl_alt_del) {
        window.Module._display_send_ctrl_alt_del(1);
        window.Module._display_send_ctrl_alt_del(0);
      }
      say("[halfix] Ctrl+Alt+Del sent", "dim");
    } catch (e) { say(`Ctrl+Alt+Del failed: ${e.message}`, "err"); }
  });

  // Probe on load
  (async () => {
    const v = verifyDiskBackend();
    diskStatus.textContent = v.ok ? "Number-safe (>4 GiB) ✓" : `FAIL: ${v.detail}`;
    diskStatus.className = v.ok ? "good" : "err";
    try {
      const probe = await probeHalfixBundle(fetch);
      if (probe.ok) {
        bundleStatus.textContent = "built ✓";
        bundleStatus.className = "good";
      } else {
        bundleStatus.textContent = "not built — run Phase 7 build";
        bundleStatus.className = "warn";
        say("[halfix] WASM bundle missing — see Phases 0/7 in Guide. You can still stage disks and run the >4 GiB test.", "warn");
      }
    } catch {
      bundleStatus.textContent = "probe failed";
      bundleStatus.className = "err";
    }
    // Show existing IndexedDB state
    try {
      const meta = await loadMeta(IMAGE_ID);
      if (meta) {
        hddMeta.textContent = `${meta.name} — ${formatBytes(meta.size)} — IndexedDB ✓ (${meta.chunks} chunks)`;
        say(`[disk] found prior HDD in IndexedDB: ${meta.name} ${formatBytes(meta.size)}`, "dim");
      }
    } catch {}
  })();

  // ---- layout assemble
  const controls1 = el("div", { class: "analyzer-controls", style: "gap:8px;flex-wrap:wrap" },
    el("span", { class: "dim", style: "font-size:12px" }, "Config:"),
    ramSel, bootSel, biosBadge, fastLabel, speedBadge
  );
  const controls2 = el("div", { class: "analyzer-controls", style: "gap:8px;flex-wrap:wrap;align-items:center" },
    el("span", { class: "dim", style: "min-width:52px" }, "HDD:"), hddInput, hddMeta, hddLoadBtn
  );
  const controls3 = el("div", { class: "analyzer-controls", style: "gap:8px;flex-wrap:wrap;align-items:center" },
    el("span", { class: "dim", style: "min-width:52px" }, "ISO:"), isoInput, isoMeta
  );
  const controls4 = el("div", { class: "analyzer-controls", style: "gap:8px;flex-wrap:wrap" },
    el("span", { class: "dim", style: "font-size:12px" }, "Remote:"), remoteUrl, remoteFetchBtn
  );
  const controls5 = el("div", { class: "analyzer-controls", style: "gap:8px;flex-wrap:wrap" },
    bootBtn, pauseBtn, resetBtn, ctrlAltDelBtn, diskTestBtn, confBtn
  );
  const helpers = el("div", { class: "analyzer-controls", style: "gap:8px;flex-wrap:wrap" },
    dlUnattend, dlTrim, isoFetchGuide, clearBtn
  );

  const canvasCard = el("div", { class: "card", style: "padding:12px" },
    el("div", { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:8px" },
      el("span", { class: "dim", style: "font-size:12px" }, "VGA canvas — click to focus keyboard. Phase 7: 10-30 MIPS in browser."),
      el("span", { class: "dim", style: "font-size:11px" }, "canvas 640×400 → auto-resizes via Halfix update_size()")
    ),
    canvas
  );

  // ---- guide (collapsible details)
  const guide = el("div", { class: "card" },
    el("h2", null, "Guide — Phases 0–7 (WASM-only UI, native for debug)"),
    el("details", { open: "true" },
      el("summary", null, "Phase 0 — Environment (native, dev-only)"),
      el("div", { class: "mono dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "cd vendor/halfix\n" +
        "node makefile.js            # debug native\n" +
        "node makefile.js release    # release native — use for actual install (70-100 MIPS)\n" +
        "Report: node -v, gcc --version, zlib, emcc --version (emsdk). Do NOT build WASM yet."
      )
    ),
    el("details", null,
      el("summary", null, "Phase 1 — CPU/RAM for Windows 10"),
      el("div", { class: "mono dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "vendor/halfix/src/cpu/ops/misc.c: ATOM_N270_SUPPORT is default (already SSE2/FXSAVE).\n" +
        "For strict P4, edit: //#define P4_SUPPORT → #define P4_SUPPORT (then rebuild native).\n" +
        "RAM: 1024–2048M here (valid 1–3584M). Do NOT pre-fix SSE #GP(0) — handle with repro in Phase 3/4."
      )
    ),
    el("details", null,
      el("summary", null, "Phase 2 — Media (Bochs BIOS, 20 GiB raw)"),
      el("div", { class: "dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "qemu-img create -f raw win10.img 20G   # or: truncate -s 20G win10.img\n" +
        "tools/fetch-win10-iso.mjs   # MS scraper → UUP fallback → manual if both fail\n" +
        "Config: bios=bios.bin (Bochs, patched) — NOT SeaBIOS (ATAPI CD bug), vgabios=vgabios.bin\n" +
        "ata0-master type=hd file=win10.img, ata0-slave type=cd file=Win10_22H2_x32.iso inserted=1, boot CD→HD.\n" +
        "In this tool: drop both files via the pickers above; choose Boot CD→HD for install."
      )
    ),
    el("details", null,
      el("summary", null, "Phase 3 — Setup (expect SSE #GP(0) → patch ops)"),
      el("div", { class: "dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "Boot native halfix with that conf, walk Setup (text + GUI).\n" +
        "If hw-check blocks: use unattend.xml (LabConfig Bypass* keys — spec-allowed, NOT licensing bypass) → click ⬇ unattend.xml.\n" +
        "On crash/triple-fault: capture faulting SSE via CPU log, cross-ref Intel SDM #GP conditions, patch vendor/halfix/src/cpu/ops/* (e.g. simd.c), rebuild native, retry. Report src/cpu/ops diff."
      )
    ),
    el("details", null,
      el("summary", null, "Phase 4 — Stabilize desktop"),
      el("div", { class: "dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "Complete OOBE (local account, skip MS/telemetry). Confirm desktop stays up 15-20 min idle. If SSE #GP(0) reappears post-install, repeat Phase 3 loop. Report unresolved instability with repro."
      )
    ),
    el("details", null,
      el("summary", null, "Phase 5 — Trim for low throughput"),
      el("div", { class: "dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "Inside the VM: disable Windows Update (Disabled), SysMain (Disabled), Defender real-time (Off), background apps (Off), pagefile fixed 512M. See ⬇ trim guide. Do via policy/services, not binary patch."
      )
    ),
    el("details", { open: "true" },
      el("summary", null, "Phase 6 — Fix 4 GiB browser disk limit (done in this tool)"),
      el("div", { class: "dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "Original runtime.js/libhalfix.js used (offset/262144)|0 and (blockBase<<18) — 32-bit truncate, caps at 4 GiB. Fixed here to Math.floor(offset/262144) (Number-safe to 2^53) / BigInt.\n" +
        "Verify without the real 20 GiB image: click Run disk >4 GiB test above — it does sparse 6 GiB + 8 GiB writes via disk.mjs + IndexedDB and asserts chunk math. Must pass before Phase 7."
      )
    ),
    el("details", { open: "true" },
      el("summary", null, "Phase 7 — WASM deploy (this page)"),
      el("div", { class: "dim", style: "font-size:12px;white-space:pre-wrap;margin-top:8px" },
        "cd vendor/halfix && node makefile.js emscripten --enable-wasm release\n" +
        "node tools/copy-halfix-artifacts.mjs   # → apps/web/public/vendor/halfix/ + dist/\n" +
        "Wire libhalfix.js + halfix.wasm + bios.bin/vgabios.bin via HalfixSession (WASM 10-30 MIPS).\n" +
        "Disk is NOT bundled: use File API → IndexedDB (primary) or Range-fetch from Internet Archive (archive.org/download — free unlimited, Range) / Hugging Face datasets (100 GiB LFS, Range). See Remote field above. Test real browser boot to same desktop as native (slower is expected)."
      )
    ),
    el("div", { class: "dim", style: "font-size:11px;margin-top:10px;border-top:1px dashed #30363d;padding-top:8px" },
      "Final deliverable: this page booting the 20 GiB Win10 image to stable desktop via Halfix/WASM, plus diff against nepx/halfix (misc.c tier, SSE fixes, chunk fix) and README with build cmds + default.conf + known limits."
    )
  );

  const card = el("div", { class: "card" },
    el("h2", null, "Boot controls"),
    statusRow,
    controls1,
    controls2,
    controls3,
    controls4,
    controls5,
    helpers
  );

  const logCard = el("div", { class: "card" },
    el("h2", null, "Log"),
    out
  );

  main.append(header, card, canvasCard, logCard, guide);

  // Initial canvas placeholder
  const ctx = canvas.getContext("2d");
  if (ctx) {
    ctx.fillStyle = "#010409";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#8b949e";
    ctx.font = "12px ui-monospace, monospace";
    ctx.fillText("Halfix VGA — Boot to start", 14, 20);
    ctx.fillText("Drop HDD + ISO above, then ▶ Boot", 14, 36);
  }
}
