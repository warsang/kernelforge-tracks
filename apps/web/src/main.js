/**
 * KERNELFORGE web shell — wires ntsim + windbg + compiler pipeline into the UI.
 * Zero-build: ESM imports resolved via import map to workspace sources.
 */

import { NtKernel, mapPe } from "@kernelforge/ntsim";
import { KdEngine } from "@kernelforge/windbg-web/engine";
import { linkDriver } from "@kernelforge/compiler-worker/linkdriver.mjs";
import { catalog } from "@kernelforge/course-content";

// ---------------------------------------------------------------- state

let kernel = null;
let kd = null;
const $ = (id) => document.getElementById(id);

async function bootKernel() {
  const tablesResp = await fetch("/assets/vergilius/windows-10/22h2/_EPROCESS.json");
  if (!tablesResp.ok) throw new Error("struct tables not deployed");
  // full table set loads in parallel in the real app; minimal boot here:
  const eprocTable = await tablesResp.json();
  const { StructTables } = await import("@kernelforge/ntsim");
  void StructTables;
  kernel = new NtKernel();
  // register scraped tables via fetch
  for (const t of ["_EPROCESS","_ETHREAD","_KPROCESS","_KTHREAD","_LIST_ENTRY",
                   "_UNICODE_STRING","_OBJECT_TYPE","_OBJECT_HEADER","_HANDLE_TABLE",
                   "_PS_PROTECTION"]) {
    try {
      const r = await fetch(`/assets/vergilius/windows-10/22h2/${t}.json`);
      if (!r.ok) continue;
      const rec = JSON.parse(await r.text());
      kernel.tables.types.set(t, rec);
    } catch { /* optional type */ }
  }
  kernel.bootstrap();
  kd = new KdEngine(kernel);
  return kernel;
}

// ---------------------------------------------------------------- tabs

for (const btn of document.querySelectorAll("#tabs button")) {
  btn.addEventListener("click", () => {
    for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("active", b === btn);
    for (const t of document.querySelectorAll(".tab")) {
      t.classList.toggle("active", t.id === `tab-${btn.dataset.tab}`);
    }
  });
}

// ---------------------------------------------------------------- windbg tab

const kdOut = $("kd-out");
function kdPrint(text, cls = "") {
  const div = document.createElement("div");
  div.className = `kd-cmd-line ${cls}`;
  div.textContent = text;
  kdOut.appendChild(div);
  kdOut.scrollTop = kdOut.scrollHeight;
}

$("kd-in").addEventListener("keydown", async (e) => {
  if (e.key !== "Enter") return;
  const line = e.target.value;
  e.target.value = "";
  if (!line.trim()) return;
  kdPrint(`kd> ${line}`, "cmd");
  if (!kernel) {
    kdPrint("(booting kernel...)");
    await bootKernel();
  }
  try {
    kdPrint(kd.execute(line));
  } catch (err) {
    kdPrint(`!! ${err.message}`);
  }
});

// ---------------------------------------------------------------- lab tab

$("btn-boot").addEventListener("click", async () => {
  $("lab-log").textContent = "booting emulated x64 kernel...\n";
  try {
    await bootKernel();
    $("lab-log").textContent +=
      `kernel booted: ${kernel.listProcesses().length} processes, ` +
      `build tables: windows-10 22h2\n` +
      `PsActiveProcessHead @ 0x${kernel.PsActiveProcessHead.toString(16)}\n`;
    $("lab-status").textContent = "kernel running";
  } catch (e) {
    $("lab-log").textContent += `boot failed: ${e.message}\n`;
  }
});

$("btn-run-lab").addEventListener("click", () => {
  if (!kernel) { $("lab-status").textContent = "boot first"; return; }
  const procs = kernel.listProcesses().map((p) => `${p.pid} ${p.name}`).join("\n");
  $("lab-log").textContent += `\n=== !process 0 0 ===\n${procs}\n`;
  $("lab-status").textContent = "checks complete";
});

// ---------------------------------------------------------------- ide tab

$("editor").value = `// kfdemo.c — your first driver
typedef long long i64;
typedef unsigned long long u64;
typedef const char* cstr;

i64 DbgPrint(cstr fmt, ...);

u64 DriverEntry(void* drv, void* reg) {
  (void)drv; (void)reg;
  DbgPrint("hello from my own driver %d\\n", 42);
  return 0;
}
`;

$("btn-compile").addEventListener("click", async () => {
  const status = $("compile-status");
  status.textContent = "compiling…";
  status.className = "";
  try {
    // Phase A (this skeleton): POST source to local clang bridge when running
    // under the dev server; Phase B swaps in browsercc WASM — same interface.
    const src = $("editor").value;
    const resp = await fetch("/api/compile", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ source: src }),
    });
    if (!resp.ok) throw new Error(`compile API ${resp.status}`);
    const { objBase64 } = await resp.json();
    const objBytes = Uint8Array.from(atob(objBase64), (c) => c.charCodeAt(0));

    if (!kernel) await bootKernel();

    let dbgThunk = null;
    const { image, entryRva } = linkDriver(
      [objBytes],
      (name) => (name === "DbgPrint" ? (dbgThunk = kernel.apiThunks.get("DbgPrint")) : null),
      0xfffff80130000000n,
    );
    const base = 0xfffff80130000000n;
    mapPe(image, kernel.mem, base, () => null);
    const r = kernel.callDriverEntry(base + BigInt(entryRva), 0n, 0n);
    if (r.status !== "ok") throw new Error(`driver faulted: ${r.error?.message ?? r.status}`);

    status.textContent = `loaded ✓ — ${kernel.dbgLog.at(-1)?.trim() ?? "(no output)"}`;
    status.className = "ok";
  } catch (e) {
    status.textContent = e.message;
    status.className = "err";
  }
});

// ---------------------------------------------------------------- course tab

function renderCourse() {
  const list = $("lesson-list");
  list.innerHTML = "";
  for (const mod of catalog.modules) {
    const h = document.createElement("div");
    h.textContent = mod.title;
    h.style.cssText = "color:var(--accent);margin:10px 0 4px;font-size:12px;letter-spacing:1px;";
    list.appendChild(h);
    for (const lesson of mod.lessons) {
      const item = document.createElement("div");
      item.className = "lesson-item";
      item.textContent = lesson.title;
      item.addEventListener("click", () => renderLesson(mod, lesson));
      list.appendChild(item);
    }
  }
}

function renderLesson(mod, lesson) {
  void mod;
  $("lesson-body").innerHTML = `
    <h1>${lesson.title}</h1>
    <p><em>${lesson.labs.map((l) => l.brief).join(" ")}</em></p>
    <p>This lesson's lab runs in the <b>Lab</b> and <b>WinDbg</b> tabs. Flags are
    submitted from the lab panel once your objective is met.</p>
    <pre>kd> !process 0 0        ; enumerate the live process list
kd> dt nt!_EPROCESS     ; real struct layout for build 19045</pre>`;
}

renderCourse();
