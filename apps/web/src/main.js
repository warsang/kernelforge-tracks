import "./styles.css";
import { marked } from "marked";
import { catalog } from "@kernelforge/course-content";
import {
  checkFlag, submitFlagForProgress, isLessonUnlocked,
  emptyProgress, resolveBackend,
} from "@kernelforge/lab-runtime";
import { loadProgress, saveProgress } from "@kernelforge/lab-runtime/storage.browser";
import { getScenario, tryLoadDumpWorld, tryLoadCarvedState } from "./scenarios.js";
import { validateDriverSource } from "./driver-builder.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { compileDriverSource, warmupCompiler } from "@kernelforge/compiler-worker/index.browser.mjs";
import { loadTables } from "./tables.js";
import { paneFor } from "./panes.js";
import { createDebugger } from "./debugger.js";
import { createDebugConsole, disposeConsoles } from "./console.js";
import { renderAnalyzer } from "./analyzer.js";

warmupCompiler(); // preload the wasm toolchain in the background

const app = document.getElementById("app");
let progress = emptyProgress();
let currentDebugger = null;
let currentKernel = null;
let currentSession = null;

function kernel_processByName(kernel, name) {
  return kernel.processesByName.get(name) ?? null;
}

/** Starter code: catalog-provided source first, legacy hardcoded fallbacks after. */
function getStarterCode(lab) {
  const provided = (lab.starterFiles ?? []).find((f) => f.content?.trim());
  if (provided) return provided.content;
  if (lab.id.includes("dkom")) {
    return `// DKOM process hiding — unlink kftarget.exe from ActiveProcessLinks
//
// This driver demonstrates Direct Kernel Object Manipulation:
// 1. Locate the target _EPROCESS by PID
// 2. Overwrite its ActiveProcessLinks to remove it from the list
// 3. The process becomes invisible to !process / NtQuerySystemInformation

#include <ntddk.h>

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    PEPROCESS targetProcess = NULL;
    HANDLE targetPid = (HANDLE)666; // kftarget.exe

    NTSTATUS status = PsLookupProcessByProcessId(targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("DKOM: Failed to find pid %lu\\n", (ULONG)(ULONG_PTR)targetPid);
        return status;
    }

    PLIST_ENTRY pLinks = (PLIST_ENTRY)((PUCHAR)targetProcess + 0x448);
    RemoveEntryList(pLinks);
    DbgPrint("DKOM: unlinked kftarget.exe, LIST_ENTRY @ %p\\n", pLinks);

    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}
`;
  }
  return "// Write your driver code here\n";
}

async function persist() {
  await saveProgress(progress);
}

const solvedCount = () => Object.keys(progress.solvedFlags).length;
const totalPoints = () => progress.points ?? 0;

// --------------------------------------------------- compiler-lab tasks
// Each compiler lab declares `compileTask`; the task owns source validation
// and post-run verification against live kernel state.

function verifyDkomTask(kernel, loaded, status) {
  const kftarget = kernel_processByName(kernel, "kftarget.exe");
  if (!kftarget) {
    status("err", "kftarget.exe not found in process list!");
    return false;
  }
  const stillVisible = kernel.listProcesses().some((p) => p.name === "kftarget.exe");
  const unloadSet = kernel.mem.u64(loaded.drvRec.va + 0x68n) !== 0n;
  const printed = [...kernel.dbgLog].reverse().find((l) => l.includes("_LIST_ENTRY"));

  if (stillVisible) {
    status("warn", "!process still shows kftarget.exe — DKOM may not have worked.");
  } else {
    status("good", "✓ kftarget.exe hidden!");
  }
  if (!unloadSet) {
    status("warn", "DriverUnload was not set on DriverObject.");
  }
  if (printed) {
    status("mono", printed.trim());
    const addr = printed.match(/LIST_ENTRY at:\s*([0-9a-f`]+)/i);
    if (addr) status("good", `LIST_ENTRY @ 0x${addr[1].replace(/`/g, "")}`);
  }
  return !stillVisible;
}

const HOOK_API = "PsLookupProcessByProcessId";

function verifyInlineHookTask(kernel, loaded, status) {
  const detoured = kernel.isDetoured(HOOK_API);
  const thunk = kernel.apiThunks.get(HOOK_API);
  const printed = [...kernel.dbgLog].reverse().find((l) => l.includes("kfdetour:"));
  const unloadSet = kernel.mem.u64(loaded.drvRec.va + 0x68n) !== 0n;

  if (!detoured) {
    status("err", "!hookscan would show nothing — your driver did not write an E9 to " +
      `${HOOK_API}'s prologue. Did you paste the export address into g_TargetFn?`);
    return false;
  }
  status("good", `✓ ${HOOK_API} prologue @ ${thunk ? "0x" + thunk.toString(16) : "?"} reads as detoured.`);
  status("dim", "Prove it: !hookscan, then !hooktest PsLookupProcessByProcessId 666");
  if (printed) {
    status("mono", printed.trim());
  }
  if (!unloadSet) {
    status("warn", "DriverUnload was not set on DriverObject.");
  }
  return true;
}

const COMPILE_TASKS = {
  "dkom-hide": { validate: (src) => validateDriverSource(src, "dkom-hide"), verify: verifyDkomTask },
  "inline-hook": { validate: (src) => validateDriverSource(src, "inline-hook"), verify: verifyInlineHookTask },
};

/** Defense-lab tasks verify via the sensor's own DbgPrint telemetry. */
function logJoin(kernel) { return kernel.dbgLog.join("\n"); }

function makeSentinelVerify(patterns) {
  return (kernel, _loaded, status) => {
    const log = logJoin(kernel);
    let ok = true;
    for (const [label, rx] of patterns) {
      if (rx.test(log)) status("good", `✓ ${label}`);
      else { ok = false; status("err", `✗ missing: ${label}`); }
    }
    if (ok) status("dim", "Sensor telemetry complete — read findings from the debugger.");
    return ok;
  };
}

COMPILE_TASKS["sentinel-v1"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["process-list walk", /SENTINEL-V1: process list walk/],
    ["DKOM carve detection", /carve hit 'kftarget\.exe'.*pid=666|no hidden-process signatures/],
    ["unbacked-exec classification", /UNBACKED EXEC DETECTED|belongs to a listed module/],
    ["completion secret", /secret=kf-sentinel-v1-ok/],
  ]),
};
COMPILE_TASKS["sentinel-v2"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["IRQL sampling", /SENTINEL-WATCHDOG: sampled IRQL = 15/],
    ["ladder restoration", /ladder restored to 2/],
    ["watchdog secret", /secret=kf-watchdog-ok/],
  ]),
};
COMPILE_TASKS["sentinel-v3"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["PsLookupProcessByProcessId attested", /SENTINEL-ATTEST: PsLookupProcessByProcessId/],
    ["hook conviction", /INLINE HOOK DETECTED/],
    ["completion secret", /secret=kf-attest-ok/],
  ]),
};
COMPILE_TASKS["sentinel-v4"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    // %p renders without 0x; %02x pads to 8 digits (model formatter limits)
    ["guard sweep ran", /SENTINEL-POOLMON: block 0 @ fffff90000001000 guard intact/],
    ["corruption convicted", /block 1 @ fffff90000001200.*CORRUPTED/],
    ["completion secret", /secret=kf-poolmon-ok/],
  ]),
};
const taskFor = (lab) => COMPILE_TASKS[lab.compileTask ?? (lab.id.includes("dkom") ? "dkom-hide" : "")] ?? null;

// ---------------------------------------------------------------- rendering

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  // NB: defaults don't cover explicit `null` callers — normalize instead.
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}

function refreshHeader() {
  const el = document.querySelector(".points");
  if (el) el.textContent = `${solvedCount()} flags · ${totalPoints()} pts`;
}

function renderShell() {
  app.innerHTML = "";
  const header = h("header", null,
    h("span", { class: "logo" }, "⚒ KernelForge"),
    h("span", { class: "spacer" }),
    h("span", { class: "points" }, `${solvedCount()} flags · ${totalPoints()} pts`),
  );
  app.append(header, h("div", { id: "layout" },
    h("aside", { id: "sidebar" }),
    h("main", { id: "main" }),
  ));
  renderSidebar();
  renderWelcome();
}

function renderSidebar() {
  const sidebar = document.getElementById("sidebar");
  sidebar.innerHTML = "";
  sidebar.append(h("h2", null, "Tools"));
  const analyzerBtn = h("button", {
    class: "tool",
    onclick: () => renderAnalyzer(document.getElementById("main")),
  }, "⚒ Driver Analyzer");
  sidebar.append(analyzerBtn);
  for (const mod of catalog.modules) {
    sidebar.append(h("h2", null, mod.title));
    for (const lesson of mod.lessons) {
      const unlocked = isLessonUnlocked(lesson, progress);
      const done = progress.completedLessons.includes(lesson.id);
      sidebar.append(h("button", {
        class: `lesson ${unlocked ? "" : "locked"} ${done ? "done" : ""}`,
        onclick: () => unlocked && renderLesson(lesson),
      }, `${done ? "✔" : unlocked ? "▸" : "🔒"} ${lesson.title}`));
    }
  }
}

function renderWelcome() {
  const main = document.getElementById("main");
  main.innerHTML = "";
  main.append(
    h("div", { class: "card" },
      h("h1", null, "Windows Kernel Fundamentals"),
      h("p", null, "Pick a lesson from the sidebar. Labs boot a real x64 Windows " +
        "kernel model in your browser — inspect it with the debugger console, " +
        "solve the objectives, submit flags."),
      h("p", { class: "dim" }, "Progress lives in IndexedDB on this machine only."),
    ),
  );
}

// ------------------------------------------------------------ lab rendering

function renderLesson(lesson) {
  const main = document.getElementById("main");
  disposeConsoles(); // terminals from the previous lesson render
  main.innerHTML = "";

  // Lesson body: markdown (shipped as content modules in course-content).
  const card = h("div", { class: "card" }, h("h1", null, lesson.title));
  const body = h("div", { class: "lesson-body md" });
  if (typeof lesson.body === "string" && lesson.body.length) {
    body.innerHTML = marked.parse(lesson.body);
  } else {
    body.append(h("p", { class: "dim" }, "(no lesson text)"));
  }
  card.append(body);
  main.append(card);

  for (const lab of lesson.labs) {
    // xterm.js-backed kd> console (div fallback in headless DOMs); input is
    // inline — every submitted line routes to currentDebugger.exec.
    const consoleHost = h("div", { class: "console-host" });
    const consoleReady = createDebugConsole(consoleHost, {
      onSubmit: (line) => currentDebugger?.exec(line),
    });

    const pane = paneFor(lab.kind) ?? {};
    const backends = pane.backends ?? [
      { value: "js", label: "CPU: JsInterpreter (deterministic)" },
      { value: "unicorn", label: "CPU: Unicorn (QEMU wasm)" },
    ];
    const backendSel = h("select", {},
      backends.map((b) => h("option", { value: b.value }, b.label)));
    const bootBtn = h("button", {
      class: "primary",
      onclick: async () => {
        bootBtn.disabled = true;
        bootBtn.textContent = "booting…";
        const dbg = await consoleReady;
        try {
          const scenario = getScenario(lab.scenario);
          const factory = pane.rawBoot ? null : await resolveBackend(backendSel.value);
          const dumpWorld = pane.noDump ? null : await tryLoadDumpWorld();
          const io = pane.rawBoot ? {} : {
            makeBackend: (mem) => factory(mem),
            loadTables: () => loadTables(),
            dumpWorld,
            carvedState: pane.noDump ? null : await tryLoadCarvedState(),
          };
          const session = await scenario.boot(io);
          dbg.innerHTML = "";
          currentSession = session;
          currentKernel = session.kernel ?? null;
          currentDebugger = pane.createDebugger
            ? pane.createDebugger(session, dbg)
            : createDebugger(session.kernel, dbg);
          if (!pane.noDump && session.dumpPagesLoaded > 0) {
            currentDebugger.write(
              `CARVED-DUMP MODE: ${session.dumpPagesLoaded} genuine pages ` +
              `(ntoskrnl/CI/cng) loaded at true VAs from a public kernel dump.`);
          }
          if (dumpWorld && !pane.noDump) {
            currentDebugger.write(
              `REAL-DUMP MODE: ${dumpWorld.meta.processCount} processes, ` +
              `${dumpWorld.meta.moduleCount} modules extracted from a genuine ` +
              `Windows kernel dump (${dumpWorld.meta.source}).`);
          }
          currentDebugger.write(`Booted "${lab.scenario}" on the ${backendSel.value} backend. Type 'help'.`);
          dbg.focusTarget?.focus?.();
        } catch (e) {
          dbg.innerHTML = "";
          dbg.write(`boot failed: ${e.message}`, "err");
        } finally {
          bootBtn.disabled = false;
          bootBtn.textContent = "Boot / Reset";
        }
      },
    }, "Boot / Reset");

    const card = h("div", { class: "card lab" },
      h("h2", null, lab.title + " ", h("code", { class: "kind" }, lab.kind)),
      h("p", null, lab.brief),
    );

    // pane-registered editors (e.g. linux LKM IDE)
    if (pane.attachEditor) {
      const editorStatus = h("div", { class: "compile-status" });
      card.append(pane.attachEditor({
        h,
        lab,
        status: (text, cls = "dim") => editorStatus.append(h("div", { class: cls }, text)),
        getSession: () => ({ linux: currentSession?.linux ?? null }),
      }));
      card.append(editorStatus);
    }

    if (lab.kind === "compiler") {
      const task = taskFor(lab);
      const editor = h("textarea", {
        class: "code-editor", rows: 16, spellcheck: "false",
      }, getStarterCode(lab));
      const compileBtn = h("button", { class: "primary" }, task ? "Compile & Load Driver" : "(unsupported lab)");
      compileBtn.disabled = !task;
      const compileStatus = h("div", { class: "compile-status" });
      const status = (cls, text) =>
        compileStatus.append(h("div", { class: cls }, text));
      compileBtn.addEventListener("click", async () => {
        if (!task) return;
        compileStatus.innerHTML = "";
        const src = editor.value;
        const validation = task.validate(src);
        if (!validation.ok) {
          for (const err of validation.errors)
            compileStatus.append(h("div", { class: "err" }, "✗ " + err));
          return;
        }
        for (const warn of validation.warnings)
          compileStatus.append(h("div", { class: "dim" }, "⚠ " + warn));
        compileStatus.append(h("div", { class: "good" }, "✓ Code validated — compiling..."));

        // Boot if needed
        if (!currentDebugger) {
          bootBtn?.click();
          if (!currentDebugger) {
            status("err", "boot failed");
            return;
          }
        }

        // Real compilation: in-browser wasm clang first, server bridge fallback.
        // Managing a clean compile IS part of the exercise: no simulated fallback.
        let objBytes, via;
        try {
          ({ objBytes, via } = await compileDriverSource(src));
        } catch (err) {
          status("err", "✗ compile failed: " + err.message);
          return;
        }
        const viaMsg = via === "wasm"
          ? "compiled in-browser (wasm clang)"
          : "compiled via server fallback";
        status("good", `✓ ${viaMsg} (${objBytes.length} bytes)`);

        // Link + manual-map the student's actual bytes into emulated memory.
        let loaded;
        try {
          loaded = loadCompiledDriver(currentKernel, objBytes, { labId: lab.id });
        } catch (err) {
          status("err", "✗ load failed: " + err.message);
          return;
        }
        status("good", `✓ mapped at 0x${loaded.base.toString(16)} as ${loaded.name}`);

        // Execute DriverEntry on the session's CPU engine (SEH-aware).
        const regPathBuf = currentKernel.allocPool(0x100);
        currentKernel.mem.writeUtf16(regPathBuf,
          "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
        const result = currentKernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
          loaded.image);

        if (result.status !== "ok") {
          status("err", `✗ Driver faulted: ${result.error?.message ?? result.status}`);
          for (const ex of currentKernel.exceptionTrace.splice(0)) {
            status("warn", `${ex.handled ? "SEH handled" : "UNHANDLED"} @ ${ex.faultRip}: ${ex.detail}`);
          }
          return;
        }
        currentDebugger.write(`${loaded.name}: DriverEntry executed on ${backendSel.value} backend.`);

        // Task-specific verification against live kernel state.
        const ok = task.verify(currentKernel, loaded, status);
        if (lab.compileTask === "inline-hook") {
          currentDebugger.write(ok
            ? `Detour is live — inspect it with !hookscan / !hooktest.`
            : `No detour landed — check g_TargetFn and recompile.`);
        } else {
          currentDebugger.write(`Run !process 0 0 to verify kftarget.exe is hidden; lm shows your driver.`);
        }
      });
      card.append(editor, h("div", { class: "controls" }, compileBtn), compileStatus);
    }

    card.append(h("div", { class: "controls" }, backendSel, bootBtn));
    card.append(consoleHost);

    // ---- flag submission
    for (const f of lab.flags) {
      const solved = !!progress.solvedFlags[f.id];
      const inp = h("input", { placeholder: solved ? "solved ✔" : "your answer…", disabled: solved ? "" : undefined });
      const btn = h("button", {
        disabled: solved ? "" : undefined,
        onclick: async () => {
          const ok = await checkFlag(inp.value, f);
          const ev = submitFlagForProgress(progress, lesson, f.id, ok);
          if (ok) {
            progress = ev.progress;
            await persist();
            btn.textContent = "✔";
            btn.classList.add("good");
            inp.placeholder = "solved ✔";
            inp.disabled = true;
            btn.disabled = true;
            refreshHeader();
            renderSidebar(); // surface newly unlocked lessons immediately
          } else {
            inp.classList.add("bad");
            setTimeout(() => inp.classList.remove("bad"), 600);
          }
        },
      }, solved ? "✔" : "submit");
      card.append(h("div", { class: "flag" },
        h("span", { class: "prompt" }, f.prompt),
        h("span", { class: "pts" }, `${f.points} pts`),
        h("div", { class: "row" }, inp, btn),
      ));
    }

    main.append(card);
  }
}

// --------------------------------------------------------------------- init

(async function init() {
  try { progress = (await loadProgress()) ?? emptyProgress(); } catch { progress = emptyProgress(); }
  renderShell();
})();
