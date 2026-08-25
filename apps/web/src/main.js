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
import { createDebugger } from "./debugger.js";
import { createDebugConsole, disposeConsoles } from "./console.js";
import { renderAnalyzer } from "./analyzer.js";

warmupCompiler(); // preload the wasm toolchain in the background

const app = document.getElementById("app");
let progress = emptyProgress();
let currentDebugger = null;
let currentKernel = null;

function kernel_processByName(kernel, name) {
  return kernel.processesByName.get(name) ?? null;
}

function getStarterCode(lab) {
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

    const backendSel = h("select", {},
      h("option", { value: "js" }, "CPU: JsInterpreter (deterministic)"),
      h("option", { value: "unicorn" }, "CPU: Unicorn (QEMU wasm)"),
    );
    const bootBtn = h("button", {
      class: "primary",
      onclick: async () => {
        bootBtn.disabled = true;
        bootBtn.textContent = "booting…";
        const dbg = await consoleReady;
        try {
          const scenario = getScenario(lab.scenario);
          const factory = await resolveBackend(backendSel.value);
          const dumpWorld = await tryLoadDumpWorld();
          const carvedState = await tryLoadCarvedState();
          const session = await scenario.boot({
            makeBackend: (mem) => factory(mem),
            loadTables: () => loadTables(),
            dumpWorld,
            carvedState,
          });
          dbg.innerHTML = "";
          currentKernel = session.kernel;
          currentDebugger = createDebugger(session.kernel, dbg);
          if (session.dumpPagesLoaded > 0) {
            currentDebugger.write(
              `CARVED-DUMP MODE: ${session.dumpPagesLoaded} genuine pages ` +
              `(ntoskrnl/CI/cng) loaded at true VAs from a public kernel dump.`);
          }
          if (dumpWorld) {
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

    if (lab.kind === "compiler") {
      const editor = h("textarea", {
        class: "code-editor", rows: 16, spellcheck: "false",
      }, getStarterCode(lab));
      const compileBtn = h("button", { class: "primary" }, "Compile & Load Driver");
      const compileStatus = h("div", { class: "compile-status" });
      compileBtn.addEventListener("click", async () => {
        compileStatus.innerHTML = "";
        const src = editor.value;
        const validation = validateDriverSource(src, "dkom-hide");
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
            compileStatus.append(h("div", { class: "err" }, "boot failed"));
            return;
          }
        }

        // Find kftarget.exe
        const kftarget = kernel_processByName(currentKernel, "kftarget.exe");
        if (!kftarget) {
          compileStatus.append(h("div", { class: "err" }, "kftarget.exe not found in process list!"));
          return;
        }

        // Real compilation: in-browser wasm clang first, server bridge fallback.
        // Managing a clean compile IS part of the exercise: no simulated fallback.
        let objBytes, via;
        try {
          ({ objBytes, via } = await compileDriverSource(src));
        } catch (err) {
          compileStatus.append(h("div", { class: "err" }, "✗ compile failed: " + err.message));
          return;
        }
        const viaMsg = via === "wasm"
          ? "compiled in-browser (wasm clang)"
          : "compiled via server fallback";
        compileStatus.append(h("div", { class: "good" }, `✓ ${viaMsg} (${objBytes.length} bytes)`));

        // Link + manual-map the student's actual bytes into emulated memory.
        let loaded;
        try {
          loaded = loadCompiledDriver(currentKernel, objBytes, { labId: lab.id });
        } catch (err) {
          compileStatus.append(h("div", { class: "err" }, "✗ load failed: " + err.message));
          return;
        }
        compileStatus.append(h("div", { class: "good" },
          `✓ mapped at 0x${loaded.base.toString(16)} as ${loaded.name}`));

        // Execute DriverEntry on the session's CPU engine (SEH-aware).
        const regPathBuf = currentKernel.allocPool(0x100);
        currentKernel.mem.writeUtf16(regPathBuf,
          "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
        const result = currentKernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
          loaded.image);

        if (result.status !== "ok") {
          compileStatus.append(h("div", { class: "err" },
            `✗ Driver faulted: ${result.error?.message ?? result.status}`));
          for (const ex of currentKernel.exceptionTrace.splice(0)) {
            compileStatus.append(h("div", { class: "warn" },
              `${ex.handled ? "SEH handled" : "UNHANDLED"} @ ${ex.faultRip}: ${ex.detail}`));
          }
          return;
        }

        // Verify against live kernel state mutated by the student's bytes.
        const stillVisible = currentKernel.listProcesses().some((p) => p.name === "kftarget.exe");
        const unloadSet = currentKernel.mem.u64(loaded.drvRec.va + 0x68n) !== 0n;
        const printed = [...currentKernel.dbgLog].reverse().find((l) => l.includes("_LIST_ENTRY"));

        if (stillVisible) {
          compileStatus.append(h("div", { class: "warn" },
            "!process still shows kftarget.exe — DKOM may not have worked."));
        } else {
          compileStatus.append(h("div", { class: "good" }, "✓ kftarget.exe hidden!"));
        }
        if (!unloadSet) {
          compileStatus.append(h("div", { class: "warn" }, "DriverUnload was not set on DriverObject."));
        }
        if (printed) {
          compileStatus.append(h("div", { class: "mono" }, printed.trim()));
          const addr = printed.match(/LIST_ENTRY at:\s*([0-9a-f`]+)/i);
          if (addr) {
            compileStatus.append(h("div", { class: "good" },
              `LIST_ENTRY @ 0x${addr[1].replace(/`/g, "")}`));
          }
        }
        currentDebugger.write(`${loaded.name}: DriverEntry executed on ${backendSel.value} backend.`);
        currentDebugger.write(`Run !process 0 0 to verify kftarget.exe is hidden; lm shows your driver.`);
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
