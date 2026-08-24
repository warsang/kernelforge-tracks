import "./styles.css";
import { catalog } from "@kernelforge/course-content";
import {
  checkFlag, submitFlagForProgress, isLessonUnlocked,
  emptyProgress, resolveBackend,
} from "@kernelforge/lab-runtime";
import { loadProgress, saveProgress } from "@kernelforge/lab-runtime/storage.browser";
import { getScenario, tryLoadDumpWorld } from "./scenarios.js";
import { loadTables } from "./tables.js";
import { createDebugger } from "./debugger.js";

const app = document.getElementById("app");
let progress = emptyProgress();
let currentDebugger = null;

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
  main.innerHTML = "";
  main.append(
    h("div", { class: "card" },
      h("h1", null, lesson.title),
      h("p", { class: "dim" }, "(lesson MDX bodies land with the content pipeline — labs are fully playable)"),
    ),
  );

  for (const lab of lesson.labs) {
    const consoleOut = h("div", { class: "console" });
    let dbg = null;

    const backendSel = h("select", {},
      h("option", { value: "js" }, "CPU: JsInterpreter (deterministic)"),
      h("option", { value: "unicorn" }, "CPU: Unicorn (QEMU wasm)"),
    );
    const bootBtn = h("button", {
      class: "primary",
      onclick: async () => {
        bootBtn.disabled = true;
        bootBtn.textContent = "booting…";
        try {
          const scenario = getScenario(lab.scenario);
          const factory = await resolveBackend(backendSel.value);
          const dumpWorld = await tryLoadDumpWorld();
          const session = await scenario.boot({
            makeBackend: (mem) => factory(mem),
            loadTables: () => loadTables(),
            dumpWorld,
          });
          consoleOut.innerHTML = "";
          currentDebugger = createDebugger(session.kernel, consoleOut);
          if (dumpWorld) {
            currentDebugger.write(
              `REAL-DUMP MODE: ${dumpWorld.meta.processCount} processes, ` +
              `${dumpWorld.meta.moduleCount} modules extracted from a genuine ` +
              `Windows kernel dump (${dumpWorld.meta.source}).`);
          }
          currentDebugger.write(`Booted "${lab.scenario}" on the ${backendSel.value} backend. Type 'help'.`);
        } catch (e) {
          consoleOut.innerHTML = "";
          const line = h("div", { class: "err" }, `boot failed: ${e.message}`);
          consoleOut.append(line);
        } finally {
          bootBtn.disabled = false;
          bootBtn.textContent = "Boot / Reset";
        }
      },
    }, "Boot / Reset");

    const cmdInput = h("input", {
      class: "cmd",
      placeholder: "kd> command…  (help, lm, !process 0 0, r, db <addr>, dq <addr>, !eproc <addr|pid>)",
    });
    cmdInput.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter") return;
      const line = cmdInput.value;
      cmdInput.value = "";
      if (!currentDebugger || !line.trim()) return;
      currentDebugger.exec(line);
    });

    const card = h("div", { class: "card lab" },
      h("h2", null, lab.title + " ", h("code", { class: "kind" }, lab.kind)),
      h("p", null, lab.brief),
    );

    if (lab.kind === "compiler") {
      card.append(h("p", { class: "warn" },
        "⚠ compiler-backed labs arrive with the browser compile service — " +
        "the runtime scenario preview below still boots."));
    }

    card.append(h("div", { class: "controls" }, backendSel, bootBtn));
    card.append(cmdInput, consoleOut);

    // ---- flag submission
    for (const f of lab.flags) {
      const solved = !!progress.solvedFlags[f.id];
      const inp = h("input", { placeholder: solved ? "solved ✔" : "FLAG{…}", disabled: solved ? "" : undefined });
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
