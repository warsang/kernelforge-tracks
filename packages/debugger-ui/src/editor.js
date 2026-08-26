/**
 * editor.js — shared Monaco code-editor service.
 *
 * One lazy `monaco-editor` load per page; a GitHub-dark-matching theme; a
 * textarea fallback with the identical handle API when Monaco cannot load
 * (offline bundle, node --test, happy-dom). Every code surface in the app
 * routes through createCodeEditor():
 *
 *   compiler-lab IDE  | linux LKM IDE      | lesson fenced blocks
 *   pseudocode tab    | sogen script tab   | future surfaces
 *
 * Handle contract (both paths):
 *   getValue() / setValue(v) / focus() / dispose() / onChange(cb) -> unsub
 *   .monaco  true when backed by real Monaco
 */

const KF_THEME = "kf-dark";

/** @type {Promise<object|null>} resolved monaco module or null */
let monacoOnce = null;
/** @type {Set<Handle>} */
const live = new Set();

function isHeadlessDom() {
  return typeof window !== "undefined" && !!window.happyDOM;
}

async function getMonaco() {
  if (isHeadlessDom()) return null;
  if (!monacoOnce) {
    monacoOnce = (async () => {
      try {
        const mod = await import("monaco-editor");
        const monaco = mod.editor ? mod : null;
        if (!monaco) return null;

        // Editor worker for tokenization-heavy languages; workerless Monaco
        // still renders/edits fine when this fails (node, exotic embeds).
        try {
          const w = await import("./editor-worker.vite.js");
          self.MonacoEnvironment = { getWorker: () => w.default() };
        } catch { /* workerless */ }

        monaco.editor.defineTheme(KF_THEME, {
          base: "vs-dark",
          inherit: true,
          rules: [
            { token: "comment", foreground: "8b949e", fontStyle: "italic" },
            { token: "keyword", foreground: "ff7b72" },
            { token: "string", foreground: "a5d6ff" },
            { token: "number", foreground: "79c0ff" },
            { token: "type", foreground: "ffa657" },
          ],
          colors: {
            "editor.background": "#0d1117",
            "editor.foreground": "#e6edf3",
            "editorLineNumber.foreground": "#6e7681",
            "editorLineNumber.activeForeground": "#e6edf3",
            "editor.selectionBackground": "#264f78aa",
            "editor.lineHighlightBackground": "#161b22",
            "editorCursor.foreground": "#58a6ff",
            "editorIndentGuide.background1": "#21262d",
          },
        });
        return monaco;
      } catch {
        return null;
      }
    })();
  }
  return monacoOnce;
}

/**
 * @typedef {Object} EditorHandle
 * @property {() => string} getValue
 * @property {(v: string) => void} setValue
 * @property {() => void} focus
 * @property {() => void} dispose
 * @property {(cb: (value: string) => void) => () => void} onChange
 * @property {boolean} monaco true when backed by real Monaco
 */

/**
 * Shared handle plumbing: fans native change events into subscribers.
 * @param {{getValue, setValue, focus?, dispose?, monaco: boolean,
 *          subscribe?: (push: () => void) => void}} impl
 * @returns {EditorHandle}
 */
function makeHandle(impl) {
  const cbs = new Set();
  impl.subscribe?.(() => { for (const cb of cbs) cb(impl.getValue()); });
  const handle = {
    monaco: impl.monaco,
    getValue: () => impl.getValue(),
    setValue: (v) => impl.setValue(v),
    focus: () => impl.focus?.(),
    dispose: () => {
      live.delete(handle);
      try { impl.dispose?.(); } catch { /* best effort */ }
    },
    onChange: (cb) => (cbs.add(cb), () => cbs.delete(cb)),
  };
  live.add(handle);
  return handle;
}

/**
 * Create a code editor inside `container`.
 *
 * @param {HTMLElement} container
 * @param {{value?: string, language?: string, readOnly?: boolean,
 *          minimap?: boolean, lineNumbers?: boolean, height?: string}} opts
 * @returns {Promise<EditorHandle>}
 */
export async function createCodeEditor(container, opts = {}) {
  const {
    value = "",
    language = "c",
    readOnly = false,
    minimap = false,
    lineNumbers = true,
    height = "360px",
  } = opts;

  const monaco = await getMonaco();
  if (monaco) {
    try {
      const host = document.createElement("div");
      host.className = "kf-monaco-host";
      host.style.height = height;
      container.append(host);
      const ed = monaco.editor.create(host, {
        value,
        language,
        readOnly,
        theme: KF_THEME,
        automaticLayout: true,
        fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
        fontSize: 12.5,
        minimap: { enabled: minimap },
        lineNumbers: lineNumbers ? "on" : "off",
        scrollBeyondLastLine: false,
        renderLineHighlight: "all",
        tabSize: 4,
        insertSpaces: false,
      });
      return makeHandle({
        getValue: () => ed.getValue(),
        setValue: (v) => ed.setValue(v),
        focus: () => ed.focus(),
        dispose: () => { try { ed.dispose(); } catch { /* gone */ } host.remove(); },
        monaco: true,
        subscribe: (push) => ed.onDidChangeModelContent(push),
      });
    } catch {
      // fall through to the textarea path
    }
  }

  // ---- textarea fallback (identical contract) ------------------------------
  const ta = document.createElement("textarea");
  ta.className = "code-editor";
  ta.rows = 16;
  ta.spellcheck = false;
  ta.value = value;
  ta.readOnly = readOnly;
  container.append(ta);
  return makeHandle({
    getValue: () => ta.value,
    setValue: (v) => { ta.value = v; },
    focus: () => ta.focus(),
    dispose: () => ta.remove(),
    monaco: false,
    subscribe: (push) =>
      ta.addEventListener("input", push),
  });
}

/** Dispose every live editor (lesson re-render housekeeping). */
export function disposeAllEditors() {
  for (const h of [...live]) {
    try { h.dispose(); } catch { /* best effort */ }
  }
  live.clear();
}
