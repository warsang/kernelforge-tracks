// Vite-only module: bundles the Monaco editor web worker as a separate lazy
// chunk. Imported dynamically (and caught) by editor.js — under node --test
// this specifier is unresolvable and the app degrades to workerless Monaco or
// the textarea fallback.
import EditorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";

export default function makeEditorWorker() {
  return new EditorWorker();
}
