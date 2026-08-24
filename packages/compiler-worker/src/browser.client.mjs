/**
 * Main-thread client for the in-browser compiler worker.
 *
 * compileSource(source) -> Uint8Array (x64 COFF .obj) | throws with stderr
 * Same shape the /api/compile bridge returns, so callers can switch freely.
 */

export class BrowserCompiler {
  constructor() {
    this.worker = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  _ensureWorker() {
    if (this.worker) return this.worker;
    this.worker = new Worker(
      new URL("./browser.worker.mjs", import.meta.url),
      { type: "module" }
    );
    this.worker.onmessage = (ev) => {
      const { id, ok, objBytes, error } = ev.data ?? {};
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);
      ok ? pending.resolve(objBytes) : pending.reject(new Error(error));
    };
    this.worker.onerror = (e) => {
      for (const p of this.pending.values()) p.reject(new Error(e.message ?? "worker error"));
      this.pending.clear();
    };
    return this.worker;
  }

  _call(op, payload) {
    const worker = this._ensureWorker();
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      worker.postMessage({ id, op, payload });
    });
  }

  /** Preload clang/lld WASM (~40MB) — call early during page load. */
  warmup() {
    return this._call("warmup", {});
  }

  /**
   * @param {string} source C source
   * @returns {Promise<Uint8Array>} x64 COFF object
   */
  async compileSource(source) {
    const bytes = await this._call("compile", { source });
    return bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  }
}
