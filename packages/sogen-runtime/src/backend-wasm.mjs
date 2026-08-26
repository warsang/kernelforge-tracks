/**
 * backend-wasm.mjs — DebugSession adapter over the vendored sogen WASM core.
 *
 * Transport: Web Worker running apps/web/public/sogen/emulator-worker.js.
 * Message surface (upstream page contract):
 *   -> { message: "run",   data: { file, options, arguments, persist } }
 *   <- { message: "log",   data: string[] }        (stdout/DbgPrint lines)
 *   <- { message: "end",   data: exitCode|null }
 *   <- { message: "event", data: <Flatbuffers bytes, base64> }
 *
 * The Flatbuffers event channel carries the debugger verb protocol
 * (DebugCommandRequest/Response envelopes whose payloads are UTF-8 JSON —
 * see upstream docs/debugger/ARCHITECTURE.md). `debugCommand()` below is
 * the single seam: when the FB codec lands it completes the DebugSession;
 * until then every debug verb throws DebuggerUnavailableError and the app
 * falls back to the static session (backend-static.mjs).
 */

export class DebuggerUnavailableError extends Error {
  constructor(why) {
    super(`sogen wasm debugger unavailable: ${why}`);
    this.name = "DebuggerUnavailableError";
  }
}

const WORKER_URL = "sogen/emulator-worker.js";
const GLUE_URL = "sogen/32/analyzer.js";
const WASM_URL = "sogen/32/analyzer.wasm";

/** Probe whether the vendored assets are present (HEAD checks). */
export async function probeAssets(fetchImpl = globalThis.fetch) {
  const results = await Promise.all(
    [WORKER_URL, GLUE_URL, WASM_URL].map(async (u) => {
      try {
        const r = await fetchImpl(u, { method: "HEAD" });
        return { url: u, ok: !!r.ok };
      } catch {
        return { url: u, ok: false };
      }
    }),
  );
  return {
    ok: results.every((r) => r.ok),
    missing: results.filter((r) => !r.ok).map((r) => r.url),
  };
}

/** Command kinds from upstream docs/debugger/ARCHITECTURE.md. */
export const DebugCommandKind = {
  GetRegisters: 0,
  Disassemble: 1,
  GetModules: 2,
  GetThreads: 3,
  GetCallStack: 4,
  SetBreakpoint: 5,
  ClearBreakpoint: 6,
  ListBreakpoints: 7,
  StepInto: 8,
  StepOver: 9,
  StepOut: 10,
  RunTo: 11,
  Continue: 12,
  ReadMemory: 13,
};

/**
 * Create a wasm-backed session client.
 * @param {{file: string, options?: string[], arguments?: string[],
 *          breakOnStart?: boolean, persist?: boolean}} boot
 * @param {{workerFactory?: () => Worker}} [opts]
 */
export function createWasmClient(boot, opts = {}) {
  const state = {
    worker: null,
    paused: true,
    pauseCount: 0,
    exited: null,
    logTail: [],
    /** @type {Set<(msg: object) => void>} raw event listeners (fb bytes b64) */
    eventListeners: new Set(),
    /** @type {Map<number, {resolve:(v:any)=>void, reject:(e:any)=>void}>} */
    pendingCommands: new Map(),
    nextCommandId: 1,
  };

  function start() {
    const worker = opts.workerFactory
      ? opts.workerFactory()
      : new Worker(WORKER_URL);
    state.worker = worker;

    worker.onmessage = (event) => {
      const data = event.data ?? {};
      switch (data.message) {
        case "log": {
          for (const line of data.data ?? []) state.logTail.push(line);
          if (state.logTail.length > 2000) state.logTail.splice(0, state.logTail.length - 2000);
          break;
        }
        case "end":
          state.exited = data.data ?? null;
          state.paused = false;
          for (const [, p] of state.pendingCommands) {
            p.reject(new Error("emulation ended"));
          }
          state.pendingCommands.clear();
          break;
        case "event":
          for (const cb of state.eventListeners) cb(data.data);
          // DebugCommandResponse routing happens inside the fb decoder once
          // it lands; the id-correlation map is already in place.
          break;
        default:
          break;
      }
    };
    worker.onerror = (e) => {
      state.logTail.push(`[worker-error] ${e.message ?? "unknown"}`);
    };

    const options = [...(boot.options ?? [])];
    if (boot.breakOnStart) options.push("--break-start");
    worker.postMessage({
      message: "run",
      data: {
        file: boot.file,
        options,
        arguments: boot.arguments ?? [],
        persist: boot.persist ?? false,
        wasm64: false,
        cacheBuster: undefined,
      },
    });
    return worker;
  }

  /**
   * Issue one debugger command through the Flatbuffers envelope.
   * LOUD DEGRADE: the FB codec is the remaining vendor milestone; until it
   * lands every call rejects with DebuggerUnavailableError and callers fall
   * back to backend-static.mjs.
   */
  async function debugCommand(kind, payloadJson) {
    if (!state.worker) throw new DebuggerUnavailableError("worker not started");
    throw new DebuggerUnavailableError(
      "flatbuffers DebugCommand codec not implemented yet " +
      "(see packages/sogen-runtime/vendor/README.md — kinds " +
      `${kind}${payloadJson ? ":" + JSON.stringify(payloadJson).slice(0, 40) : ""})`,
    );
  }

  return {
    start,
    debugCommand,
    get logLines() { return [...state.logTail]; },
    get exited() { return state.exited; },
    get paused() { return state.paused; },
    terminate() {
      state.worker?.terminate?.();
      state.worker = null;
    },
  };
}
