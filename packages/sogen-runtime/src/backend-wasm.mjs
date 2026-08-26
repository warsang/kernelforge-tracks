/**
 * backend-wasm.mjs — DebugSession adapter over the vendored sogen WASM core.
 *
 * Transport: Web Worker running apps/web/public/sogen/emulator-worker.js.
 * Message surface (upstream page contract):
 *   -> { message: "run",   data: { file, options, arguments, persist } }
 *   -> { message: "event", data: <base64 DebugEvent FB> }   (commands/state)
 *   <- { message: "log",   data: string[] }
 *   <- { message: "end",   data: exitCode|null }
 *   <- { message: "event", data: <base64 DebugEvent FB> }   (responses)
 *
 * Wire codec lives in ./fb/debugger.mjs (hand-ported subset of upstream
 * page/src/fb/debugger). Verb semantics mirror upstream page/src/debugger/api.ts:
 * every debug command is a DebugCommandRequest{id,kind,payload} whose payload
 * packs little-endian args and whose response payload is UTF-8 JSON.
 */

import {
  Event as FbEvent, State as FbState,
  encodeDebugEvent, encodeDebugArgs,
  decodeDebugEvent, decodeJsonPayload,
} from "./fb/debugger.mjs";

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

const COMMAND_TIMEOUT_MS = 8000;

/**
 * Low-level wasm emulator client: worker lifecycle + FB event plumbing +
 * id-correlated debug commands. Mirrors upstream Emulator's debugger half.
 */
export function createWasmClient(boot, opts = {}) {
  const state = {
    worker: null,
    fbState: FbState.None,
    pauseCount: 0,
    exited: null,
    logTail: [],
    pendingCommands: new Map(), // id -> {settle}
    pendingReads: new Set(),
    nextCommandId: 1,
    status: null,
  };

  function sendFb(event) {
    const b64 = bytesToBase64(encodeDebugEvent(event));
    state.worker?.postMessage({ message: "event", data: b64 });
  }

  function handleEvent(fb) {
    switch (fb.eventType) {
      case FbEvent.GetStateResponse: {
        const prev = state.fbState;
        state.fbState = fb.event?.state ?? FbState.None;
        if (state.fbState === FbState.Paused && prev !== FbState.Paused) {
          state.pauseCount++;
        }
        break;
      }
      case FbEvent.ApplicationExit:
        state.exited = fb.event?.exit_status ?? null;
        break;
      case FbEvent.EmulationStatus:
        state.status = fb.event;
        break;
      case FbEvent.ReadMemoryResponse: {
        // per-address FIFO tombstones resolve raw reads (upstream model)
        for (const entry of [...state.pendingReads]) {
          if (entry.address === fb.event?.address && !entry.settled) {
            entry.settled = true;
            state.pendingReads.delete(entry);
            entry.settle(fb.event?.data ?? new Uint8Array(0));
            break;
          }
        }
        break;
      }
      case FbEvent.WriteMemoryResponse:
        break;
      case FbEvent.DebugCommandResponse: {
        const entry = state.pendingCommands.get(fb.event?.id);
        if (!entry || entry.settled) break;
        // settle() itself guards idempotency + cleans up the pending map
        entry.settle({
          ok: fb.event.ok,
          data: decodeJsonPayload(fb.event.payloadBytes),
        });
        break;
      }
      default:
        break;
    }
  }

  function start() {
    const worker = opts.workerFactory
      ? opts.workerFactory()
      : new Worker(WORKER_URL);
    state.worker = worker;

    worker.onmessage = (event) => {
      const data = event.data ?? {};
      switch (data.message) {
        case "log":
          for (const line of data.data ?? []) state.logTail.push(line);
          if (state.logTail.length > 2000) state.logTail.splice(0, state.logTail.length - 2000);
          break;
        case "end":
          state.exited = data.data ?? null;
          state.fbState = FbState.None;
          for (const [, p] of state.pendingCommands) p.settle(null);
          state.pendingCommands.clear();
          break;
        case "event":
          if (typeof data.data === "string") {
            handleEvent(decodeDebugEvent(base64ToBytes(data.data)));
          }
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
    // seed target binaries into the emulated root before callMain
    for (const f of boot.files ?? []) {
      worker.postMessage({
        message: "writeFile",
        data: { path: f.path, bytes: f.bytes },
      });
    }
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

    // ask for an initial state snapshot once the analyzer is up
    setTimeout(() => {
      if (state.exited === null) sendFb({ eventType: FbEvent.GetStateRequest });
    }, 250);
    return worker;
  }

  /** One generic debug command; resolves parsed JSON or null. */
  function debugCommand(kind, args = new Uint8Array(0)) {
    if (!state.worker) return Promise.resolve(null);
    if (state.fbState !== FbState.Paused) return Promise.resolve(null);
    const id = state.nextCommandId++;
    if (state.nextCommandId > 0xffffffff) state.nextCommandId = 1;
    return new Promise((resolve) => {
      const entry = { settled: false, settle: () => {} };
      const finish = (value) => {
        if (entry.settled) return;
        entry.settled = true;
        clearTimeout(entry.timer);
        state.pendingCommands.delete(id);
        resolve(value);
      };
      entry.settle = finish;
      entry.timer = setTimeout(() => finish(null), COMMAND_TIMEOUT_MS);
      state.pendingCommands.set(id, entry);
      sendFb({ eventType: FbEvent.DebugCommandRequest, id, kind, payload: args });
    });
  }

  /** Raw memory read through the dedicated union messages (no pause needed). */
  function readMemoryRaw(address, size) {
    if (!state.worker || state.exited !== null) return Promise.resolve(null);
    const key = BigInt(address);
    return new Promise((resolve) => {
      const entry = {
        address: key,
        settled: false,
        settle: (v) => {
          entry.settled = true;
          clearTimeout(entry.timer);
          resolve(v);
        },
      };
      entry.timer = setTimeout(() => {
        state.pendingReads.delete(entry);
        resolve(null);
      }, COMMAND_TIMEOUT_MS);
      state.pendingReads.add(entry);
      sendFb({ eventType: FbEvent.ReadMemoryRequest, address: key, size: Number(size) });
    });
  }

  /** Raw memory write through the dedicated union messages. */
  function writeMemoryRaw(address, bytes) {
    if (!state.worker || state.exited !== null) return;
    sendFb({
      eventType: FbEvent.WriteMemoryRequest,
      address: BigInt(address),
      data: bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes),
    });
  }

  async function requestState() {
    if (!state.worker || state.exited !== null) return;
    sendFb({ eventType: FbEvent.GetStateRequest });
    // state responses are asynchronous events; poll briefly
    for (let i = 0; i < 20 && state.fbState === FbState.None; i++) {
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  return {
    start,
    debugCommand,
    readMemoryRaw,
    writeMemoryRaw,
    requestState,
    pause: () => sendFb({ eventType: FbEvent.PauseRequest }),
    get logLines() { return [...state.logTail]; },
    get exited() { return state.exited; },
    get paused() { return state.fbState === FbState.Paused; },
    get pauseCount() { return state.pauseCount; },
    get status() { return state.status; },
    terminate() {
      state.worker?.terminate?.();
      state.worker = null;
    },
    _state: state, // exposed for tests
  };
}

// ---- base64 --------------------------------------------------------------------

function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToBytes(data) {
  const bin = atob(data);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Full DebugSession over createWasmClient — drops into createDebuggerShell /
 * analysis workspace without UI changes. Introspection verbs mirror upstream
 * page/src/debugger/api.ts exactly.
 */
export function createSogenDebugSession(boot, opts = {}) {
  const client = opts.client ?? createWasmClient(boot, opts);

  const command = (kind, args) =>
    client.debugCommand(kind, args).then((r) => (r && r.ok ? r.data : null));

  const listeners = new Set();
  let lastSeenPauseCount = -1;
  const syncFromClient = () => {
    session.pauseCount = client.pauseCount;
    session.paused = client.exited !== null ? true : client.paused;
    if (client.pauseCount !== lastSeenPauseCount) {
      lastSeenPauseCount = client.pauseCount;
      for (const cb of listeners) {
        try { cb(); } catch { /* listener errors are non-fatal */ }
      }
    }
  };
  const pollTimer = setInterval(syncFromClient, 120);
  pollTimer.unref?.();

  const session = {
    kind: "sogen-wasm",
    paused: true,
    pauseCount: 0,
    onStateChange(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },

    async getRegisters() {
      const d = await command(DebugCommandKind.GetRegisters);
      return d?.registers ?? [];
    },
    async disassemble(address, count) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      const d = await command(DebugCommandKind.Disassemble,
        encodeDebugArgs([["u64", addr], ["u32", count]]));
      return (d?.instructions ?? []).map((i) => ({
        ...i,
        address: String(i.address).replace(/^0x/i, "").padStart(12, "0"),
        branch: i.branch ? String(i.branch).replace(/^0x/i, "") : undefined,
      }));
    },
    async readMemory(address, size) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      // prefer the JSON channel (paused snapshot), fall back to raw reads
      const d = await command(DebugCommandKind.ReadMemory,
        encodeDebugArgs([["u64", addr], ["u32", size]]));
      if (d?.data) return Uint8Array.from(d.data);
      const raw = await client.readMemoryRaw(addr, size);
      return raw ?? new Uint8Array(Number(size));
    },
    async writeMemory(address, bytes) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      client.writeMemoryRaw(addr, bytes);
    },
    async getModules() {
      const d = await command(DebugCommandKind.GetModules);
      return (d?.modules ?? []).map((m) => ({
        ...m,
        base: String(m.base).replace(/^0x/i, "").padStart(12, "0"),
        entry: String(m.entry ?? m.base).replace(/^0x/i, "").padStart(12, "0"),
      }));
    },
    async getThreads() {
      const d = await command(DebugCommandKind.GetThreads);
      return d?.threads ?? [];
    },
    async getCallStack() {
      const d = await command(DebugCommandKind.GetCallStack);
      return d?.frames ?? [];
    },
    async getMemoryRegions() { return []; },

    async setBreakpoint(address) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      const d = await command(DebugCommandKind.SetBreakpoint,
        encodeDebugArgs([["u64", addr], ["u8", 0]]));
      return d?.breakpoints ?? [];
    },
    async clearBreakpoint(address) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      const d = await command(DebugCommandKind.ClearBreakpoint,
        encodeDebugArgs([["u64", addr]]));
      return d?.breakpoints ?? [];
    },
    async listBreakpoints() {
      const d = await command(DebugCommandKind.ListBreakpoints);
      return (d?.breakpoints ?? []).map((b) => ({
        ...b,
        address: String(b.address).replace(/^0x/i, ""),
      }));
    },

    stepInto() { return command(DebugCommandKind.StepInto); },
    stepOver() { return command(DebugCommandKind.StepOver); },
    stepOut() { return command(DebugCommandKind.StepOut); },
    runTo(address) {
      const addr = BigInt("0x" + String(address).replace(/^0x/i, ""));
      return command(DebugCommandKind.RunTo, encodeDebugArgs([["u64", addr]]));
    },
    resume() { return command(DebugCommandKind.Continue); },
    pause() { client.pause(); },
  };

  if (opts.autoStart !== false) {
    client.start();
    void client.requestState();
  }
  return { session, client };
}
