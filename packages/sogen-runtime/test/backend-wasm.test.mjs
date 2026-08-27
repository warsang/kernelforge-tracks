/**
 * createWasmClient / createSogenDebugSession against a scripted mock Worker:
 * run-message shape, writeFile seeding, id-correlated command responses,
 * pause-state machine (pauseCount bumps on Running->Paused transitions).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Builder } from "flatbuffers";
import {
  Event as FbEvent, State,
  encodeDebugEvent,
} from "../src/fb/debugger.mjs";
import { createWasmClient, createSogenDebugSession } from "../src/backend-wasm.mjs";

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

/** Scripted worker: captures posts, lets tests emit events back. */
function mockWorker() {
  const w = {
    posted: [],
    onmessage: null,
    onerror: null,
    postMessage(msg) { w.posted.push(msg); },
    terminate() {},
    /** Deliver a DebugEvent to the client handler. */
    emit(event) {
      w.onmessage?.({ data: { message: "event", data: b64(event) } });
    },
    log(lines) {
      w.onmessage?.({ data: { message: "log", data: lines } });
    },
  };
  return w;
}

function buildGetStateResponse(stateValue) {
  const b = new Builder(32);
  b.startObject(1);
  b.addFieldInt32(0, stateValue, 0);
  const inner = b.endObject();
  b.startObject(2);
  b.addFieldInt8(0, FbEvent.GetStateResponse, 0);
  b.addFieldOffset(1, inner, 0);
  b.finish(b.endObject());
  return b.asUint8Array();
}

function buildDebugCommandResponse(id, ok, payloadJson) {
  const payload = new TextEncoder().encode(payloadJson);
  const b = new Builder(128);
  b.startVector(1, payload.length, 1);
  for (let i = payload.length - 1; i >= 0; i--) b.addInt8(payload[i]);
  const vec = b.endVector();
  b.startObject(3);
  b.addFieldInt32(0, id, 0);
  b.addFieldInt8(1, ok ? 1 : 0, 0);
  b.addFieldOffset(2, vec, 0);
  const inner = b.endObject();
  b.startObject(2);
  b.addFieldInt8(0, FbEvent.DebugCommandResponse, 0);
  b.addFieldOffset(1, inner, 0);
  b.finish(b.endObject());
  return b.asUint8Array();
}

test("client: run message, writeFile seeds, paused-state tracking", async () => {
  const worker = mockWorker();
  const client = createWasmClient({
    file: "c:/demo.exe",
    breakOnStart: true,
    files: [{ path: "/root-windows/filesys/c:/demo.exe", bytes: new Uint8Array([0x4d, 0x5a]) }],
  }, { workerFactory: () => worker });

  assert.equal(client.paused, false, "state unknown before first response");
  client.start();

  const runMsg = worker.posted.find((m) => m.message === "run");
  assert.ok(runMsg, "run message missing");
  assert.equal(runMsg.data.file, "c:/demo.exe");
  assert.ok(runMsg.data.options.includes("--break-start"));
  const seed = worker.posted.find((m) => m.message === "writeFile");
  assert.ok(seed, "writeFile seed missing");
  assert.deepEqual([...seed.data.bytes], [0x4d, 0x5a]);

  worker.log(["hello"]);
  assert.deepEqual(client.logLines, ["hello"]);

  // Running -> Paused transition bumps pauseCount
  worker.emit(buildGetStateResponse(State.Running));
  assert.equal(client.paused, false);
  worker.emit(buildGetStateResponse(State.Paused));
  assert.equal(client.paused, true);
  assert.equal(client.pauseCount, 1);
});

test("debugCommand correlates responses by id and parses JSON", async () => {
  const worker = mockWorker();
  const client = createWasmClient({ file: "c:/demo.exe", breakOnStart: true },
    { workerFactory: () => worker });
  client.start();
  worker.emit(buildGetStateResponse(State.Paused));

  const pending = client.debugCommand(0 /* GetRegisters */);
  // let the microtask queue post the request
  await Promise.resolve();
  const reqMsg = [...worker.posted].reverse().find((m) => m.message === "event");
  assert.ok(reqMsg, "no FB request posted");

  // respond with matching id — extract from the encoded buffer
  const decoded = (await import("../src/fb/debugger.mjs"))
    .decodeDebugEvent(Buffer.from(reqMsg.data, "base64"));
  assert.equal(decoded.event.kind, 0);
  worker.emit(buildDebugCommandResponse(decoded.event.id, true,
    JSON.stringify({ registers: [{ name: "rip", value: "0x401000", size: 8 }] })));

  const result = await pending;
  assert.equal(result.ok, true);
  assert.equal(result.data.registers[0].name, "rip");
});

test("commands resolve null while running (paused-only contract)", async () => {
  const worker = mockWorker();
  const client = createWasmClient({ file: "c:/demo.exe" },
    { workerFactory: () => worker });
  client.start();
  worker.emit(buildGetStateResponse(State.Running));
  const result = await client.debugCommand(2);
  assert.equal(result, null);
});

test("createSogenDebugSession surfaces registers/modules via session API", async () => {
  const worker = mockWorker();
  const client = createWasmClient({ file: "c:/demo.exe", breakOnStart: true },
    { workerFactory: () => worker });
  const { session } = createSogenDebugSession(
    { file: "c:/demo.exe", breakOnStart: true },
    { client, autoStart: false },
  );
  client.start();
  worker.emit(buildGetStateResponse(State.Paused));

  const regsPending = session.getRegisters();
  await Promise.resolve();
  await Promise.resolve();
  const reqMsg = [...worker.posted].reverse().find((m) => m.message === "event");
  const fb = (await import("../src/fb/debugger.mjs"))
    .decodeDebugEvent(Buffer.from(reqMsg.data, "base64"));
  assert.equal(fb.event.kind, 0); // GetRegisters
  worker.emit(buildDebugCommandResponse(fb.event.id, true,
    JSON.stringify({ registers: [{ name: "rax", value: "0x2a", size: 8 }] })));
  const regs = await regsPending;
  assert.equal(regs[0].name, "rax");
  assert.equal(regs[0].value, "0x2a");

  // disassemble maps addresses/branch fields into the Insn shape
  const disPending = session.disassemble("401000", 4);
  await Promise.resolve();
  await Promise.resolve();
  const req2 = [...worker.posted].reverse().find((m) => m.message === "event");
  const fb2 = (await import("../src/fb/debugger.mjs"))
    .decodeDebugEvent(Buffer.from(req2.data, "base64"));
  worker.emit(buildDebugCommandResponse(fb2.event.id, true, JSON.stringify({
    instructions: [
      { address: "401000", size: 5, mnemonic: "mov", operands: "eax, 0x2a",
        symbol: "", isCall: false, isJump: false, isReturn: false },
      { address: "401005", size: 2, mnemonic: "jz", operands: "", branch: "401010",
        isCall: false, isJump: true, isReturn: false },
    ],
  })));
  const insns = await disPending;
  assert.equal(insns[0].mnemonic, "mov");
  assert.equal(insns[1].branch, "401010");
});
