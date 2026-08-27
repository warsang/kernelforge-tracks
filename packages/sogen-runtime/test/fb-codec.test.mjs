/**
 * FlatBuffers wire codec round-trips against hand-built reference buffers
 * (builder call sequences mirror upstream's generated pack() code).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Builder } from "flatbuffers";
import {
  Event as FbEvent, State,
  encodeDebugEvent, decodeDebugEvent,
  encodeDebugArgs, decodeJsonPayload,
} from "../src/fb/debugger.mjs";

/** Build DebugCommandResponse{id,ok,payload} exactly like upstream gen code. */
function buildDebugCommandResponse(id, ok, payloadBytes) {
  const b = new Builder(64);
  let vec = 0;
  if (payloadBytes?.length) {
    b.startVector(1, payloadBytes.length, 1);
    for (let i = payloadBytes.length - 1; i >= 0; i--) b.addInt8(payloadBytes[i]);
    vec = b.endVector();
  }
  b.startObject(3);
  b.addFieldInt32(0, id, 0);
  b.addFieldInt8(1, ok ? 1 : 0, 0);
  if (vec) b.addFieldOffset(2, vec, 0);
  const inner = b.endObject();
  b.startObject(2);
  b.addFieldInt8(0, FbEvent.DebugCommandResponse, 0);
  b.addFieldOffset(1, inner, 0);
  b.finish(b.endObject());
  return b.asUint8Array();
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

test("DebugCommandRequest encodes and decodes symmetrically", () => {
  const payload = new Uint8Array([1, 2, 3, 4]);
  const bytes = encodeDebugEvent({
    eventType: FbEvent.DebugCommandRequest, id: 0xdeadbeef, kind: 7, payload,
  });
  const { eventType, event } = decodeDebugEvent(bytes);
  assert.equal(eventType, FbEvent.DebugCommandRequest);
  assert.equal(event.id, 0xdeadbeef);
  assert.equal(event.kind, 7);
  assert.deepEqual([...event.payloadBytes], [...payload]);
});
test("GetStateResponse decodes state value", () => {
  const { eventType, event } = decodeDebugEvent(buildGetStateResponse(State.Paused));
  assert.equal(eventType, FbEvent.GetStateResponse);
  assert.equal(event.state, State.Paused);
});

test("DebugCommandResponse carries ok + UTF-8 JSON payload", () => {
  const body = JSON.stringify({ registers: [{ name: "rip", value: "0x401000" }] });
  const bytes = buildDebugCommandResponse(42, true, new TextEncoder().encode(body));
  const { eventType, event } = decodeDebugEvent(bytes);
  assert.equal(eventType, FbEvent.DebugCommandResponse);
  assert.equal(event.id, 42);
  assert.equal(event.ok, true);
  assert.deepEqual(decodeJsonPayload(event.payloadBytes),
    { registers: [{ name: "rip", value: "0x401000" }] });
});

test("encodeDebugArgs packs little-endian u64/u32/u8", () => {
  const args = encodeDebugArgs([["u64", 0x1122334455667788n], ["u32", 0xaabbccdd], ["u8", 0x7f]]);
  assert.equal(args.length, 13);
  const view = new DataView(args.buffer);
  assert.equal(view.getBigUint64(0, true), 0x1122334455667788n);
  assert.equal(view.getUint32(8, true), 0xaabbccdd);
  assert.equal(view.getUint8(12), 0x7f);
});
