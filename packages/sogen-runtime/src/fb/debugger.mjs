/**
 * fb/debugger.mjs — minimal FlatBuffers codec for sogen's debugger channel.
 *
 * Hand-ported (JS) subset of upstream momo5502/sogen `src/debugger/events.fbs`
 * generated bindings (page/src/fb/debugger/*.ts) — identical vtable shapes,
 * field ids and defaults, so bytes interoperate with the C++ event_handler.
 * Union `Event` type codes follow the .fbs declaration order (1-based).
 *
 * Envelope: DebugEvent { eventType: uint8 union tag (vtable slot 4),
 *                        event: table (slot 6) }.
 */

import { Builder, ByteBuffer } from "flatbuffers";

// ---- Event union tags ------------------------------------------------------

export const Event = {
  NONE: 0,
  PauseRequest: 1,
  RunRequest: 2,
  GetStateRequest: 3,
  GetStateResponse: 4,
  WriteMemoryRequest: 5,
  WriteMemoryResponse: 6,
  ReadMemoryRequest: 7,
  ReadMemoryResponse: 8,
  WriteRegisterRequest: 9,
  WriteRegisterResponse: 10,
  ReadRegisterRequest: 11,
  ReadRegisterResponse: 12,
  ApplicationExit: 13,
  EmulationStatus: 14,
  GetMemoryRegionsRequest: 15,
  GetMemoryRegionsResponse: 16,
  DebugCommandRequest: 17,
  DebugCommandResponse: 18,
};

export const State = { None: 0, Running: 1, Paused: 2 };

// ---- reader ------------------------------------------------------------------

class Reader {
  constructor(bb, pos) {
    this.bb = bb;
    this.pos = pos;
  }
  /** vtable-relative lookup -> byte offset from table start (0 = absent) */
  off(slot) {
    const vtable = this.pos - this.bb.readUint32(this.pos);
    return slot < this.bb.readUint16(vtable)
      ? this.bb.readUint16(vtable + slot)
      : 0;
  }
  u32(slot, dflt = 0) {
    const o = this.off(slot);
    return o ? this.bb.readUint32(this.pos + o) : dflt;
  }
  u64(slot, dflt = 0n) {
    const o = this.off(slot);
    return o ? this.bb.readUint64(this.pos + o) : dflt;
  }
  bool(slot, dflt = false) {
    const o = this.off(slot);
    return o ? !!this.bb.readUint8(this.pos + o) : dflt;
  }
  /** [ubyte] vector -> Uint8Array view */
  ubyteVector(slot) {
    const o = this.off(slot);
    if (!o) return new Uint8Array(0);
    const rel = this.bb.readUint32(this.pos + o);
    const vec = this.pos + o + rel; // indirect
    // length u32 sits immediately before the elements
    const len = this.bb.readUint32(vec);
    const all = this.bb.bytes();
    return all.subarray(vec + 4, vec + 4 + len);
  }
}

/** Decode a DebugEvent envelope. Returns { eventType, event } */
export function decodeDebugEvent(bytes) {
  const bb = new ByteBuffer(bytes);
  const root = bb.readInt32(bb.position()) + bb.position();
  const env = new Reader(bb, root);
  const oType = env.off(4);
  const eventType = oType ? bb.readUint8(env.pos + oType) : 0;
  let event = null;
  const o = env.off(6);
  if (o) {
    const memberPos = bb.readUint32(env.pos + o) + env.pos + o;
    event = decodeUnionMember(eventType, bb, memberPos);
  }
  return { eventType, event };
}

function envOffType(env) {
  const o = env.off(4);
  return o ? env.bb.readUint8(env.pos + o) : 0;
}

function decodeUnionMember(type, bb, pos) {
  const t = new Reader(bb, pos);
  switch (type) {
    case Event.GetStateResponse:
      return { state: t.u32(4) };
    case Event.ApplicationExit:
      return { exit_status: t.u32(4, null) };
    case Event.EmulationStatus:
      return {
        active_threads: t.u32(4),
        reserved_memory: t.u64(6),
        committed_memory: t.u64(8),
        executed_instructions: t.u64(10),
      };
    case Event.ReadMemoryResponse:
      return { address: t.u64(4), data: t.ubyteVector(6) };
    case Event.WriteMemoryResponse:
      return {
        address: t.u64(4),
        size: t.u32(6),
        success: t.bool(8),
      };
    case Event.GetMemoryRegionsResponse:
      return { regions: t.ubyteVector(4) };
    case Event.DebugCommandResponse:
      return {
        id: t.u32(4),
        ok: t.bool(6),
        payloadBytes: t.ubyteVector(8),
      };
    case Event.DebugCommandRequest:
      return {
        id: t.u32(4),
        kind: t.u32(6),
        payloadBytes: t.ubyteVector(8),
      };
    default:
      return {};
  }
}

// ---- writer -------------------------------------------------------------------

/**
 * Encode DebugEvent{eventType, ...} bytes for the worker's event queue.
 * Supports exactly what our client sends:
 *   PauseRequest | GetStateRequest | RunRequest{singleStep}
 *   ReadMemoryRequest{address,size} | WriteMemoryRequest{address,data}
 *   DebugCommandRequest{id,kind,payload}
 */
export function encodeDebugEvent({ eventType, address, size, id, kind, payload, data, singleStep }) {
  const b = new Builder(1024);

  // child vectors first (offsets point backwards); element writes are the
  // single-argument form (raw push), matching upstream generated vectors
  let vecOff = 0;
  if (eventType === Event.DebugCommandRequest && payload?.length) {
    b.startVector(1, payload.length, 1);
    for (let i = payload.length - 1; i >= 0; i--) b.addInt8(payload[i]);
    vecOff = b.endVector();
  }
  if (eventType === Event.WriteMemoryRequest && data?.length) {
    b.startVector(1, data.length, 1);
    for (let i = data.length - 1; i >= 0; i--) b.addInt8(data[i]);
    vecOff = b.endVector();
  }

  let inner;
  switch (eventType) {
    case Event.PauseRequest:
    case Event.GetStateRequest:
      b.startObject(0);
      inner = b.endObject();
      break;
    case Event.RunRequest:
      b.startObject(1);
      b.addFieldInt8(0, singleStep ? 1 : 0, 0);
      inner = b.endObject();
      break;
    case Event.ReadMemoryRequest:
      b.startObject(2);
      b.addFieldInt64(0, BigInt(address ?? 0), 0n);
      b.addFieldInt32(1, Number(size ?? 0), 0);
      inner = b.endObject();
      break;
    case Event.WriteMemoryRequest:
      b.startObject(2);
      b.addFieldInt64(0, BigInt(address ?? 0), 0n);
      if (vecOff) b.addFieldOffset(1, vecOff, 0);
      inner = b.endObject();
      break;
    case Event.DebugCommandRequest:
      b.startObject(3);
      b.addFieldInt32(0, Number(id ?? 0), 0);
      b.addFieldInt32(1, Number(kind ?? 0), 0);
      if (vecOff) b.addFieldOffset(2, vecOff, 0);
      inner = b.endObject();
      break;
    default:
      throw new Error(`encodeDebugEvent: unsupported event type ${eventType}`);
  }

  b.startObject(2);
  b.addFieldInt8(0, eventType, 0);
  b.addFieldOffset(1, inner, 0);
  b.finish(b.endObject());
  return b.asUint8Array();
}

/** UTF-8 JSON body for DebugCommandRequest payloads. */
export function jsonPayload(text) {
  return text ? new TextEncoder().encode(text) : new Uint8Array(0);
}

/** Decode DebugCommandResponse payload bytes as JSON (null when empty/bad). */
export function decodeJsonPayload(payloadBytes) {
  if (!payloadBytes || !payloadBytes.length) return null;
  try {
    return JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }
}

/**
 * Pack debug-command args little-endian, mirroring upstream
 * Emulator.encodeDebugArgs(["u64"|"u32"|"u8", value] parts).
 */
export function encodeDebugArgs(parts) {
  let size = 0;
  for (const [t] of parts) size += t === "u64" ? 8 : t === "u32" ? 4 : 1;
  const buf = new Uint8Array(size);
  const view = new DataView(buf.buffer);
  let off = 0;
  for (const [t, v] of parts) {
    if (t === "u64") {
      view.setBigUint64(off, BigInt(v), true);
      off += 8;
    } else if (t === "u32") {
      view.setUint32(off, Number(v) >>> 0, true);
      off += 4;
    } else {
      view.setUint8(off, Number(v) & 0xff);
      off += 1;
    }
  }
  return buf;
}
