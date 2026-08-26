/**
 * GDB Remote Serial Protocol bridge tests — scripted guest peer, no
 * emulator required. Covers framing, run-length decoding, register/memory
 * transactions, breakpoint ops, and the GdbSession DebugSession surface.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { framePacket, checksum, rleDecode, RspClient } from "../src/rsp.mjs";
import { GdbSession, parseGPacket } from "../src/gdb-session.mjs";

/**
 * Scripted in-memory RSP peer.
 * responder(cmd) -> reply payload | "@STOP" (async T05) | undefined (silent)
 */
function makePeer(responder) {
  const sent = [];
  let rx = null;
  const emit = (text) => {
    for (const ch of text) rx?.(ch.charCodeAt(0));
  };
  return {
    sent,
    transport: {
      send(bytes) {
        const text = [...bytes].map((b) => String.fromCharCode(b)).join("");
        sent.push(text);
        const m = /^\$([^#]+)#/.exec(text);
        if (!m) return;
        const reply = responder(m[1]);
        if (reply === "@STOP") {
          // stop packets are framed like every other RSP response
          const stopPkt = "T05thread:1;eip:08048074;";
          queueMicrotask(() => emit("+$" + stopPkt + "#" + checksum(stopPkt)));
          return;
        }
        if (reply === undefined) return;
        queueMicrotask(() => emit("+$" + reply + "#" + checksum(reply)));
      },
      onReceive(cb) { rx = cb; },
    },
  };
}

test("rle decode + checksum + framing", () => {
  assert.equal(framePacket("qSupported"), "$qSupported#" + checksum("qSupported"));
  assert.equal(rleDecode("0* "), "0000"); // ' ' = 32 -> 3 extra copies of '0'
  assert.equal(rleDecode("ab"), "ab");
});

test("RspClient: connect handshake + memory read round-trip", async () => {
  const seen = [];
  const { transport, sent } = makePeer((cmd) => {
    seen.push(cmd);
    if (cmd.startsWith("qSupported")) return "PacketSize=3fff;swbreak+;vContSupported-";
    if (cmd === "?") return "S05";
    if (cmd.startsWith("m")) return "78563412"; // little-endian dword
    return "OK";
  });
  const rsp = new RspClient(transport);
  const feats = await rsp.connect();
  assert.equal(feats.swbreak, true);
  assert.equal(seen.at(-1), "?");

  // ack '+' must have gone out after the last response frame
  assert.match(sent.at(-1), /^\+$/);

  const bytes = await rsp.readMemory("1000", 4);
  assert.deepEqual([...bytes], [0x78, 0x56, 0x34, 0x12]);
});

test("parseGPacket decodes i386 little-endian dwords", () => {
  // order: eax ecx edx ebx esp ebp esi edi eip eflags cs ss ds es fs gs
  const blob =
    "11223344" + // eax: bytes 11 22 33 44 -> 0x44332211
    "0".repeat(56) +
    "70800408" + // eip: bytes 70 80 04 08 -> 0x08048070
    "46000000" + // eflags: bytes 46 00 00 00 -> 0x00000046
    "0".repeat(48);
  const regs = parseGPacket(blob);
  assert.equal(regs.eax.toString(16), "44332211");
  assert.equal(regs.eip.toString(16), "8048070");
  assert.equal(regs.eflags.toString(16), "46");
  assert.equal(regs.gs.toString(16), "0");
});

test("GdbSession: attach, registers, breakpoints, step, continue", async () => {
  const EIP_AFTER_STEP = "74050408";
  let mode = "idle";
  const peer = makePeer((cmd) => {
    if (cmd.startsWith("qSupported")) return "PacketSize=3fff";
    if (cmd === "?") return "T05thread:1;eip:08048070;";
    if (mode === "stepping" && cmd === "s") return "@STOP";
    if (mode === "running" && (cmd === "c" || cmd.startsWith("v"))) return "@STOP";
    if (cmd.startsWith("Z0") || cmd.startsWith("z0")) return "OK";
    if (cmd === "g") {
      // LE byte order: eip 0x08048070 -> chars "70800408"
      const eip = mode === "stepped" ? EIP_AFTER_STEP : "70800408";
      return (
        "11223344" + "0".repeat(56) + eip + "46000000" + "0".repeat(48)
      );
    }
    if (cmd.startsWith("m")) return "90".repeat(64);
    if (cmd === "D") return "OK";
    return "OK";
  });

  const session = await GdbSession.attach(peer.transport);

  // registers parse out of the g blob
  const regs = await session.getRegisters();
  assert.equal(regs.find((r) => r.name === "eax").value, "44332211"); // LE dword decode
  assert.equal(regs.find((r) => r.name === "eip").value, "08048070"); // padded to width 8

  // disassembly reads memory through the stub (nops decode as `db`? no:
  // capstone decodes 0x90 as nop — but the stub returns nops for any addr)
  const insns = await session.disassemble("8048070", 4);
  assert.ok(insns.length >= 1, "disasm produced instructions");
  assert.equal(insns[0].mnemonic, "nop");

  // breakpoint lifecycle
  await session.setBreakpoint("8048074");
  assert.equal((await session.listBreakpoints()).length, 1);
  assert.ok(peer.sent.some((f) => /^\$Z0,8048074,1#/.test(f)));

  // single step (async stop path)
  mode = "stepping";
  await session.stepInto();
  assert.equal(session.paused, true);
  assert.ok(session.pauseCount >= 2);
  mode = "stepped";

  // continue until the next stop
  mode = "running";
  await session.continueRunInternal();
  assert.equal(session.lastStop.signal, 5);
  assert.equal(session.paused, true);

  await session.clearBreakpoint("8048074");
  assert.equal((await session.listBreakpoints()).length, 0);

  await session.detach();
});
