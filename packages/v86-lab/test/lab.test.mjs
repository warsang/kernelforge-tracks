import { test } from "node:test";
import assert from "node:assert/strict";

import { SerialCapture } from "../src/serial.mjs";
import { GUEST_SEEDS } from "../src/seeds.mjs";
import { resolveV86, BundleMissingError, bootLinuxSession } from "../src/session.mjs";

// scripted guest output — what a buildroot console actually sprays over ttyS0
const DMESG_M7 = [
  "[    0.000000] Linux version 6.6.18 (buildroot) #1 SMP",
  "[   12.402310] kflag: module loaded",
  "KFFLAG: kf-lkm-hello",
  "[   12.410001] kflag: read /root/.kflag from kernel space",
].join("\n");

test("serial capture reassembles lines from byte-level chunks", () => {
  const cap = new SerialCapture();
  // feed one byte at a time like v86's serial0-output-byte listener
  for (const ch of DMESG_M7 + "\n") cap.push(ch);
  assert.equal(cap.lines.length, 4);
  assert.match(cap.lines[0], /Linux version 6\.6\.18/);
});

test("KFFLAG secrets extracted across CR and partial writes", async () => {
  const cap = new SerialCapture();
  const stream = DMESG_M7.split("").map((c) => (c === "\n" ? "\r\n" : c));
  for (const chunk of stream) cap.push(chunk);
  assert.equal(cap.secrets.length, 1);
  assert.equal(cap.findSecret("kf-lkm-hello").length, 1);
  assert.equal(cap.findSecret("KF-LKM-HELLO ").length, 1); // normalization
  assert.equal(cap.findSecret("wrong").length, 0);
});

test("nextLine resolves on future lines only", async () => {
  const cap = new SerialCapture();
  cap.push("early line\n");
  // backlog does NOT satisfy a waiter
  await assert.rejects(() => cap.nextLine(30), /timeout/);

  const p = cap.nextLine(500);
  setTimeout(() => cap.push("late line\n"), 20);
  assert.equal(await p, "late line");
});

// ------------------------------------------------------------------ seeds

test("guest seeds pin every linux flag plaintext", () => {
  assert.equal(GUEST_SEEDS["lkm-hello"].kflagFile, "kf-lkm-hello");
  assert.equal(GUEST_SEEDS["syscall-trace"].traceSecret, "kf-trace-ok");
  assert.equal(GUEST_SEEDS["task-hide"].hiddenTasks, 3);
  assert.equal(GUEST_SEEDS["task-hide"].revealSecret, "kf-detector-ok");
});

// ---------------------------------------------------------------- session

test("boot without a bundle fails with instructive error", async () => {
  await assert.rejects(
    () => bootLinuxSession({ worldId: "lkm-hello", image: new ArrayBuffer(8), v86: null }),
    (e) => e instanceof BundleMissingError && /vendor/.test(e.message),
  );
});

test("resolveV86 finds the vendored bundle or soft-degrades to null", async () => {
  const bundle = await resolveV86();
  if (bundle === null) return; // not vendored in this checkout — fine
  assert.equal(typeof bundle.V86, "function");
});
