import { test } from "node:test";
import assert from "node:assert/strict";

import { catalog } from "../src/index.mjs";
import { checkFlag, emptyProgress, submitFlagForProgress } from "@kernelforge/lab-runtime";

test("catalog v2 has five modules / seven lessons / fifteen flags", () => {
  assert.equal(catalog.version, 2);
  assert.equal(catalog.modules.length, 5);
  const lessons = catalog.modules.flatMap((m) => m.lessons);
  assert.equal(lessons.length, 7);
  const flags = lessons.flatMap((l) => l.labs.flatMap((lab) => lab.flags));
  assert.equal(flags.length, 15);
});

test("lesson chain is linear m1.l1 -> m4.l1", () => {
  const lessons = catalog.modules.flatMap((m) => m.lessons);
  for (const l of lessons) {
    if (l.id === "m1.l1") { assert.deepEqual(l.requires, []); continue; }
    const prev = lessons[lessons.indexOf(l) - 1];
    assert.ok(l.requires.includes(prev.id), `${l.id} must require ${prev.id}`);
  }
});

test("every lesson body ships markdown content", () => {
  for (const l of catalog.modules.flatMap((m) => m.lessons)) {
    assert.equal(typeof l.body, "string", `${l.id} body missing`);
    assert.ok(l.body.length > 200, `${l.id} body suspiciously short`);
    assert.match(l.body, /^## /, `${l.id} body should start with a heading`);
  }
});

test("answer hashes verify against expected plaintexts", async () => {
  // instructor-side ground truth; checkFlag normalizes trim+lowercase
  const expect = {
    "m1.l1.f1": "KFPROBE.SYS",
    "m1.l1.f2": "312",
    // kftarget.exe EPROCESS @ 0xffffc80000001000 + ActiveProcessLinks offset
    // 0x448 (22h2) — must stay in sync with scenarios.js populateFromDump()
    "m1.l2.f1": "0xFFFFC80000001448",
    "m1.l3.f1": "kf-manual-map-master",
    "m2.l1.f1": "15",
    "m2.l1.f2": "0xFFFFF8055A401400",
    "m2.l1.f3": "kf-dpc-drain-ok",
    "m3.l1.f1": "PsLookupProcessByProcessId",
    "m3.l1.f2": "666",
    "m3.l1.f3": "STATUS_SUCCESS",
    "m4.l1.f1": "0xfffff90000001200",
    "m4.l1.f2": "kf-pool-guard-ok",
    // anti-trace world: TraceVeh @ kftrace base +0x1400; one traced selftest
    // swallows exactly 4 int1 events (A:1, B:1, C: stall-expiry + nop = 2);
    // secret prints only after eb-clearing g_AntiTraceEnabled
    "m5.l1.f1": "0xfffff8055a801400",
    "m5.l1.f2": "4",
    "m5.l1.f3": "kf-trace-bypass-ok",
  };
  const all = catalog.modules
    .flatMap((m) => m.lessons)
    .flatMap((l) => l.labs)
    .flatMap((x) => x.flags);
  for (const [id, plain] of Object.entries(expect)) {
    const def = all.find((f) => f.id === id);
    assert.ok(def, `missing flag ${id}`);
    assert.equal(await checkFlag(plain, def), true, `${id} should accept ${plain}`);
    assert.equal(await checkFlag(`  ${plain.toLowerCase()} `, def), true,
      `${id} should normalize case/whitespace`);
    assert.equal(await checkFlag("wrong answer", def), false);
  }
});

test("no flag uses the legacy FLAG{} prompt syntax", () => {
  for (const f of catalog.modules
    .flatMap((m) => m.lessons)
    .flatMap((l) => l.labs)
    .flatMap((x) => x.flags)) {
    assert.doesNotMatch(f.prompt, /FLAG\{/, `${f.id} still references FLAG{} syntax`);
  }
});

test("lesson progression unlocks l2 after l1 completion", async () => {
  const m1 = catalog.modules[0];
  const [l1] = m1.lessons;
  let p = emptyProgress();
  for (const flag of l1.labs[0].flags) {
    p = submitFlagForProgress(p, l1, flag.id, true).progress;
  }
  assert.equal(p.completedLessons.includes("m1.l1"), true);
  assert.equal(p.points, 200); // 100 + 100
});
