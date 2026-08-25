import { test } from "node:test";
import assert from "node:assert/strict";

import { catalog } from "../src/index.mjs";
import { checkFlag, emptyProgress, submitFlagForProgress } from "@kernelforge/lab-runtime";

test("catalog v4 has thirteen modules / nineteen lessons / forty-five flags", () => {
  assert.equal(catalog.version, 4);
  assert.equal(catalog.modules.length, 13);
  const lessons = catalog.modules.flatMap((m) => m.lessons);
  assert.equal(lessons.length, 19);
  const flags = lessons.flatMap((l) => l.labs.flatMap((lab) => lab.flags));
  assert.equal(flags.length, 45);
});

test("tracks span kernel, userland and linux", () => {
  const tracks = new Set(catalog.modules.map((m) => m.track));
  for (const t of ["windows-kernel", "windows-userland", "linux-kernel", "reversing"]) {
    assert.ok(tracks.has(t), `missing track ${t}`);
  }
});

test("lesson chain is linear m1.l1 -> m13.l1", () => {
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
    // m3.l1.lab2: deterministic 4th thunk (bases.thunk + 0x30) + driver secret
    "m3.l1.f4": "0xfffff80100000030",
    "m3.l1.f5": "kf-hook-author-ok",
    "m4.l1.f1": "0xfffff90000001200",
    "m4.l1.f2": "kf-pool-guard-ok",
    // windows-userland: sogen reference backend world constants
    "m5.l1.f1": "0x00400000",
    "m5.l1.f2": "0x021000d0",
    "m5.l1.f3": "0x24",
    "m6.l1.f1": "0x004532a0",
    "m6.l1.f2": "0x0046f010",
    "m6.l1.f3": "kf-input-restored",
    // linux-kernel: frozen i386 ABI + guest-seeded secrets
    "m7.l1.f1": "128",
    "m7.l1.f2": "kf-lkm-hello",
    "m8.l1.f1": "11",
    "m8.l1.f2": "kf-trace-ok",
    "m9.l1.f1": "3",
    "m9.l1.f2": "kf-detector-ok",
    // reversing: static analysis over the api-hook world
    "m10.l1.f1": "128",
    "m10.l1.f2": "0xfffff8055a601010",
    "m10.l1.f3": "0xfffff8055a601000",
    // smm track: paging + chipset world constants
    "m11.l1.f1": "0x10d000",
    "m11.l1.f2": "7",
    "m11.l1.f3": "nx",
    "m12.l1.f1": "kfsmm-exfil-2026",
    "m12.l1.f2": "0",
    "m13.l1.f1": "0xfb04",
    "m13.l1.f2": "mf2k",
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
