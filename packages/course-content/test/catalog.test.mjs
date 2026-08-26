import { test } from "node:test";
import assert from "node:assert/strict";

import { catalog } from "../src/index.mjs";
import { checkFlag, emptyProgress, submitFlagForProgress } from "@kernelforge/lab-runtime";

test("catalog v5 has twenty-three modules / thirty-four lessons / ninety-eight flags", () => {
  assert.equal(catalog.version, 5);
  assert.equal(catalog.modules.length, 23);
  const lessons = catalog.modules.flatMap((m) => m.lessons);
  assert.equal(lessons.length, 34);
  const flags = lessons.flatMap((l) => l.labs.flatMap((lab) => lab.flags));
  assert.equal(flags.length, 98);
});

test("tracks span kernel, userland and linux", () => {
  const tracks = new Set(catalog.modules.map((m) => m.track));
  for (const t of ["windows-kernel", "windows-userland", "linux-kernel", "reversing"]) {
    assert.ok(tracks.has(t), `missing track ${t}`);
  }
});

test("lesson chain is linear m1.l0 -> m19.l1", () => {
  const lessons = catalog.modules.flatMap((m) => m.lessons);
  for (const l of lessons) {
    if (l.id === "m1.l0") { assert.deepEqual(l.requires, []); continue; }
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
    "m1.l0.f1": "4",
    "m1.l0.f2": "apcstate",
    "m1.l0.f3": "kftarget.exe",
    "m1.l1.f1": "KFPROBE.SYS",
    // 1312 everywhere: the dump overlay carries an authentic svchost.exe at
    // 312, and Cids must stay unique system-wide (issue #6)
    "m1.l1.f2": "1312",
    // kftarget.exe EPROCESS @ 0xffffa40bc9e73dc0 + ActiveProcessLinks offset
    // 0x448 (22h2) — must stay in sync with scenarios.js populateFromDump()
    "m1.l2.f1": "0xffffa40bc9e74208",
    "m1.l3.f1": "kf-manual-map-master",
    "m2.l1.f1": "15",
    "m2.l1.f2": "0xFFFFF8055A401400",
    "m2.l1.f3": "kf-dpc-drain-ok",
    // m2.l3 attack workshop (irql-attackers world; KFWARZ_* anchors)
    "m2.l3.f1": "2",
    "m2.l3.f2": "0x80010031",
    "m2.l3.f3": "3",
    "m2.l3.f4": "133",
    "m2.l3.f5": "3",
    "m2.l3.f6": "2",
    "m2.l3.f7": "0xfffff8055a701000",
    "m2.l3.f8": "kf-hijack-seen",
    // m2.l4 defense workshop
    "m2.l4.f1": "1",
    "m2.l4.f2": "kf-watchdog-ok",
    "m2.l4.f3": "missed",
    "m2.l4.f4": "2",
    "m2.l4.f5": "5",
    "m2.l4.f6": "1",
    "m2.l4.f7": "109",
    "m2.l4.f8": "0",
    "m3.l1.f1": "PsLookupProcessByProcessId",
    "m3.l1.f2": "888",
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
    // blog labs v4 (renumbered m14-m19): paging / edr-sensor / ssdt
    "m14.l1.f1": "0x0000000003005000",
    "m14.l1.f2": "0x0000078250e65218",
    "m14.l1.f3": "kf-pt-healed",
    "m15.l1.f1": "STATUS_ACCESS_DENIED",
    "m15.l1.f2": "0x0000000050101000",
    "m15.l1.f3": "kf-edr-blindspot",
    "m16.l1.f1": "NtOpenProcess",
    "m16.l1.f2": "0x0000000005201000",
    "m16.l1.f3": "kf-ssdt-clean",
    // m17 tbm-ac gauntlet
    "m17.l1.f1": "5",
    "m17.l1.f2": "0x00600100",
    "m17.l1.f3": "kf-tbm-godmode",
    // m18 linux syscall-table hook (frozen i386 ABI + guest seeds)
    "m18.l1.f1": "37",
    "m18.l1.f2": "kf-hookspotted",
    "m18.l1.f3": "kf-syscall-clean",
    // m19 reversing the sensor
    "m19.l1.f1": "64",
    "m19.l1.f2": "0x0000000050101000",
    "m19.l1.f3": "64",
    // m20 hooks & integrity monitoring (mini-PatchGuard timing lab)
    "m20.l1.f1": "109",
    "m20.l1.f2": "4",
    "m20.l1.f3": "kf-pg-evaded",
    "m20.l2.f1": "iat",
    "m20.l2.f2": "veh",
    // m21 userland injection (handle-based vs handleless)
    "m21.l1.f1": "kf-ul-inject-ok",
    "m21.l1.f2": "process_vm_write",
    "m21.l1.f3": "apcstate",
    // m22 custom hypervisors & EPT shadowing
    "m22.l2.f1": "0xe9",
    "m22.l2.f2": "2",
    "m22.l2.f3": "kf-ept-detected",
    // m23 DKOM field labs
    "m23.l1.f1": "0x62",
    "m23.l1.f2": "STATUS_ACCESS_DENIED",
    "m23.l1.f3": "kf-ppl-off",
    "m23.l1.f4": "2",
    "m23.l1.f5": "apcstate",
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
  // m1.l0's primer lab completes first (50 + 100 + 100)
  const l0 = m1.lessons.find((l) => l.id === "m1.l0");
  let p = emptyProgress();
  for (const flag of l0.labs[0].flags) {
    p = submitFlagForProgress(p, l0, flag.id, true).progress;
  }
  assert.equal(p.completedLessons.includes("m1.l0"), true);
  assert.equal(p.points, 250);
  const l1 = m1.lessons.find((l) => l.id === "m1.l1");
  p = emptyProgress();
  for (const flag of l1.labs[0].flags) {
    p = submitFlagForProgress(p, l1, flag.id, true).progress;
  }
  assert.equal(p.completedLessons.includes("m1.l1"), true);
  assert.equal(p.points, 200); // 100 + 100
});
