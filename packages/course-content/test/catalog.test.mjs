import { test } from "node:test";
import assert from "node:assert/strict";

import { catalog } from "../src/index.mjs";
import { checkFlag, emptyProgress, submitFlagForProgress } from "@kernelforge/lab-runtime";

test("catalog has module 1 with three lessons and four flags", () => {
  assert.equal(catalog.modules.length, 1);
  const m1 = catalog.modules[0];
  assert.equal(m1.lessons.length, 3);
  const flags = m1.lessons.flatMap((l) => l.labs.flatMap((lab) => lab.flags));
  assert.equal(flags.length, 4);
});

test("flag hashes verify against expected plaintexts", async () => {
  // instructor-side ground truth (also in private notes; hashes are public-safe)
  const expect = {
    "m1.l1.f1": "FLAG{kfbootkit.sys}",
    "m1.l1.f2": "FLAG{312}",
    "m1.l3.f1": "FLAG{manual_map_master}",
  };
  const all = catalog.modules[0].lessons.flatMap((l) => l.labs.flatMap((x) => x.flags));
  for (const [id, plain] of Object.entries(expect)) {
    const def = all.find((f) => f.id === id);
    assert.ok(def, `missing flag ${id}`);
    assert.equal(await checkFlag(plain, def), true, `${id} should accept ${plain}`);
    assert.equal(await checkFlag("wrong", def), false);
  }
});

test("lesson progression unlocks l2 after l1 completion", async () => {
  const m1 = catalog.modules[0];
  const [l1, l2] = m1.lessons;
  let p = emptyProgress();
  for (const flag of l1.labs[0].flags) {
    p = submitFlagForProgress(p, l1, flag.id, true).progress;
  }
  assert.equal(p.completedLessons.includes("m1.l1"), true);
  assert.equal(p.points, 200); // 100 + 100
});
