import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  checkFlag,
  emptyProgress,
  isLessonUnlocked,
  submitFlagForProgress,
} from "../src/index.mjs";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

test("checkFlag accepts exact match only", async () => {
  const def = { id: "f1", sha256: sha("FLAG{hello_world}") };
  assert.equal(await checkFlag("FLAG{hello_world}", def), true);
  assert.equal(await checkFlag("  FLAG{hello_world}  ", def), true); // trimmed
  assert.equal(await checkFlag("flag{hello_world}", def), false);
  assert.equal(await checkFlag("FLAG{nope}", def), false);
});

test("progression: flags complete lessons", async () => {
  const lesson = {
    id: "L1",
    requires: [],
    labs: [{ flags: [{ id: "a", points: 10 }, { id: "b", points: 20 }] }],
  };
  const dep = { id: "L2", requires: ["L1"], labs: [] };

  let p = emptyProgress();
  assert.equal(isLessonUnlocked(lesson, p), true);
  assert.equal(isLessonUnlocked(dep, p), false);

  // wrong submission -> no state change
  const r0 = submitFlagForProgress(p, lesson, "a", false);
  assert.deepEqual(r0.events, []);

  p = submitFlagForProgress(p, lesson, "a", true).progress;
  assert.equal(p.points, 10);
  assert.ok(p.solvedFlags.a);

  const res = submitFlagForProgress(p, lesson, "b", true);
  p = res.progress;
  assert.equal(p.points, 30);
  assert.ok(res.events.includes(`lesson-complete:L1`));
});

test("progression: duplicate submissions award nothing twice", () => {
  const lesson = {
    id: "L1",
    requires: [],
    labs: [{ flags: [{ id: "a", points: 10 }] }],
  };
  let p = emptyProgress();
  p = submitFlagForProgress(p, lesson, "a", true).progress;
  const again = submitFlagForProgress(p, lesson, "a", true);
  assert.equal(again.points ?? p.points, p.points);
  assert.deepEqual(again.events, []);
});
