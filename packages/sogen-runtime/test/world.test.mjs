import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildSauerWorld, SogenConsole, SAUER_CONSTANTS, createSogenSession,
} from "../src/index.mjs";

const C = SAUER_CONSTANTS;

test("world layout pins every catalog constant", () => {
  const w = buildSauerWorld({ hooked: false });
  assert.equal(C.imageBase, 0x00400000n);
  assert.equal(C.clSendInput, 0x004532a0n);
  assert.equal(C.cheatStub, 0x0046f010n);
  // entity array + stride + player index => local player VA
  const player = C.entityArray + BigInt(C.playerIndex * C.entityStride);
  assert.equal(player, 0x021000d0n);
  assert.equal(C.healthOffset, 0x24);
  // world materialized the right pages
  assert.ok(w.mem.hasPage(0x00400000n));
  assert.ok(w.mem.canRead(C.clSendInput, 10));
});

test("cl_sendinput carries the canonical prologue in pristine worlds", () => {
  for (const hooked of [false, true]) {
    const w = buildSauerWorld({ hooked });
    // pristine snapshot must contain the prologue regardless of hooking
    const orig = w.hookscan(); // diffs only; verify via fresh world instead:
    if (!hooked) {
      const live = Array.from(w.mem.read(C.clSendInput, 10));
      assert.deepEqual(live, [0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10]);
    }
  }
});

// ---------------------------------------------------------------- m5.l1 lab

function solveRecon(console) {
  const f1 = console.execute("lm").match(/sauerbraten\.exe/)
    ? console.execute("pe sauerbraten.exe").match(/base: (0x[0-9a-f]+)/)[1]
    : null;

  // scan 1: full health is noisy
  const first = console.execute(`scan 0x02100000 0x12000 100`).split("\n");
  assert.ok(first.length > 5, "first scan should be noisy");

  // oracle: damage filters the live value
  console.execute("!damage 25");
  const survivors = console.execute(`scan 0x02100000 0x12000 75`).split("\n");
  assert.equal(survivors.length, 1, "exactly one live 75 after damage");
  const healthAddr = BigInt(survivors[0]);

  // hexdump around the hit reveals the entity (name visible at +0x2c)
  const dump = console.execute(`x ${survivors[0]} 30`);
  assert.match(dump, /kfgamer/, "entity name visible near health field");

  const f3 = `0x${(healthAddr - 0x021000d0n).toString(16)}`;
  return {
    f1,
    f2: "0x" + (healthAddr - BigInt(C.healthOffset)).toString(16).padStart(8, "0"),
    f3,
  };
}

test("m5.l1 solvable through the console with catalog answers", () => {
  const session = createSogenSession("sauer-recon");
  const con = new SogenConsole(session.world);

  const answers = solveRecon(con);
  assert.equal(answers.f1, "0x00400000");
  assert.equal(answers.f2, "0x021000d0");
  assert.equal(answers.f3, "0x24");
});

test("lm lists deferred system dlls and materialized game image", () => {
  const session = createSogenSession("sauer-recon");
  const out = new SogenConsole(session.world).execute("lm");
  assert.match(out, /sauerbraten\.exe/);
  assert.match(out, /ntdll\.dll.*deferred/s);
  assert.match(out, /opengl32\.dll/);
});

// ---------------------------------------------------------------- m6.l1 lab

test("sauer-hook world has exactly one E9 detour resolvable by hookscan", () => {
  const session = createSogenSession("sauer-hook");
  const con = new SogenConsole(session.world);

  const scan = con.execute("hookscan");
  assert.match(scan, /site 0x004532a0/);
  assert.match(scan, /E9 -> 0x0046f010/);

  // input gate while hooked: angles rewritten, no secret
  const hooked = con.execute("!inputtest");
  assert.match(hooked, /REWRITTEN/);
  assert.doesNotMatch(hooked, /kf-input-restored/);

  // repair with eb using original bytes
  con.execute("eb 0x004532a0 48 89 5c 24 08");
  assert.match(con.execute("hookscan"), /no modifications/);

  const honest = con.execute("!inputtest");
  assert.match(honest, /passthrough OK/);
  assert.match(honest, /kf-input-restored/);
});

test("m6.l1 solvable start to finish with catalog answers", () => {
  const session = createSogenSession("sauer-hook");
  const con = new SogenConsole(session.world);

  const scan = con.execute("hookscan");
  const site = scan.match(/site (0x[0-9a-f]+)/)[1];
  const target = scan.match(/E9 -> (0x[0-9a-f]+)/)[1];
  assert.equal(site, "0x004532a0");
  assert.equal(target, "0x0046f010");

  // restore from the printed original bytes
  const orig = scan.match(/orig: ([0-9a-f ]+)/)[1].trim();
  con.execute(`eb ${site} ${orig}`);
  assert.doesNotMatch(con.execute("hookscan"), /site/);

  const test = con.execute("!inputtest");
  const secret = test.match(/all-clear: (\S+)/)[1];
  assert.equal(secret, "kf-input-restored");
});

test("recon world stays clean and inputtest refuses secrets there too", () => {
  const session = createSogenSession("sauer-recon");
  const con = new SogenConsole(session.world);
  assert.match(con.execute("hookscan"), /no modifications/);
  assert.doesNotMatch(con.execute("!inputtest"), /REWRITTEN/);
});
