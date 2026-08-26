/**
 * Glossary data quality: coverage, hygiene, and lookup behavior.
 * These guard the tooltip pipeline's source of truth.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  glossary, commandDocs, findTermEntry, normalizeTermKey, buildTermPattern,
} from "../src/index.mjs";

const ENTRIES = Object.values(glossary);
const COMMANDS = Object.values(commandDocs);

test("glossary has substantial coverage", () => {
  assert.ok(ENTRIES.length >= 40, `expected >=40 concept entries, got ${ENTRIES.length}`);
  assert.ok(COMMANDS.length >= 10, `expected >=10 command entries, got ${COMMANDS.length}`);
});

test("requested terms are present with expansions", () => {
  for (const key of ["hal", "irql", "pml4", "dkom", "eprocess", "dpc", "ntstatus", "iat"]) {
    const e = glossary[key];
    assert.ok(e, `missing glossary.${key}`);
    if (/[A-Z]{2,}/.test(e.term)) {
      assert.ok(e.full, `${key}: all-caps term should have a full expansion`);
      assert.ok(!e.full.includes(e.term), `${key}: full should not repeat the abbreviation itself`);
    }
  }
});

test("every entry: def is a real sentence, term is non-empty", () => {
  for (const [key, e] of [...Object.entries(glossary), ...Object.entries(commandDocs)]) {
    assert.ok(e.term && e.term.trim(), `${key}: empty term`);
    assert.ok(e.def && e.def.length >= 30, `${key}: def too short`);
    assert.match(e.def, /[.!?]['")\]]?$/, `${key}: def should end with sentence punctuation`);
  }
});

test("no surface-form collisions across terms + aliases", () => {
  // index() throws at import time on collisions; assert it stays silent by
  // re-verifying here so failures point at this suite.
  const seen = new Map();
  const check = (surface, owner) => {
    const norm = normalizeTermKey(surface);
    assert.ok(!seen.has(norm), `collision: "${norm}" used by ${seen.get(norm)} and ${owner.key}`);
    seen.set(norm, owner);
  };
  for (const e of ENTRIES) {
    check(e.term, e);
    for (const a of e.aliases ?? []) check(a, e);
  }
  for (const c of COMMANDS) {
    check(c.term, c); // commands may overlap concepts? no — keep namespaces clean
  }
});

test("normalizeTermKey strips nt! prefix and leading underscores", () => {
  assert.equal(normalizeTermKey("_EPROCESS"), "eprocess");
  assert.equal(normalizeTermKey("nt!_EPROCESS"), "eprocess");
  assert.equal(normalizeTermKey("__X"), "x");
});

test("findTermEntry resolves prose forms, code forms and plurals", () => {
  assert.equal(findTermEntry("HAL")?.key, "hal");
  assert.equal(findTermEntry("PML4")?.key, "pml4");
  assert.equal(findTermEntry("_EPROCESS")?.key, "eprocess");
  assert.equal(findTermEntry("nt!_EPROCESS")?.key, "eprocess");
  assert.equal(findTermEntry("pools")?.key, "pool");
  assert.equal(findTermEntry("DISPATCH_LEVEL")?.key, "dispatch_level");
  assert.equal(findTermEntry("!irql")?.key, "!irql"); // command namespace
  assert.equal(findTermEntry("totally unknown term"), null);
  assert.equal(findTermEntry(""), null);
});

test("buildTermPattern excludes debugger commands but keeps aliases", () => {
  const p = buildTermPattern();
  // Aliases (any case) are emitted verbatim; "Interrupt ReQuest Level" is
  // stored lowercase, and matching is case-insensitive downstream.
  assert.ok(p.toLowerCase().includes("interrupt request level"));
  assert.ok(!p.includes("\\!"), "commands must not leak into the prose pattern");
  // longest-first ordering
  const parts = p.split("|").map((s) => s.replace(/\\/g, ""));
  const idx = (f) => parts.findIndex((x) => x.toLowerCase() === f.toLowerCase());
  assert.ok(idx("Interrupt ReQuest Level") < idx("IRQL"), "longer alias must sort before short form");
});
