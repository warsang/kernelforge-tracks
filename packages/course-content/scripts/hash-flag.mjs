#!/usr/bin/env node
// Computes the sha256 of a flag string so content authors never commit plaintext.
// Usage: node hash-flag.mjs 'FLAG{...}'
import { createHash } from "node:crypto";

const flag = process.argv[2];
if (!flag) {
  console.error("usage: node hash-flag.mjs '<flag string>'");
  process.exit(1);
}
console.log(createHash("sha256").update(flag, "utf8").digest("hex"));
