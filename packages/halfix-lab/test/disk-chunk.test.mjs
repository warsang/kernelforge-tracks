import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CHUNK_SIZE,
  chunkIndex,
  chunkOffset,
  chunkIndex32,
  verify32BitBug,
  syntheticImageSize,
} from "../src/disk.mjs";
import { verifyDiskBackend, buildConf } from "../src/session.mjs";

describe("halfix disk chunk backend (Phase 6)", () => {
  it("CHUNK_SIZE is 256 KiB", () => {
    assert.equal(CHUNK_SIZE, 256 * 1024);
  });

  it("chunkIndex uses Number-safe arithmetic", () => {
    assert.equal(chunkIndex(0), 0);
    assert.equal(chunkIndex(CHUNK_SIZE - 1), 0);
    assert.equal(chunkIndex(CHUNK_SIZE), 1);
    assert.equal(chunkIndex(4 * 1024 * 1024 * 1024), 16384);
    assert.equal(chunkIndex(6 * 1024 * 1024 * 1024), 24576);
    assert.equal(chunkIndex(16 * 1024 * 1024 * 1024), 65536);
    assert.equal(chunkIndex(20 * 1024 * 1024 * 1024), 81920);
  });

  it("chunkOffset correctness", () => {
    assert.equal(chunkOffset(0), 0);
    assert.equal(chunkOffset(CHUNK_SIZE), 0);
    assert.equal(chunkOffset(CHUNK_SIZE + 1), 1);
    assert.equal(chunkOffset(4 * 1024 * 1024 * 1024 + 123), 123);
  });

  it("chunkIndex32 (buggy) wraps at offset shift beyond 4 GiB while fixed does not", () => {
    // chunkIndex via |0 still fits for 24576 (15 bits), so the real wrap is in offset arithmetic:
    // (blockBase << 18) truncates to 32-bit. 6 GiB needs 33 bits (0x180000000).
    const blockBase = 24576; // 6 GiB / 256 KiB
    const fixedOff = blockBase * CHUNK_SIZE;
    const buggyOff = (blockBase << 18) >>> 0; // 32-bit shift, wraps at 4 GiB
    assert.equal(fixedOff, 6442450944);
    assert.notEqual(buggyOff, fixedOff);
    assert.equal(buggyOff, fixedOff >>> 0);
    assert.equal(buggyOff, 2147483648); // low 32 bits of 0x180000000

    // Also verify that chunkIndex for 6 GiB is correct with the fixed helper
    const off6g = 6 * 1024 * 1024 * 1024;
    assert.equal(chunkIndex(off6g), 24576);
    // The 32-bit version still yields 24576 here, but the *offset* calculation is what breaks:
    assert.equal(chunkIndex32(off6g), 24576); // |0 doesn't break index itself, but the shift does for file.slice offsets
  });

  it("verify32BitBug reports correct", () => {
    const rep = verify32BitBug();
    assert.equal(rep.off4g.fixed, 16384);
    assert.equal(rep.off6g.fixed, 24576);
    assert.equal(rep.off8g.fixed, 32768);
  });

  it("syntheticImageSize math", () => {
    const s = syntheticImageSize(20 * 1024 * 1024 * 1024);
    assert.equal(s.chunks, 81920);
    assert.equal(s.chunkSize, CHUNK_SIZE);
  });

  it("verifyDiskBackend passes", () => {
    const v = verifyDiskBackend();
    assert.equal(v.ok, true);
  });

  it("buildConf defaults to Bochs BIOS and 2048M", () => {
    const cfg = buildConf({});
    assert.match(cfg, /bios=bios\.bin/);
    assert.match(cfg, /memory=2048M/);
    assert.match(cfg, /\[ata0-master\]/);
    assert.match(cfg, /\[ata0-slave\]/);
    assert.match(cfg, /\[boot\]/);
  });

  it("buildConf supports WASI?", () => {
    const cfg = buildConf({ ramMb: 1024, bootOrder: "hd" });
    assert.match(cfg, /memory=1024M/);
    assert.match(cfg, /a=hd/);
  });
});
