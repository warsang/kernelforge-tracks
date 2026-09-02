/**
 * @kernelforge/halfix-lab — disk chunk backend (Phase 6 fix)
 *
 * Halfix stores disk images as 256 KiB chunks:
 *   chunk_index = floor(offset / 262144)
 *   chunk_offset = offset % 262144
 *
 * Original browser backend (`runtime.js` / `libhalfix.js`) used 32-bit-bounded
 * arithmetic (`|0`, `>>>0`, `<<18`) which caps addressable space at ~4 GiB
 * even though the on-disk format theoretically supports 2^50 bytes (1 TiB).
 * Windows 10 x86 needs ~16 GiB minimum, so we must widen.
 *
 * This module provides the *correct* arithmetic and a chunked IndexedDB/File
 * store used by the WASM frontend. It also powers the synthetic 6-8 GiB test.
 */

export const CHUNK_SIZE = 256 * 1024; // 262144
export const CHUNK_SHIFT = 18; // 2^18 = 262144

/**
 * Fixed: uses Number (safe up to 2^53-1 ~ 9 PB) instead of 32-bit truncation.
 * For future >2^53 images use BigInt variant below.
 */
export function chunkIndex(offset) {
  // offset may be Number or BigInt
  if (typeof offset === "bigint") {
    return Number(offset / BigInt(CHUNK_SIZE));
  }
  return Math.floor(offset / CHUNK_SIZE);
}

export function chunkOffset(offset) {
  if (typeof offset === "bigint") {
    return Number(offset % BigInt(CHUNK_SIZE));
  }
  return offset % CHUNK_SIZE;
}

// BigInt variant for >2^53 images (theoretical 1 TiB+)
export function chunkIndexBig(offset) {
  const bi = typeof offset === "bigint" ? offset : BigInt(Math.floor(offset));
  return bi / BigInt(CHUNK_SIZE);
}

// Original buggy helpers — kept for regression test comparison
export function chunkIndex32(offset) {
  // eslint-disable-next-line no-bitwise
  return (offset / CHUNK_SIZE) | 0; // truncates to 32-bit signed
}
export function chunkIndexU32(offset) {
  // eslint-disable-next-line no-bitwise
  return ((offset / CHUNK_SIZE) >>> 0);
}

// File-backed chunking: slice a File into 256 KiB blocks without loading all
export function sliceFileChunk(file, index) {
  const start = index * CHUNK_SIZE;
  const end = Math.min(start + CHUNK_SIZE, file.size);
  if (start >= file.size) return null;
  return file.slice(start, end);
}

// IndexedDB chunk store (idb-keyval) — mirrors v86-lab file injection pattern
// Keys: `halfix:chunk:<imageId>:<hexIndex>`, meta: `halfix:meta:<imageId>`
import { get, set, del, keys } from "idb-keyval";

function chunkKey(imageId, index) {
  return `halfix:chunk:${imageId}:${index.toString(16).padStart(8, "0")}`;
}
function metaKey(imageId) {
  return `halfix:meta:${imageId}`;
}

export async function storeChunk(imageId, index, data) {
  await set(chunkKey(imageId, index), data);
}

export async function loadChunk(imageId, index) {
  return await get(chunkKey(imageId, index));
}

export async function storeMeta(imageId, meta) {
  await set(metaKey(imageId), meta);
}

export async function loadMeta(imageId) {
  return await get(metaKey(imageId));
}

export async function clearImage(imageId) {
  const all = await keys();
  const prefix = `halfix:chunk:${imageId}:`;
  const meta = metaKey(imageId);
  for (const k of all) {
    if (typeof k === "string" && (k.startsWith(prefix) || k === meta)) {
      await del(k);
    }
  }
}

/**
 * Ingest a File into chunked IndexedDB store. Reports progress via onProgress.
 * Returns { chunks, size, chunkSize }
 */
export async function ingestFile(imageId, file, onProgress) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  let stored = 0;
  // Clear previous ingestion for this imageId
  await clearImage(imageId);

  for (let i = 0; i < totalChunks; i++) {
    const slice = sliceFileChunk(file, i);
    if (!slice) break;
    const buf = await slice.arrayBuffer();
    await storeChunk(imageId, i, new Uint8Array(buf));
    stored++;
    if (onProgress && i % 16 === 0) {
      onProgress(i + 1, totalChunks);
    }
  }
  const meta = {
    size: file.size,
    chunks: totalChunks,
    chunkSize: CHUNK_SIZE,
    name: file.name,
    ingestedAt: Date.now(),
  };
  await storeMeta(imageId, meta);
  if (onProgress) onProgress(totalChunks, totalChunks);
  return meta;
}

/**
 * Read arbitrary byte range from chunked store (handles cross-chunk spans)
 * Used by Halfix drive emulation in the browser.
 */
export async function readRange(imageId, offset, length) {
  const startChunk = chunkIndex(offset);
  const endChunk = chunkIndex(offset + length - 1);
  const out = new Uint8Array(length);
  let outOff = 0;
  let curOff = offset;

  for (let ci = startChunk; ci <= endChunk; ci++) {
    const chunk = await loadChunk(imageId, ci);
    if (!chunk) {
      // sparse zero fill (matches raw sparse image semantics)
      const chunkStart = ci * CHUNK_SIZE;
      const from = Math.max(curOff, chunkStart);
      const to = Math.min(offset + length, chunkStart + CHUNK_SIZE);
      const fillLen = to - from;
      // out already zero-filled
      outOff += fillLen;
      curOff += fillLen;
      continue;
    }
    const chunkStart = ci * CHUNK_SIZE;
    const from = Math.max(curOff, chunkStart);
    const to = Math.min(offset + length, chunkStart + CHUNK_SIZE);
    const sliceOff = from - chunkStart;
    const len = to - from;
    out.set(chunk.subarray(sliceOff, sliceOff + len), outOff);
    outOff += len;
    curOff += len;
  }
  return out;
}

/**
 * Write arbitrary byte range into chunked store (handles cross-chunk spans)
 */
export async function writeRange(imageId, offset, data) {
  const length = data.length;
  const startChunk = chunkIndex(offset);
  const endChunk = chunkIndex(offset + length - 1);
  let dataOff = 0;
  let curOff = offset;

  for (let ci = startChunk; ci <= endChunk; ci++) {
    const chunkStart = ci * CHUNK_SIZE;
    const from = Math.max(curOff, chunkStart);
    const to = Math.min(offset + length, chunkStart + CHUNK_SIZE);
    const sliceOff = from - chunkStart;
    const len = to - from;

    let chunk = await loadChunk(imageId, ci);
    if (!chunk) {
      // allocate zero-filled chunk
      chunk = new Uint8Array(CHUNK_SIZE);
    } else if (chunk.length !== CHUNK_SIZE) {
      // last chunk may be short — pad
      const padded = new Uint8Array(CHUNK_SIZE);
      padded.set(chunk);
      chunk = padded;
    }
    chunk.set(data.subarray(dataOff, dataOff + len), sliceOff);
    await storeChunk(imageId, ci, chunk);

    dataOff += len;
    curOff += len;
  }

  // update meta size if we extended
  const meta = await loadMeta(imageId);
  if (meta) {
    const newSize = Math.max(meta.size, offset + length);
    const newChunks = Math.ceil(newSize / CHUNK_SIZE);
    if (newChunks !== meta.chunks || newSize !== meta.size) {
      await storeMeta(imageId, { ...meta, size: newSize, chunks: newChunks });
    }
  }
}

/**
 * Totally synthetic test helpers — create a sparse image larger than 4GiB
 * without allocating the full buffer. Used for Phase 6 verification.
 */
export function syntheticImageSize(bytes) {
  return { size: bytes, chunks: Math.ceil(bytes / CHUNK_SIZE), chunkSize: CHUNK_SIZE };
}

// Helper to verify the 32-bit bug: indices beyond 4GiB should wrap with |0 but not with fixed version
export function verify32BitBug() {
  const off4g = 4 * 1024 * 1024 * 1024; // 0x100000000
  const off6g = 6 * 1024 * 1024 * 1024; // 0x180000000
  const off8g = 8 * 1024 * 1024 * 1024;
  return {
    off4g: { expected: off4g / CHUNK_SIZE, buggy: chunkIndex32(off4g), fixed: chunkIndex(off4g) },
    off6g: { expected: off6g / CHUNK_SIZE, buggy: chunkIndex32(off6g), fixed: chunkIndex(off6g) },
    off8g: { expected: off8g / CHUNK_SIZE, buggy: chunkIndex32(off8g), fixed: chunkIndex(off8g) },
  };
}
