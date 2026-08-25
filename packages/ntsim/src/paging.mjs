/**
 * paging.mjs — x64 guest paging for ntsim: 4-level walker, table builder,
 * and a translating SparseMemory facade.
 *
 * Fidelity contract (Intel SDM Vol.3 ch.4):
 *   PML4E -> PDPTE -> PDE -> PTE, 4KB/2MB/1GB pages, canonical 48-bit VAs,
 *   flag bits: P(0) RW(1) US(2) PWT(3) PCD(4) A(5) D(6) PS(7) G(8) NX(63).
 *
 * Memory model:
 *   - The RAW SparseMemory is PHYSICALLY addressed when paging is enabled.
 *     Page tables live there at physical frame addresses.
 *   - `TranslatedMemory` wraps the raw store and implements the identical
 *     SparseMemory surface, translating every VA access through the Mmu
 *     (with a small TLB cache). When CR0.PG is clear it is identity.
 *   - Demand-zero mapping fills unmapped VAs with fresh RW+X supervisor
 *     frames so legacy scenarios keep running under paging; explicit
 *     mapRange() calls refine permissions (NX data, user pages, ...).
 *
 * Page faults raise CpuError whose message matches seh.classifyFault's
 * "#PF / access violation" family, so drivers' own __except handlers work.
 */

import { SparseMemory } from "./memory.mjs";
import { CpuError } from "./cpu.mjs";

const PAGE_SIZE = 4096;
const PAGE_MASK = 0xfffn;

export const PTE = {
  PRESENT: 1n << 0n,
  WRITE: 1n << 1n,
  USER: 1n << 2n,
  PWT: 1n << 3n,
  PCD: 1n << 4n,
  ACCESSED: 1n << 5n,
  DIRTY: 1n << 6n,
  PS: 1n << 7n, // PAT on PTE level
  GLOBAL: 1n << 8n,
  NX: 1n << 63n,
};

/** Canonical x64 VA check (bits 47..63 must be sign-extension). */
export function isCanonical(va) {
  const v = BigInt.asUintN(64, BigInt(va));
  const top = v >> 47n;
  return top === 0n || top === 0x1ffffn;
}

export function canonicalize(va) {
  const v = BigInt.asUintN(64, BigInt(va));
  return (v & (1n << 47n)) ? (v | 0xffff000000000000n) : (v & 0x0000ffffffffffffn);
}

/** Page fault shaped like the backend faults SEH already understands. */
export class PageFault extends CpuError {
  constructor(va, reason, access) {
    super(`page fault (${reason}) ${access} @ va=0x${BigInt.asUintN(64, va).toString(16)} — unmapped memory`, va);
    this.name = "PageFault";
    this.va = BigInt.asUintN(64, va);
    this.reason = reason; // "not present" | "write to read-only" | "supervisor-only" | "NX execute" | "non-canonical"
    this.access = access; // "read" | "write" | "fetch"
  }
}

// ------------------------------------------------------------------- Mmu

export class Mmu {
  /**
   * @param {SparseMemory} raw physically-addressed backing store
   * @param {object} [opts] {frameBase?, demandMap?:boolean}
   */
  constructor(raw, opts = {}) {
    this.raw = raw;
    this.cr0 = 0x80010031n; // PE|MP|NE|ET|WP... PG set by enablePaging()
    this.cr3 = 0n;
    this.cr4 = 0x370678n; // PAE|OSFXSR|OSXMMEXCET|...
    this.efer = 0x500n; // LME|LMA
    /** demand-zero fill for unmapped VAs (RWX supervisor) */
    this.demandMap = opts.demandMap ?? true;
    this.nextFrame = opts.frameBase ?? 0x100000n; // skip low legacy IBV
    this.framesUsed = 0;
    /** @type {{base:bigint,size:bigint}[]} VAs that map PA===VA (SMRAM/TSEG) */
    this.identityRanges = [];
    /** @type {Map<string,{pa:bigint,w:boolean,u:boolean,x:boolean}>} */
    this.tlb = new Map();
    this.tlbLimit = 4096;
    this.lastFault = null;
  }

  get pagingEnabled() {
    return (this.cr0 & 0x80000000n) !== 0n && (this.efer & 0x400n) !== 0n && (this.cr4 & 0x20n) !== 0n;
  }

  enablePaging(cr3Frame) {
    this.cr3 = BigInt(cr3Frame);
    this.cr4 |= 0x20n; // PAE
    this.cr0 |= 0x80000000n; // PG
    this.efer |= 0x500n; // LME|LMA
    this.flushTlb();
  }

  flushTlb() { this.tlb.clear(); }

  // ------------------------------------------------------------- frames

  frameAlloc(count = 1) {
    const pa = this.nextFrame;
    this.nextFrame += BigInt(count) * BigInt(PAGE_SIZE);
    this.framesUsed += count;
    return pa;
  }

  // -------------------------------------------------------------- walk

  #readTableEntry(pa, what, va) {
    const b = this.raw.read(pa, 8);
    const entry = b.reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
    void what; void va;
    return entry;
  }

  #writeTableEntry(pa, value) {
    const out = new Uint8Array(8);
    let v = BigInt(value);
    for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    this.raw.write(pa, out);
    this.flushTlb();
  }

  /**
   * Translate a VA. @param {"read"|"write"|"fetch"} access
   * @returns {{pa:bigint, w:boolean,u:boolean,x:boolean, level:1|2|3|4, ptePa:bigint|null}}
   * @throws {PageFault}
   */
  translate(va, access = "read") {
    const v = BigInt.asUintN(64, BigInt(va));
    if (!isCanonical(v)) {
      this.lastFault = new PageFault(v, "non-canonical", access);
      throw this.lastFault;
    }

    const key = `${v >> 12n}|${access}`;
    const hit = this.tlb.get(key);
    if (hit) {
      // cache holds the FRAME base — re-apply this access's page offset
      const offMask = hit.level === 1 ? PAGE_MASK
        : hit.level === 3 ? (1n << 30n) - 1n : (1n << 21n) - 1n;
      return { ...hit, pa: hit.paBase | (v & offMask) };
    }

    const pml4Base = this.cr3 & 0x000ffffffffff000n;
    const indexes = [
      (v >> 39n) & 0x1ffn,
      (v >> 30n) & 0x1ffn,
      (v >> 21n) & 0x1ffn,
      (v >> 12n) & 0x1ffn,
    ];

    let tablePa = pml4Base;
    let level = 4;
    let entry = 0n;
    let ptePa = null;

    for (;;) {
      const idxIdx = 4 - level;
      const entryPa = tablePa + BigInt(indexes[idxIdx]) * 8n;
      entry = this.#readTableEntry(entryPa);
      if ((entry & PTE.PRESENT) === 0n) {
        this.lastFault = new PageFault(v, "not present", access);
        throw this.lastFault;
      }
      if (level > 1 && (entry & PTE.PS) !== 0n) break; // large page here
      if (level === 1) { ptePa = entryPa; break; }     // leaf 4KB PTE
      tablePa = entry & 0x000ffffffffff000n;
      level--;
    }

    // compose physical address + effective permissions
    let paBase, offMask;
    if (level === 1) {
      paBase = entry & 0x000ffffffffff000n;
      offMask = PAGE_MASK;
    } else {
      // large page: stopped AT `level`, entry holds the frame base
      const shift = level === 3 ? 30n : 21n;
      paBase = entry & 0x000ffffffffff000n;
      offMask = (1n << shift) - 1n;
    }
    const w = (entry & PTE.WRITE) !== 0n;
    const u = (entry & PTE.USER) !== 0n;
    const x = (entry & PTE.NX) === 0n;

    const result = { pa: BigInt.asUintN(64, paBase | (v & offMask)), paBase, w, u, x, level, ptePa };
    // permission enforcement (single ring-0 subject today)
    if (access === "write" && !w) {
      this.lastFault = new PageFault(v, "write to read-only", access);
      throw this.lastFault;
    }
    if (access === "fetch" && !x) {
      this.lastFault = new PageFault(v, "NX execute", access);
      throw this.lastFault;
    }

    if (this.tlb.size < this.tlbLimit) this.tlb.set(key, result);
    // set A/D bits best-effort on the leaf
    try {
      if (ptePa !== null) {
        const cur = this.#readTableEntry(ptePa);
        if ((cur & PTE.ACCESSED) === 0n) {
          this.#writeTableEntry(ptePa, cur | PTE.ACCESSED | (access === "write" ? PTE.DIRTY : 0n));
        } else if (access === "write" && (cur & PTE.DIRTY) === 0n) {
          this.#writeTableEntry(ptePa, cur | PTE.DIRTY);
        }
      }
    } catch { /* A/D bookkeeping never fatal */ }
    return result;
  }

  /**
   * Ensure [va, va+len) is mapped, demand-allocating whole pages with
   * default flags. Used by TranslatedMemory before accesses that missed.
   * VAs inside identityRanges map PA===VA (SMRAM/TSEG windows).
   */
  ensureRange(va, len, flags = { w: true, u: false, x: true }) {
    let cur = BigInt.asUintN(64, BigInt(va)) & ~PAGE_MASK;
    const end = (BigInt.asUintN(64, BigInt(va)) + BigInt(len) - 1n) & ~PAGE_MASK;
    for (; cur <= end; cur += BigInt(PAGE_SIZE)) {
      if (this.lookup(cur)) continue;
      const ident = this.#identityPaFor(cur);
      if (ident !== null) {
        this.mapPage(cur, ident, { present: true, write: flags.w ?? true, user: false, nx: !flags.x, global: false });
        if (!this.raw.hasPage(ident)) {
          this.raw.write(ident, new Uint8Array(PAGE_SIZE)); // zero-back the frame
        }
        continue;
      }
      this.mapPage(cur, this.frameAlloc(), {
        present: true, write: flags.w ?? true, user: flags.u ?? false, nx: !flags.x, global: false,
      });
    }
  }

  #identityPaFor(va) {
    const v = BigInt.asUintN(64, BigInt(va));
    for (const r of this.identityRanges) {
      if (v >= r.base && v < r.base + r.size) return v & ~PAGE_MASK;
    }
    return null;
  }

  /** Non-throwing probe: returns translation or null. */
  lookup(va) {
    try {
      const saved = this.demandMap;
      this.demandMap = false;
      try { return this.translate(va, "read"); } finally { this.demandMap = saved; }
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------- builder

  /**
   * Create a fresh page-table hierarchy rooted at a newly allocated PML4.
   * @returns {bigint} cr3 physical frame base
   */
  newAddressSpace() {
    const pml4 = this.frameAlloc();
    this.raw.write(pml4, new Uint8Array(PAGE_SIZE)); // empty = nothing mapped
    return pml4;
  }

  /**
   * Map one 4KB page. Flags: {present,write,user,nx,global}
   */
  mapPage(va, pa, flags = {}) {
    const v = canonicalize(va) & ~PAGE_MASK;
    const pml4Base = this.cr3 & 0x000ffffffffff000n;
    const idx = [
      (v >> 39n) & 0x1ffn,
      (v >> 30n) & 0x1ffn,
      (v >> 21n) & 0x1ffn,
      (v >> 12n) & 0x1ffn,
    ];
    let tablePa = pml4Base;
    for (let lvl = 4; lvl >= 2; lvl--) {
      const ePa = tablePa + BigInt(idx[4 - lvl]) * 8n;
      const e = this.#readTableEntry(ePa);
      if ((e & PTE.PRESENT) === 0n) {
        const nt = this.frameAlloc();
        this.raw.write(nt, new Uint8Array(PAGE_SIZE));
        this.#writeTableEntry(ePa, (nt & 0x000ffffffffff000n) | PTE.PRESENT | PTE.WRITE | PTE.USER);
      }
      tablePa = this.#readTableEntry(ePa) & 0x000ffffffffff000n;
    }
    let f = PTE.PRESENT | PTE.ACCESSED | PTE.DIRTY;
    if (flags.write ?? true) f |= PTE.WRITE;
    if (flags.user ?? false) f |= PTE.USER;
    if (flags.nx ?? false) f |= PTE.NX;
    if (flags.global ?? false) f |= PTE.GLOBAL;
    this.#writeTableEntry(tablePa + BigInt(idx[3]) * 8n, (BigInt(pa) & 0x000ffffffffff000n) | f);
  }

  unmap(va) {
    const v = canonicalize(va) & ~PAGE_MASK;
    const t = this.walkToPte(v);
    if (t) this.#writeTableEntry(t, 0n);
  }

  /** Physical address of the leaf PTE slot for va, or null. */
  walkToPte(va) {
    const v = canonicalize(va) & ~PAGE_MASK;
    const pml4Base = this.cr3 & 0x000ffffffffff000n;
    const idx = [
      (v >> 39n) & 0x1ffn, (v >> 30n) & 0x1ffn, (v >> 21n) & 0x1ffn, (v >> 12n) & 0x1ffn,
    ];
    let tablePa = pml4Base;
    for (let lvl = 4; lvl >= 2; lvl--) {
      const ePa = tablePa + BigInt(idx[4 - lvl]) * 8n;
      const e = this.#readTableEntry(ePa);
      if ((e & PTE.PRESENT) === 0n) return null;
      tablePa = e & 0x000ffffffffff000n;
    }
    return tablePa + BigInt(idx[3]) * 8n;
  }

  /** Read raw PTE for va (or null). */
  readPte(va) {
    const ptePa = this.walkToPte(va);
    return ptePa === null ? null : this.#readTableEntry(ptePa);
  }

  /**
   * Identity-frame map of a VA range: allocate contiguous frames, copy
   * optional bytes in. Returns first frame pa.
   */
  allocAndMap(vaStart, pageCount, bytesIn = null, flags = {}) {
    const pa0 = this.frameAlloc(pageCount);
    for (let i = 0; i < pageCount; i++) {
      this.mapPage(BigInt(vaStart) + BigInt(i) * BigInt(PAGE_SIZE), pa0 + BigInt(i) * BigInt(PAGE_SIZE), flags);
      const off = i * PAGE_SIZE;
      if (bytesIn && off < bytesIn.length) {
        this.raw.write(pa0 + BigInt(off), bytesIn.subarray(off, Math.min(bytesIn.length, off + PAGE_SIZE)));
      }
    }
    return pa0;
  }
}

// ---------------------------------------------------- TranslatedMemory

/**
 * SparseMemory-compatible facade over the RAW store: every address-bearing
 * operation goes through the MMU when paging is enabled, else identity.
 * Subclassing keeps dump()/pages/dirty semantics working unchanged for all
 * existing consumers (cpu, kernel model, debugger, snapshots).
 */
export class TranslatedMemory extends SparseMemory {
  /** @type {Mmu|null} */
  #mmu = null;
  /** guard hook (WP5 SMRAM): (va, write) => true when access must fault */
  accessGuard = null;

  attach(mmu) {
    this.#mmu = mmu;
    mmu.flushTlb();
  }

  get mmu() { return this.#mmu; }
  get rawMem() { return this.#mmu ? this.#mmu.raw : this; }

  #xlate(addr, write) {
    const mmu = this.#mmu;
    if (this.accessGuard && this.accessGuard(BigInt(addr), write)) {
      throw new PageFault(BigInt(addr), "not present", write ? "write" : "read");
    }
    if (!mmu || !mmu.pagingEnabled) return BigInt.asUintN(64, BigInt(addr));
    try {
      return mmu.translate(BigInt(addr), write ? "write" : "read").pa;
    } catch (e) {
      if (e instanceof PageFault && mmu.demandMap && e.reason === "not present") {
        mmu.ensureRange(BigInt(addr), 1);
        return mmu.translate(BigInt(addr), write ? "write" : "read").pa;
      }
      throw e;
    }
  }

  #xlateFetch(addr) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) return BigInt.asUintN(64, BigInt(addr));
    try {
      return mmu.translate(BigInt(addr), "fetch").pa;
    } catch (e) {
      if (e instanceof PageFault && mmu.demandMap && e.reason === "not present") {
        mmu.ensureRange(BigInt(addr), 1);
        return mmu.translate(BigInt(addr), "fetch").pa;
      }
      throw e;
    }
  }

  // -- overridden span ops -------------------------------------------------

  read(addr, len) {
    const mmu = this.#mmu;
    // single source of truth: everything lands in the RAW store
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      const out = dst.read(BigInt.asUintN(64, BigInt(addr)), len);
      this.stats.reads++;
      return out;
    }
    // translate per-page so spans crossing pages each get their own PA
    const out = new Uint8Array(len);
    let done = 0;
    let a = BigInt.asUintN(64, BigInt(addr));
    while (done < len) {
      const off = Number(a & PAGE_MASK);
      const chunk = Math.min(PAGE_SIZE - off, len - done);
      const pa = this.#xlate(a, false);
      out.set(this.rawMem.read(pa, chunk), done);
      a += BigInt(chunk); done += chunk;
    }
    this.stats.reads++;
    return out;
  }

  write(addr, bytes) {
    const src = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      dst.write(BigInt.asUintN(64, BigInt(addr)), src);
      this.stats.writes++;
      return;
    }
    let done = 0;
    let a = BigInt.asUintN(64, BigInt(addr));
    while (done < src.length) {
      const off = Number(a & PAGE_MASK);
      const chunk = Math.min(PAGE_SIZE - off, src.length - done);
      const pa = this.#xlate(a, true);
      this.rawMem.write(pa, src.subarray(done, done + chunk));
      a += BigInt(chunk); done += chunk;
    }
    this.stats.writes++;
  }

  // fetch path used by the interpreter (execute permission enforced)
  fetchBytes(addr, len) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      return dst.read(BigInt.asUintN(64, BigInt(addr)), len);
    }
    return this.rawMem.read(this.#xlateFetch(addr), len);
  }

  hasPage(addr) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      return dst.hasPage(addr);
    }
    const t = mmu.lookup(addr);
    return !!t && this.rawMem.hasPage(t.pa);
  }

  canRead(addr, len = 1) {
    const mmu = this.#mmu;
    if (!mmu || !mmu.pagingEnabled) {
      const dst = this.rawMem === this ? this : this.rawMem;
      return dst.canRead(addr, len);
    }
    let cur = BigInt.asUintN(64, BigInt(addr));
    const end = cur + BigInt(len);
    while (cur < end) {
      const t = mmu.lookup(cur);
      if (!t || !this.rawMem.hasPage(t.pa)) return false;
      cur = (cur & ~BigInt(PAGE_MASK)) + BigInt(PAGE_SIZE);
    }
    return true;
  }
}
