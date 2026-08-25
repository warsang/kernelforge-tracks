/**
 * ntsim paging model: a real x64-4-level page-table layer over SparseMemory.
 *
 * Design notes:
 * - Page-table frames live at LOW physical addresses (default base 0x300000)
 *   so worlds built on NtKernel({bases}) low-memory layouts stay under bit 47
 *   and run identically under the JsInterpreter and the Unicorn/QEMU backend
 *   (see packages/ntsim-unicorn/src/backend.mjs softmmu limitation).
 * - Every DTB installs a SELF-REFERENCING PML4 entry (index configurable,
 *   default 0xF in emulated layouts; real Windows uses 0x1ED). Through the
 *   self-map, page-table memory is readable/writable at computable VAs with
 *   plain dq/eb — exactly how Windows manages PTEs from virtual memory
 *   (coresecurity "Getting Physical", connormcgarr paging write-ups).
 * - The walker mirrors kdmp.mjs virtTranslate semantics: present-bit checks
 *   per level, PS-bit large pages (1GB at PDPT, 2MB at PD).
 * - All state is ordinary sparse pages: both CPU backends observe identical
 *   bytes; nothing here executes code, so it is backend-neutral by design.
 */

export const PAGE_SIZE = 0x1000;

/** Hardware PTE bits we model (x64 long-mode format). */
export const PTE_BIT = {
  PRESENT: 1n << 0n,
  WRITABLE: 1n << 1n,
  USER: 1n << 2n,
  WRITE_THROUGH: 1n << 3n,
  CACHE_DISABLE: 1n << 4n,
  ACCESSED: 1n << 5n,
  DIRTY: 1n << 6n,
  LARGE: 1n << 7n,
  GLOBAL: 1n << 8n,
  NX: 1n << 63n,
};

const CANON_HIGH = 0xffff000000000000n;
const CANON_LOW = 0x0000ffff00000000n;

/**
 * Split a virtual address into the 9/9/9/9/12 index fields.
 * Accepts BigInt or numeric-string input; returns Number indices + offset.
 */
export function splitVa(va) {
  const v = BigInt(va);
  return {
    offset: Number(v & 0xfffn),
    ptIndex: Number((v >> 12n) & 0x1ffn),
    pdIndex: Number((v >> 21n) & 0x1ffn),
    pdPtIndex: Number((v >> 30n) & 0x1ffn),
    pml4Index: Number((v >> 39n) & 0x1ffn),
  };
}

/**
 * Compose a VA from index fields with canonical sign-extension of bit 47.
 * joinVa(0xf,0xf,0xf,0xf,0) with high=true => 0xfffffffffffff000 style.
 */
export function joinVa(pml4Index, pdPtIndex, pdIndex, ptIndex, offset, high = true) {
  let v = (BigInt(pml4Index) << 39n) | (BigInt(pdPtIndex) << 30n) |
    (BigInt(pdIndex) << 21n) | (BigInt(ptIndex) << 12n) | (BigInt(offset) & 0xfffn);
  if (high && (v & CANON_LOW)) v |= CANON_HIGH;
  return v;
}

/** Decode a hardware PTE into named bits + frame info. */
export function decodePte(value) {
  const v = BigInt.asUintN(64, BigInt(value));
  return {
    raw: v,
    present: !!(v & PTE_BIT.PRESENT),
    writable: !!(v & PTE_BIT.WRITABLE),
    user: !!(v & PTE_BIT.USER),
    accessed: !!(v & PTE_BIT.ACCESSED),
    dirty: !!(v & PTE_BIT.DIRTY),
    large: !!((v >> 7n) & 1n),
    global: !!(v & PTE_BIT.GLOBAL),
    nx: !!(v & PTE_BIT.NX),
    pfn: v >> 12n,
    frame: (v >> 12n) << 12n,
  };
}

/** WinDbg-style letter string for the low 12 bits: "--A--KRV" ordering is
 *  C G L D A N T U W V (MS docs "!pte" table), plus explicit NX marker. */
export function pteBitsString(value) {
  const v = BigInt.asUintN(64, BigInt(value));
  const c = ["C", "G", "L", "D", "A", "N", "T", "-", "W", "V"];
  const set = [0x200n, 0x100n, 0x80n, 0x40n, 0x20n, 0x10n, 0x8n, 0n, 0x2n, 0x1n];
  let s = "";
  for (let i = 0; i < set.length; i++) {
    if (i === 7) { s += (v & 0x4n) ? "U" : "K"; continue; }
    s += (v & set[i]) ? c[i] : "-";
  }
  return s + ((v & PTE_BIT.NX) ? " NX" : " X");
}

/**
 * Self-map alias windows. Real x64 Windows materializes page-table memory
 * in virtual space through the self-referencing PML4 entry (index 0x1ED,
 * yielding the famous PTE space at 0xFFFFF68000000000 — see lesson prose).
 * Emulating that exactly would require translating EVERY memory access, so
 * ntsim exposes equivalent, computable alias WINDOWS instead: one 4K window
 * per table, addressed by its position in the tree and mirrored 1:1 onto
 * the physical frame. Index math stays a pure 9-bit exercise, and dq/eb
 * through a window touches real backing bytes.
 *
 * With selfRefIndex `s` (kept below 0x1FF; low-memory layouts keep the whole
 * range under bit 47 for unicorn parity) and reserved sentinel 0x1FF:
 *   PML4 window:            va(s, 1FF, 1FF, 1FF, 0)
 *   PDPT#a window:          va(s, a,   1FF, 1FF, 0)
 *   PD#a,b window:          va(s, a,   b,   1FF, 0)
 *   PT#a,b,c window:        va(s, a,   b,   c,   0)
 * Entry N sits at windowBase + N*8. Paths containing index 0x1FF are
 * rejected (they would fold into a parent window).
 */
export const SELF_MAP_SENTINEL = 0x1ff;

export function selfMapVas(selfRefIndex, high = false) {
  const s = BigInt(selfRefIndex);
  const T = BigInt(SELF_MAP_SENTINEL);
  const mk = (a, b, c, d) => joinVa(s, a, b, c, d, high);
  return {
    pml4Base: mk(T, T, T, 0n),
    pdptBase: (a) => mk(BigInt(a), T, T, 0n),
    pdBase: (a, b) => mk(BigInt(a), BigInt(b), T, 0n),
    ptBase: (a, b, c) => mk(BigInt(a), BigInt(b), BigInt(c), 0n),
    pml4e: (idx) => mk(T, T, T, BigInt(idx) * 8n),
    pdpte: (a, y) => mk(BigInt(a), T, T, BigInt(y) * 8n),
    pde: (a, b, z) => mk(BigInt(a), BigInt(b), T, BigInt(z) * 8n),
    pte: (a, b, c, w) => mk(BigInt(a), BigInt(b), BigInt(c), BigInt(w) * 8n),
  };
}

/**
 * A collection of per-process page tables over SparseMemory.
 * Attached to scenarios as `kernel.paging`; debugger commands (!cr3, !pte,
 * !vtop) read it when present.
 */
export class PageTableSpace {
  /**
   * @param {import("./kernel.mjs").NtKernel} kernel
   * @param {{physBase?: bigint, selfRefIndex?: number|bigint,
   *          canonicalHigh?: boolean}} opts
   */
  constructor(kernel, opts = {}) {
    this.kernel = kernel;
    this.mem = kernel.mem;
    this.nextFrame = opts.physBase ?? 0x300000n;
    this.defaultSelfRefIndex = BigInt(opts.selfRefIndex ?? 0xf);
    // Canonical half used by self-map VAs. Low-memory (unicorn-safe) worlds
    // keep false; worlds mirroring true kernel VAs may set true.
    this.canonicalHigh = opts.canonicalHigh ?? false;
    /** @type {Map<string, object>} name -> process record */
    this.processes = new Map();
    /** frames handed out (physical base addrs) — used by scans/heuristics */
    this.frames = [];
    /**
     * Structure-frame -> self-map alias page. SparseMemory is flat, so the
     * classic "PTEs live in virtual memory" identity is materialized as a
     * mirrored page: dq/eb through the alias VA touch real backing bytes,
     * and walks sync aliases back before reading physical entries.
     * @type {Map<bigint, {base: bigint}>} framePa -> alias page base
     */
    this.mirrors = new Map();
    /** scenario hook fired once a corrupted PTE is repaired correctly */
    this.onHealed = null;
  }

  /** Register a freshly allocated STRUCTURE frame together with its alias. */
  _allocStructFrame(aliasBase) {
    const f = this.allocFrame();
    const base = aliasBase & ~0xfffn;
    for (const existing of this.mirrors.values()) {
      if (existing.base === base) {
        throw new Error(
          `paging: self-map alias collision at 0x${base.toString(16)} — ` +
          `assign each process a distinct selfRefIndex`);
      }
    }
    this.mirrors.set(f, { base });
    return f;
  }

  /** Write a 64-bit table entry on BOTH the physical frame and its alias. */
  poke64(entryPa, value) {
    this.mem.w64(entryPa, value);
    const m = this.mirrors.get(entryPa & ~0xfffn);
    if (m) this.mem.w64(m.base + (entryPa & 0xfffn), value);
  }

  /** Propagate student edits made through alias VAs into physical frames. */
  _syncAliasesBack() {
    for (const [frame, m] of this.mirrors) {
      if (!this.mem.hasPage(m.base)) continue;
      const bytes = this.mem.read(m.base, 4096);
      const phys = this.mem.read(frame, 4096);
      if (bytes.some((b, i) => b !== phys[i])) this.mem.write(frame, bytes);
    }
  }

  /** Allocate one zeroed physical frame; returns its physical base. */
  allocFrame() {
    const f = this.nextFrame;
    this.nextFrame += BigInt(PAGE_SIZE);
    this.mem.write(f, new Uint8Array(PAGE_SIZE)); // zero-fill + materialize
    this.frames.push(f);
    return f;
  }

  /** Allocate the next 2MB-aligned zeroed region (large-page backing). */
  allocLarge() {
    const align = 0x200000n;
    const pa = (this.nextFrame + align - 1n) & ~(align - 1n);
    this.nextFrame = pa + BigInt(PAGE_SIZE); // only first page needs materializing
    this.mem.write(pa, new Uint8Array(PAGE_SIZE));
    this.frames.push(pa);
    return pa;
  }

  _dtbFieldOffset() {
    try {
      return this.kernel.tables.offsetOf("_KPROCESS", "DirectoryTableBase");
    } catch {
      return 0x28n;
    }
  }

  /**
   * Create page tables for a process and record them against its EPROCESS.
   * Installs the self-referencing PML4E at `selfRefIndex` (per-process
   * override enables CR3-shuffle labs).
   * @returns process record {name,pid,dtb,selfRefIndex,mapped:[]}
   */
  createProcess({ name, pid, eproc = null, selfRefIndex = null }) {
    const idx = selfRefIndex === null || selfRefIndex === undefined
      ? this.defaultSelfRefIndex
      : BigInt(selfRefIndex);
    const sm = selfMapVas(idx, this.canonicalHigh);
    const dtb = this._allocStructFrame(sm.pml4Base);
    // self-ref entry points back at the PML4 frame itself, present+writable
    // + accessed — same flag shape as the real Windows entry.
    this.poke64(dtb + idx * 8n, (((dtb >> 12n) << 12n) | 0x63n));
    const rec = {
      name,
      pid: pid ?? null,
      eproc,
      dtb,
      selfRefIndex: idx,
      mapped: [],
      decoy: false,
    };
    this.processes.set(name, rec);
    if (eproc !== null && eproc !== undefined) {
      this.mem.w64(BigInt(eproc) + this._dtbFieldOffset(), dtb);
    }
    return rec;
  }

  /**
   * Map one page (4K or 2M large) into a process's tables, materializing
   * intermediate levels on demand.
   * @param {object} proc record from createProcess()
   * @param {bigint} va virtual address to map
   * @param {{pa?: bigint, size?: 4096|0x200000, writable?: boolean,
   *          user?: boolean, nx?: boolean, present?: boolean}} opts
   */
  mapPage(proc, va, opts = {}) {
    const pml4Idx = Number((BigInt(va) >> 39n) & 0x1ffn);
    if (pml4Idx === Number(BigInt(proc.selfRefIndex))) {
      throw new Error(
        `mapPage: refusing to map inside the self-map region (PML4 index 0x${proc.selfRefIndex.toString(16)})`);
    }
    if (Number((BigInt(va) >> 21n) & 0x1ffn) === SELF_MAP_SENTINEL ||
        Number((BigInt(va) >> 30n) & 0x1ffn) === SELF_MAP_SENTINEL ||
        Number((BigInt(va) >> 12n) & 0x1ffn) === SELF_MAP_SENTINEL) {
      throw new Error("mapPage: paths containing the reserved alias-sentinel index 0x1ff are not mappable");
    }
    const size = opts.size ?? 4096;
    const pa = opts.pa !== undefined ? BigInt(opts.pa)
      : size === 0x200000 ? this.allocLarge() : this.allocFrame();
    const idx = splitVa(va);
    const dtb = proc.dtb;
    const sm = selfMapVas(proc.selfRefIndex, this.canonicalHigh);

    // alias bases for intermediate levels (per-path windows)
    const pdptAlias = sm.pdptBase(idx.pml4Index);
    const pdAlias = sm.pdBase(idx.pml4Index, idx.pdPtIndex);
    const ptAlias = sm.ptBase(idx.pml4Index, idx.pdPtIndex, idx.pdIndex);

    const pml4eAddr = dtb + BigInt(idx.pml4Index) * 8n;
    let pml4e = this.mem.u64(pml4eAddr);
    const pdptFrame = (pml4e & ~0xfffn) === 0n
      ? this._allocStructFrame(pdptAlias) : pml4e >> 12n << 12n;
    pml4e = (pdptFrame >> 12n) << 12n | 0x23n | (opts.user ? 0x4n : 0n); // P+W(+U)
    this.poke64(pml4eAddr, pml4e);

    const pdpteAddr = pdptFrame + BigInt(idx.pdPtIndex) * 8n;
    let pdpte = this.mem.u64(pdpteAddr);
    const pdFrame = (pdpte & ~0xfffn) === 0n
      ? this._allocStructFrame(pdAlias) : pdpte >> 12n << 12n;
    pdpte = (pdFrame >> 12n) << 12n | 0x23n | (opts.user ? 0x4n : 0n);
    this.poke64(pdpteAddr, pdpte);

    const pdeAddr = pdFrame + BigInt(idx.pdIndex) * 8n;
    let pde = this.mem.u64(pdeAddr);
    if (size === 0x200000) {
      // large page: PDE points straight at the 2MB frame, PS bit set
      const flags = 0xa3n | (opts.user ? 0x4n : 0n); // P+W+PS(+U)
      this.poke64(pdeAddr, (BigInt(pa) >> 21n) << 21n | flags);
      proc.mapped.push({ va, size, pa, pdeAddr });
      return { va, pa, level: "2M", entryAddr: pdeAddr };
    }
    const ptFrame = (pde & ~0xfffn) === 0n
      ? this._allocStructFrame(ptAlias) : pde >> 12n << 12n;
    pde = (ptFrame >> 12n) << 12n | 0x23n | (opts.user ? 0x4n : 0n);
    this.poke64(pdeAddr, pde);

    const pteAddr = ptFrame + BigInt(idx.ptIndex) * 8n;
    let flags = 0x61n; // P + ACCESSED + DIRTY baseline
    if (opts.writable !== false) flags |= 0x2n;
    if (opts.user) flags |= 0x4n;
    if (opts.nx) flags |= PTE_BIT.NX;
    else flags &= ~PTE_BIT.NX;
    if (opts.present === false) flags &= ~0x1n;
    this.poke64(pteAddr, (BigInt(pa) >> 12n) << 12n | flags);
    proc.mapped.push({ va, size: 4096, pa, pteAddr });
    return { va, pa, level: "4K", entryAddr: pteAddr };
  }

  /** Physical address of the final-level entry covering `va` (PTE for 4K,
   *  PDE for 2M, PDPTE for 1G); null when the walk fails earlier.
   *  @returns {bigint|null} */
  leafEntryPa(va, dtbOrProc) {
    const w = this.translate(va, dtbOrProc);
    if (!w.ok) return null;
    return w.rows[w.rows.length - 1]?.entryPa ?? null;
  }

  /**
   * Full 4-level walk. Returns rows for every level visited so debuggers can
   * print the chain (WinDbg !pte style) and labs can grade hand-computed
   * intermediate addresses.
   * @returns {{ok:boolean, level:"4K"|"2M"|"1G"|null, pa:bigint|null,
   *            failedAt?:string, rows:Array<object>}}
   */
  translate(va, dtbOrProc) {
    this._syncAliasesBack();
    const proc = typeof dtbOrProc === "object" && dtbOrProc?.dtb !== undefined
      ? dtbOrProc
      : null;
    const dtbRaw = proc ? proc.dtb : BigInt(dtbOrProc ?? 0n);
    const dtb = dtbRaw & ~0xfffn;
    const idx = splitVa(va);
    const sm = selfMapVas(proc ? proc.selfRefIndex : this.defaultSelfRefIndex,
      this.canonicalHigh);
    const rows = [];

    const pml4ePa = dtb + BigInt(idx.pml4Index) * 8n;
    const pml4e = this.mem.u64(pml4ePa);
    rows.push({ label: "PML4E", entryPa: pml4ePa, entryVa: sm.pml4e(idx.pml4Index), value: pml4e });
    if (!(pml4e & 1n)) return { ok: false, level: null, pa: null, failedAt: "PML4E", rows };

    // PDPTE lives in the PDPT frame selected by PML4E[pml4Index]
    const pdptePa = ((pml4e >> 12n) << 12n) + BigInt(idx.pdPtIndex) * 8n;
    const pdpte = this.mem.u64(pdptePa);
    rows.push({ label: "PDPTE", entryPa: pdptePa, entryVa: sm.pdpte(idx.pml4Index, idx.pdPtIndex), value: pdpte });
    if (!(pdpte & 1n)) return { ok: false, level: null, pa: null, failedAt: "PDPTE", rows };
    if ((pdpte >> 7n) & 1n) {
      return {
        ok: true, level: "1G",
        pa: ((pdpte >> 30n) << 30n) + (va & 0x3fffffffn),
        rows,
      };
    }

    const pdBase = (pdpte >> 12n) << 12n;
    const pdePa = pdBase + BigInt(idx.pdIndex) * 8n;
    const pde = this.mem.u64(pdePa);
    rows.push({ label: "PDE", entryPa: pdePa, entryVa: sm.pde(idx.pml4Index, idx.pdPtIndex, idx.pdIndex), value: pde });
    if (!(pde & 1n)) return { ok: false, level: null, pa: null, failedAt: "PDE", rows };
    if ((pde >> 7n) & 1n) {
      return {
        ok: true, level: "2M",
        pa: ((pde >> 21n) << 21n) + (va & 0x1fffffn),
        rows,
      };
    }

    const ptBase = (pde >> 12n) << 12n;
    const ptePa = ptBase + BigInt(idx.ptIndex) * 8n;
    const pte = this.mem.u64(ptePa);
    rows.push({ label: "PTE", entryPa: ptePa, entryVa: sm.pte(idx.pml4Index, idx.pdPtIndex, idx.pdIndex, idx.ptIndex), value: pte });
    if (!(pte & 1n)) return { ok: false, level: null, pa: null, failedAt: "PTE", rows };

    return {
      ok: true,
      level: "4K",
      pa: ((pte >> 12n) << 12n) + BigInt(idx.offset),
      rows,
    };
  }

  /**
   * Scan allocated frames for a self-referencing PML4 signature — the
   * practical answer to CR3-shuffled worlds (any PML4E[i] whose PFN equals
   * the frame holding it). Returns matching DTBs sorted ascending.
   */
  scanSelfRefFrames() {
    this._syncAliasesBack();
    const hits = [];
    for (const f of this.frames) {
      for (let i = 0; i < 512; i++) {
        const e = this.mem.u64(f + BigInt(i) * 8n);
        if (e !== 0n && (e & 0x1n) && ((e >> 12n) << 12n) === f) {
          hits.push({ dtb: f, index: i, value: e });
          break;
        }
      }
    }
    return hits;
  }

  /** Look up a process record by name or PID (string or bigint). */
  findProcess(token) {
    const t = String(token).replace(/\.exe$/i, "").toLowerCase();
    if (this.processes.has(t)) return this.processes.get(t);
    for (const rec of this.processes.values()) {
      if (rec.name.toLowerCase() === t) return rec;
      if (rec.pid !== null && String(rec.pid) === t.replace(/^#/, "")) return rec;
    }
    return null;
  }
}
