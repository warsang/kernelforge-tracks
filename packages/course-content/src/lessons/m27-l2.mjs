/** Lesson body: m27.l2 — defense against userland deep cuts (markdown). */
export default `## Defending the pointer graph, the sled, and the registers

## Pointer-graph attestation

VTable swaps die to containment checks, not byte scans:

1. Walk live objects (entity arrays, renderer singletons).
2. For each \`+0x00\` pointer, require it to resolve **inside the module
   that owns the object's type** — a heap-resident "table" at
   0x02100800 has no image, no export range, no reason to exist.
3. Snapshot known-good vtables per class; diff slot values, not just
   table addresses.

This is the ring-3 cousin of m24's MajorFunction containment.

## Sled-aware integrity

Treat the hot-patch padding as part of the prologue: baseline
\`[90 x5][8b ff]\`, convict any E9/E8 in the first eight bytes. Products
that only hash function entry (2 bytes) miss exactly this install —
hash the sled too.

## The DR audit is a two-way street

\`GetThreadContext\` on every thread, on a timer:

- nonzero DR0–DR3 with no legitimate debugger attached → verdict.
- cleared-after-use is the attacker's best play, so pair the audit with
  behavior counters (\`!frametest\` trip accounting) — hardware
  breakpoints leave timing residue even when registers come back zero.

## Who catches this in the real world

- **Anticheats** run all three loops continuously from a protected
  service; the lab's \`!drxaudit\` verdict line is their actual alert text
  shape.
- **EDRs** add kernel-side VAD/page protections for flagged processes.
- **PatchGuard**: still silent — and still irrelevant down here.
`;
