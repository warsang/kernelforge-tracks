/** Lesson body: m11.l1 — x64 paging and the SMM landscape (markdown). */
export default `## Two walls around ring 0

Modern Windows runs behind two protection boundaries students rarely
see at once:

1. **Paging** (ring 0 vs page permissions): every memory access walks a
   four-level x64 address translation — PML4 → PDPT → PD → PT. Canonical
   addresses sign-extend bit 47; PTE bits decide read/write, supervisor/user,
   and NX.
2. **SMM** (ring -2 vs everything): System Management Mode is a CPU mode
   entered on an SMI that no OS can mask. Handlers live in **SMRAM**, a
   range of DRAM the chipset hides from normal code.

This platform now emulates both for real: the emulated kernel boots with
genuine page tables you can walk, and the SMM modules add a Q35-style
chipset with CF8/CFC config cycles.

## Walking pages in the console

Boot the \`smm-foundations\` world and try:

    kd> !cr                     cr0/cr3/cr4/efer — PG? PAE? LMA?
    kd> !vtop 0xfffff78000000000
    kd> !pte  0x7ffe0000

\`KUSER_SHARED_DATA\` is dual-mapped: one physical frame visible from two
VAs — exactly how Windows shares tick data between user and kernel.

## The chipset side

    kd> !smmc                   decode SMRAMC (D_OPEN/D_CLS/D_LCK/G_SMRAME)
    kd> !smram                  SMRAM range, SMBASE, SMI counters

The classic vulnerable platform powers up with \`G_SMRAME=1\` but
\`D_LCK=0\` — SMRAM exists, is closed, yet *nobody locked the door*.
`;
