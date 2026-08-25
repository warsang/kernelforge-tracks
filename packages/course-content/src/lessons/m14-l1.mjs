/** Lesson body: m14.l1 — x64 virtual memory & page-table walking (markdown). */
export default `## Every address is a small lie

Your driver's 0xFFFF... pointer never touches silicon directly. The MMU
splits every canonical x64 VA into **9/9/9/9/12** bits and walks four
tables — PML4 -> PDPT -> PD -> PT — starting from the physical frame in
**CR3** (EPROCESS.DirectoryTableBase). Each entry carries the hardware
bits that *are* memory protection: P, R/W, U/S, A, D, PS (large page),
and NX on bit 63.

In this world the tables are REAL bytes. \`!cr3 kftarget\` prints the DTB
and the process's self-map index; \`!pte <va>\` prints every level with
its physical entry address and a dq-able alias; \`!vtop <va>\` translates.
Windows manages these same bytes through its own self-map (index 0x1ED,
PTE space at 0xFFFFF68000000000); our low-memory worlds expose equivalent
alias windows under your chosen index so plain \`dq\`/\`eb\` reach them.

## The lab

1. Find the REAL DirectoryTableBase — the lowest frames belong to a
   decoy whose self-map sits at a different index (an EAC-style CR3
   shuffle). The genuine PML4 self-references through index 0xF.
2. Hand-split CODE_VA into 9-bit fields and compute the PTE alias:
   \`va(s, pml4(V), pdpt(V), pd(V), pt(V)*8)\`. Submit it (\`dq\` to verify).
3. The code page was NX-smashed: bit 63 of its PTE is set, so the
   driver's integrity pass refuses to run. Clear it with \`eb\`
   (byte 7 of the alias qword), then \`!vtop\` the code VA again and read
   the released secret from !analyze -v / DbgPrint buffer.

## Why defenders care

Page tables are where "protection" actually lives: DEP is one bit,
SMEP is U/S enforced in the walk, and CR3 shuffling breaks tools that
cache DirectoryTableBase. Hypervisor introspection reads these very
structures from physical memory — which is why cheats fight back by
hiding them first.

### Further reading

- security-auditing.com — "Windows Memory Internals" (x64 virtual memory, VAD/MDL/TLB)
- yunolay.com — "Windows Virtual Memory: Page Tables, PTEs, Working Sets"
- connormcgarr.github.io — "Turning the Pages" + ARM64 paging internals
- Core Security — "Getting Physical: Extreme abuse of Intel based Paging Systems"
- hLunaaa — "Bypassing CR3 Abuse with Physical R/W" (EAC/VKG shuffle context)
`;
