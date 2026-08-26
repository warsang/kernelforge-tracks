/** Lesson body: m25.l1 — ELF parasites: PT_NOTE infection & repair.
 *  Sources: tmpout v1 sblip (PT_NOTE in x64 asm), d3npa (Rust injector),
 *  manizzle (disinfector), s01den (OEP despite PIE; entrypoint obscuring v2),
 *  v3 vrzh (__cxa_finalize EPO). Fixture:
 *  apps/web/public/fixtures/elf/infected.elf */
export default `## An infection you can hold

Our [\`infected.elf\`](/fixtures/elf/infected.elf) fixture is the m24
baseline after the classic **PT_NOTE infection** (sblip, tmp.0ut #1): a
parasite appended at EOF, made loadable by recycling a segment nobody needs,
and a hijacked entry point that jumps back to the original code when done.

### The recipe, exactly

1. Save \`e_entry\` — that's the future OEP.
2. Walk the program header table for \`p_type == PT_NOTE (4)\`.
3. Rewrite it in place:

\`\`\`
p_type   = PT_LOAD        // 4 -> 1
p_flags  = PF_R | PF_X    // 4 | 1 = 5
p_offset = old EOF        // where we append
p_vaddr  = file_size + 0xc000000   // "as far away as possible"
p_filesz/p_memsz += parasite_len
p_align  = 0x200000
\`\`\`

(d3npa's Rust injector uses base \`0xc00000000\` — different authors, different
far-VA taste; both exploit the spec line that NOTE segments must not affect
execution.)

4. Append the parasite and point \`e_entry\` at it.
5. Patch a jump back to the OEP. x86-64 has no 64-bit immediate jmp, so
   d3npa appends \`48 b8 <imm64> ff e0\` — \`movabs rax, oep; jmp rax\`.

### Finding the OEP again (the defender's job)

manizzle's disinfector (tmp.0ut #1) keys on the invariant this technique
cannot hide: the converted segment is an **outlier PT_LOAD** whose VA lives
megabytes away from every legitimate mapping — cluster the LOAD ranges
(KMeans, inertia ratio 1.1) and the parasite segment stands alone. Disassemble
its tail backwards for the final \`jmp\`; its operand (or the \`add reg, CONST\`
feeding it) is the OEP; restore \`e_entry\` and write \`*.cleaned\`.

PIE breaks naive static OEP restoration because addresses randomize per run —
s01den's ret2OEP stub (tmp.0ut #1, after elfmaster) recomputes at runtime:

\`\`\`
call get_rip            ; get_rip: mov rax,[rsp]; ret
sub  rax, VXSIZE + 5
sub  rax, new_EP
add  rax, original_e_entry
mov  rsp, r14           ; restore the stack the host expects
jmp  rax
\`\`\`

Entrypoint obscuring (EPO) skips \`e_entry\` entirely: s01den's v2 note
patches \`.fini_array[0]\` **and** the \`R_X86_64_RELATIVE\` relocation in
\`.rela.dyn\` that would otherwise overwrite it at load time (SHT_FINI_ARRAY =
0x0F, SHT_RELA = 0x04); vrzh (tmp.0ut #3) hijacks \`__cxa_finalize\`'s
GOT slot via its \`R_X86_64_GLOB_DAT\` relocation so the parasite fires from
inside the destructor path of glibc exit.

## Lab 1 — patient zero (hands-on)

Boot the lab with the \`elf-infected\` scenario:

\`\`\`
elf> info              # structurally quiet! parsers see nothing wrong...
elf> phdr              # phdr[2]: "PT_LOAD" at a suspicious far VA?
elf> hex 0x46c 32      # the appended blob: marker + movabs rax,OEP; jmp rax
elf> str               # 'KFPARASITE' gives the game away
\`\`\`

The three flags: recover the **OEP** from the parasite's movabs immediate,
give the **decimal file offset** where the parasite starts, and name which
segment type the infector repurposed.

## Lab 2 — the paper chase (quiz)

Three answers come straight out of the zine articles above.

## Flags

Lab 1: OEP (0x-hex); parasite file offset (decimal); original \`p_type\` name
of the recycled segment. Lab 2: the far-VA base Midrashim adds to file size;
the two opcode bytes ending d3npa's jump-back stub; the language runtime whose
PT_NOTE must stay intact (blocking this infection).
`;
