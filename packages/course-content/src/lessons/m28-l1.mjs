/** Lesson body: m28.l1 — obfuscation, polymorphism & weird machines.
 *  Sources: tmpout v1 s01den (false disassembly, Eng3ls), v2 s01den (M4rx VM)
 *  + qkumba (RE of M4rx), v5 patate (code virtualization survey),
 *  febnug (XLAT / stateless control flow / Brainfuck-as-ROP),
 *  ti3f (440-byte metamorphic virus), v3 ic3qu33n (padding infection). */
export default `## Code that lies about being code

Every disassembler faces one impossible question: where do instructions
start? Everything in this module weaponizes the answer.

### False disassembly

Linear-sweep disassemblers decode every byte between instructions. s01den
(tmp.0ut #1, after Silvio Cesare) plants bytes that begin a *real* instruction
and jumps over them:

\`\`\`
db 0x48, 0x31        ; starts "xor r/m64, r64" ...
yo: xor rbx, rbx     ; ... so this decodes as garbage
    jmp yo+2         ; runtime skips the junk pair
\`\`\`

Radare2 renders \`4831 db eb02\` as \`xor qword [rax+0x31], rcx\` plus noise.
The polymorphic twist: mutate only the two junk bytes per generation and the
*listing* changes completely while the program barely does — signature-based
detection of the decryptor dies.

### EPO + oligomorphism: Eng3ls

Lin64.Eng3ls (#1, s01den & sblip) encrypts its body with a per-generation XOR
key, hides the decryptor behind false disassembly, and triggers via
**EPO**: patch \`.init_array[0]\` to an anti-ptrace constructor
(\`PTRACE_TRACEME\`, syscall 101, exit(0) if traced) and \`.fini_array[0]\`
to the payload — \`e_entry\` never moves.

### Virtual machines: M4rx and beyond

Lin64.M4rx (#2, s01den) compiles the virus into a custom ISA: fixed **8-byte**
instructions — opcode byte, two argument bytes, five random junk bytes — run
by a linear "spider" dispatcher over handlers operating on virtual registers.
The lone real \`syscall\` instruction hides behind false-disassembly bytes;
the anti-debug prologue is itself virtualized bytecode. qkumba's RE (#2) is
the required sequel: recover all 31 opcodes (29 functional), catalogue the
design flaws (writes don't zero-extend; POP pulls 8 bytes against PUSH imm8's
1), and devirtualize by hand. patate's survey (#5) generalizes the pipeline —
mutation, constant expansion, control-flow flattening, fetch/decode/dispatch —
and names the counter-offensive: taint analysis, lifting (McSema/Remill),
symbolic deobfuscation.

### Weird machines without state

febnug's #5 trilogy executes through data and flags instead of instructions:

- **XLAT is All You Need** — store *indices*, keep the mapping in an
  obfuscated table decoded on the stack; \`xlatb\` (AL ← [RBX+AL]) is the
  whole decoder. The table IS the program.
- **State Without State** — one bit lives in the Carry Flag, entropy comes
  from \`rdtsc\`, and two overlapping \`jmp rel8\` encodings (\`0xEB\`) make
  entry-point selection choose which of two CFGs the same bytes execute.
- **Brainfuck as a ROP compiler** — \`rsp\` is the program counter, gadgets
  end in \`ret\`, loops are stack-pointer arithmetic: control flow becomes
  pointer math on a weird machine.

### Metamorphism at 440 bytes

ti3f (#5): twenty 16-byte blocks of four ≤4-byte instructions re-permute
(Fisher-Yates via \`rdrand\`) each generation — ~408 reachable forms. No
relative jumps survive shuffling, so loops use \`cmovle/cmovge\` selecting a
target register plus \`jmp r8\`; every constraint is engineered away until the
whole virus fits beside a single-phdr header.

## Lab — deobfuscation gauntlet (quiz)

Six flags across the arc above: M4rx's instruction size; how many junk bytes
each false-disassembly site jumps over; the x86 instruction doing lookup
decoding in the XLAT paper; which CPU flag carries the sole bit of state in
"State Without State"; which register serves as the ROP program counter in
the Brainfuck compiler; and what toy-VM bytecode \`01 02 05 03 03 FF\`
computes (submit like a math expression, no spaces).

## Flags

Formats pinned per prompt — names lowercase, numbers decimal, expressions
compact.
`;
