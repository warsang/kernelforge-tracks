/** Lesson body: m27.l1 — vtable, hot-patch and DRx hooks, hands-on (markdown). */
export default `## Ring-3 hooks that never touch an import

Three techniques cover most of what live anticheats actually hunt. All
three leave the import table alone; they differ in WHERE the lie lives.

## VTable swaps — the lie is a pointer

C++ objects carry their method table at +0x00. Copy the honest table,
edit one slot to point at your stub, re-point the object — every virtual
call routes through you:

\`\`\`
object 0x02100400: +0x00 -> 0x005e1000 (honest)   -> 0x02100800 (cheat heap)
vtable slot0       : cl_getviewangles             -> cheat stub
\`\`\`

One qword in heap memory, zero code bytes changed anywhere. The lab:
\`!callview\` proves the rewrite; \`x\` on the object resolves the fake
table; restore the honest pointer.

## Hot-patch slots — the lie was pre-built

Microsoft compiles hot-patchable functions with a **5-NOP sled followed
by \`MOV EDI,EDI\`** (2 bytes). The sled exists so a hotfix can install an
E9 rel32 atomically — exactly what a cheat does:

\`\`\`
cl_calcspread: 90 90 90 90 90 | 8b ff | body
install      : e9 <rel32>     (sled jumps straight past MOV EDI,EDI)
\`\`\`

No prologue clobbering, no stolen-instruction copying. \`!spreadtest\`
shows the spread rewrite; \`hookscan\` shows the sled bytes differ from
pristine; restoring the five NOPs heals it.

## DRx hooks — the lie is in the CPU

Debug registers DR0–DR3 hold linear addresses; DR7 arms them as execute
breakpoints. A vectored exception handler catches each #DB and reroutes
execution — \`.text\` stays byte-for-byte pristine. Costs: four slots,
per-access exception overhead, and...

## Who catches this in the real world

- **PatchGuard: silent** (ring 3).
- **Pointer containment**: ACs walk object graphs and convict any vtable
  pointer outside the owner module's image — your fake heap table screams.
- **On-disk diffing** catches sled edits like any other inline hook.
- **The DR audit**: \`GetThreadContext\` on your own threads is the
  standard counter-move — nonzero DR0–DR3 is a verdict, not a hint.
`;
