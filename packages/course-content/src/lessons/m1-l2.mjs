/** Lesson body: m1.l2 — EPROCESS walking & DKOM process hiding (markdown). */
export default `## The list that defines "running"

Last lesson you *read* \`PsActiveProcessHead\`. This lesson you *write* to it.
The technique is **DKOM — Direct Kernel Object Manipulation**: instead of
terminating a process, edit the metadata that says it exists.

## ActiveProcessLinks

Inside every \`_EPROCESS\` sits \`ActiveProcessLinks\`, a \`_LIST_ENTRY\`
(\`{Flink, Blink}\`). The kernel's idea of "which processes exist" **is** this
ring — nothing recomputes it:

\`\`\`
head.Flink -> [P1.links] <-> [P2.links] <-> ... <-> head.Blink
\`\`\`

Unlink a node and the scheduler, task manager, and EDRs all stop seeing the
process. It keeps running — invisible.

## The lab

You will write (well: guide the builder through) a driver that:

1. Resolves the target \`_EPROCESS\` by PID (\`PsLookupProcessByProcessId\`).
2. Computes \`links = eprocess + ActiveProcessLinks.Offset\` — on 22H2 that
   offset is \`0x448\`, straight from the build tables your debugger uses.
3. Splices itself out: \`prev->Flink = next; next->Blink = prev;\`
4. \`DbgPrint\`s the address of the \`_LIST_ENTRY\` it overwrote.

After loading, confirm from the debugger:

\`\`\`
kd> !process 0 0        # kftarget.exe is gone
\`\`\`

Your answer for this lab is the printed \`_LIST_ENTRY\` address — submit the
full 16-digit hex with the \`0x\` prefix, exactly as shown.

## Why offsets come from tables

Hardcoding \`+0x448\` breaks on every Windows build. Real tooling resolves
field offsets from PDB symbols; ntsim resolves them from per-build Vergilius
tables, so the same driver source works across builds. Notice your debugger
and your driver agreeing on \`0x448\` without either hardcoding more than one
copy of the truth.

## Defensive framing

DKOM is decades old yet still appears in the wild because so much tooling
trusts the kernel's own lists unconditionally. Defenses worth knowing:
comparing the EPROCESS ring against the handle table / KTHREAD cross-references,
hypervisor-backed views (the guest cannot edit what it cannot see), and
KPP-style checks that re-walk the list from independent roots.
`;
