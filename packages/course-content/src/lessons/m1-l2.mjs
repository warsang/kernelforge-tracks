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

\`\`\`text
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

## Defensive framing — detecting DKOM

DKOM is decades old yet still appears in the wild because so much tooling
trusts the kernel's own lists unconditionally. A defender's answer is always
the same move: **find a second opinion that does not flow through the thing
being edited**, then diff. The main independent sources:

| second opinion | why DKOM cannot touch it |
|---|---|
| handle-table scan | open handles keep object headers alive regardless of list membership |
| KTHREAD cross-refs | every thread's \`ApcState.Process\` still points at the victim |
| pool carving | the EPROCESS bytes themselves survive in place |
| ETW process events | emitted at creation time, before any hiding |

A minimal in-driver cross-check against thread references:

\`\`\`c
// For each listed process we also count ETHREADs whose Cid.UniqueProcess
// matches it, walking PsActiveProcessHead *and* a thread source. A process
// with live threads but no list node is being hidden.
BOOLEAN ProcessHasLiveThreads(PEPROCESS eproc)
{
    // production: walk EPROCESS.ThreadListHead (still intact post-DKOM!)
    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)eproc + OFF_THREAD_LIST_HEAD);
    return head->Flink != head;   // unlinked processes keep their threads
}
\`\`\`

That last line is the quiet killer: **DKOM hides the process but forgets its
threads** — \`ThreadListHead\`, quota blocks and the kernel handle table all
still reference it. Hypervisor-backed views go further (the guest cannot
edit what it cannot see), and classic KPP-style checks re-walk the list from
independent roots on a timer.

You will implement exactly this class of detection in m1.l4: **KF-Sentinel
v1** walks the process list, carves the EPROCESS pool window for name
signatures, and convicts anything carved-but-not-linked. Build the attack
here, then build the thing that catches it there.
`;
