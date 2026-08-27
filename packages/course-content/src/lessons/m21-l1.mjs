/** Lesson body: m21.l1 — Userland injection: handleless vs handle-based. */
export default `## Two footprints into someone else's process

"Injection" means landing code or data inside a target process. Every
kernel-backed technique answers one question first: **how do I reach that
address space?** There are exactly two families, and they leave different
footprints for defenders to see.

## Path 1 — the handle-based classic

Usermode's contract, done from your driver:

\`\`\`c
ZwOpenProcess(&hProc,
              PROCESS_VM_WRITE | PROCESS_VM_OPERATION, &oa, &cid);
ZwWriteVirtualMemory(hProc, targetVa, payload, len, NULL);
ZwClose(hProc);
\`\`\`

The handle is a **tracked object reference**: the kernel records which
EPROCESS it points at and which access rights were granted
(\`PROCESS_VM_WRITE\` = 0x20, \`PROCESS_VM_OPERATION\` = 0x8). Everything you
do through it is checkable — wrong mask, ACCESS_DENIED; every open/close is
observable via handle-table enumeration (\`!handles\`, SystemHandleInformation).
EDRs watch this exact trail: an unknown process opening a write handle to a
game is the loudest possible injection signal.

## Path 2 — handleless by attachment

Skip the object manager entirely: get the EPROCESS pointer directly and
*become* the process:

\`\`\`c
PsLookupProcessByProcessId((HANDLE)888, &proc);
KeStackAttachProcess(proc, &apcState);   // ApcState.Process rotates to target
RtlCopyMemory(targetVa, payload, len);   // plain memory move
KeUnstackDetachProcess(&apcState);
ObDereferenceObject(proc);
\`\`\`

No handle exists, so no handle audit fires. The residue moves instead:
the attaching thread's \`KTHREAD.ApcState.Process\` names the victim while
attached (m1.l0's row #2), and the copy itself is invisible to any
API-level hook because there isn't one. This is the same primitive DKOM
labs use — and why EDRs cross-check attachments, not just handles.

## The lab

Boot \`ul-inject\`: kftarget.exe exposes a game-like page at
\`0x7ff600100000\`. Compile the starter — it lands both payloads, prints one
line per path, then the completion secret. In the debugger you can confirm
both bytes landed at the same address; only the telemetry differs.

## Flags

1. The completion secret from the driver's DbgPrint buffer.
2. The access-right constant (as spelled in ntddk.h) that
   \`ZwWriteVirtualMemory\` requires on the handle beyond
   \`PROCESS_VM_OPERATION\`.
3. The per-thread structure that records where an attached thread is
   attached — one word, lowercase.
`;
