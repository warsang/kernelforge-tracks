/** Lesson body: m1.l0 — Kernel objects primer: the four places a process
 *  exists (markdown). Read this before touching ActiveProcessLinks. */
export default `## Never trust one list

An EDR process inventory is not one lookup — it is several independent
records diffed against each other. When they disagree, something is lying.
The four records that matter on Windows x64:

| # | source | owned by | survives a simple \`_EPROCESS\` unlink? |
|---|---|---|---|
| 1 | \`ActiveProcessLinks\` | each \`_EPROCESS\` | **no** — it *is* the list |
| 2 | \`KTHREAD→ApcState.Process\` | every thread | yes |
| 3 | handle tables (\`ObjectTable\`) | every process | yes |
| 4 | process-start telemetry | kernel callbacks / ETW | yes |

Read that last column precisely: it says these records survive **the one
edit m1.l2 teaches** — rewiring the victim's \`LIST_ENTRY\`. It does *not*
say they are unattackable. Every row can be tampered with given enough
privilege and nerve: rewrite each thread's \`ApcState.Process\` back at its
own \`_EPROCESS\` (row 2), strip your handles out of every other process's
table (row 3), or unregister the notify callbacks / kill the ETW session
(row 4). Each escalation is its own move, leaves its own residue, and is
exactly what later modules make you try — and then detect.

Attackers start by editing #1 (**DKOM**). Defenders convict by diffing #1
against #2, #3 and #4. This lesson introduces every structure those rows
name — you will edit them in m1.l2 and detect the edit in m1.l4.

## _EPROCESS and its list

Every process is described by an \`_EPROCESS\` in non-paged pool. The kernel
chains them through an embedded \`_LIST_ENTRY {Flink, Blink}\`:

\`\`\`
kd> dt nt!_EPROCESS
   +0x440 UniqueProcessId : Uint8B          // the Cid you see in !process
   +0x448 ActiveProcessLinks : _LIST_ENTRY  // the chain itself
   +0x550 Peb          : Ptr64 _PEB
   ...
\`\`\`

(Offsets shown are the 22H2 build tables this course ships; your debugger
and your drivers both resolve them from the same source.) The ring is rooted
at the global \`nt!PsActiveProcessHead\`. \`NtQuerySystemInformation\`, Task
Manager and most tooling simply walk it:

\`\`\`
kd> !process 0 0
kd> ? nt!PsActiveProcessHead
\`\`\`

That is row #1. One \`prev->Flink = next\` later, a process vanishes from
every consumer of this list — while still running. Hold that thought.

## Threads: _ETHREAD, _KTHREAD and ApcState

Each thread is described by an \`_ETHREAD\` whose first bytes embed the
scheduler's view, \`_KTHREAD\`. Two fields matter here:

- \`_EPROCESS.ThreadListHead\` — every owning process rings up its threads,
  so "which threads does X have" does **not** need the process list.
- \`_KTHREAD.ApcState\` (a \`_KAPC_STATE\`, 22H2 offset \`+0x98\`) — records
  which address space the thread is currently attached to.

\`\`\`
kd> dt nt!_KTHREAD
   +0x098 ApcState : _KAPC_STATE
   +0x24a ApcStateIndex : UChar
   +0x258 SavedApcState : _KAPC_STATE
   +0x2f8 ThreadListEntry : _LIST_ENTRY
\`\`\`

### What attach actually does

Normally \`ApcState.Process\` points at the thread's own \`_EPROCESS\`. When a
driver crosses into another process with \`KeStackAttachProcess(target,
&apc)\`, the kernel **rotates** these fields:

\`\`\`
before:  ApcState.Process = self        SavedApcState = -
attach:  ApcState.Process = target      SavedApcState.Process = self
detach:  ApcState.Process = self        SavedApcState = -
\`\`\`

The caller's \`KAPC_STATE\` buffer receives the saved state so detach can
restore it. Inspect live state per thread any time (this transcript is from
the lab world — \`kfsample\` is the canary process, and addressing it by
name works in every lab world even though PIDs differ between overlays):

\`\`\`
kd> !process kfsample 7
PROCESS 0xffffb80000003350  SessionId: none  Cid: 1312  Peb: 00000000  ParentCid: 0000
    ImageFileName: kfsample.exe
    Token: 0xffffa40bc9e78500  ActiveThreads: 1
    THREAD 0xffffb80004002ea0  Cid 1312.1044  Teb: 000000e441400000  Win32Thread: 00000000  ApcState->kfsample.exe
kd> !process 0 4            # every process, one THREAD line each
\`\`\`

The \`ApcState->\` annotation is the point of this lesson: **it is a pointer
into the process world that no \`ActiveProcessLinks\` edit can retract.**
Unlink \`_EPROCESS\` X and every X-thread still carries \`ApcState->
X\`, still sits in X's \`ThreadListHead\` ring. An in-driver detector needs
nothing exotic — walk the ring, read the pointer:

\`\`\`c
// second opinion for "does P really exist": its own threads say yes.
BOOLEAN ProcessHasLiveThreads(PEPROCESS eproc)
{
    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)eproc + OFF_THREAD_LIST_HEAD);
    return head->Flink != head;   // DKOM hides the process, not its threads
}
\`\`\`

Production sensors go further: they snapshot every \`ApcState.Process\`
target at boot and re-walk periodically — anything referenced by a live
thread but absent from the list gets convicted. That diff is exactly what
KF-Sentinel v1 builds in m1.l4.

## Handle tables: who else knows you exist

Row #3. Every \`_EPROCESS\` embeds an \`ObjectTable\` pointer to its
\`_HANDLE_TABLE\` — the record of objects *this process holds handles to*.
When \`services.exe\` opens lsass, that reference lives in services' table,
not in lsass's list node. Hide a process and its handles remain fully open
elsewhere.

User mode enumerates them with \`NtQuerySystemInformation\
(SystemHandleInformation)\`; ring 0 does the same. ntsim models class 16/64
with EX-style entries — document your layout assumptions when you parse:

\`\`\`c
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    ULONG UniqueProcessId;     // owner
    ULONG HandleAttributes;
    ULONG GrantedAccess;
    USHORT HandleValue;
    USHORT CreatorBackTraceIndex;
    PVOID Object;              // ntsim: target _EPROCESS — the cross-ref!
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
\`\`\`

Scan the entries, group by \`Object\`, and you have a process inventory that
never touches \`ActiveProcessLinks\`. In the lab worlds three seeded pairs
are waiting: \`services.exe→lsass.exe\`, \`winlogon.exe→lsass.exe\`, and —
usefully for m1.l4 — \`kfsample.exe→kftarget.exe\`.

## Process-start telemetry: the birth certificate

Row #4. Independent of all lists above, the kernel *announces* creations to
registered observers. The documented driver API:

\`\`\`c
PsSetCreateProcessNotifyRoutineEx(NotifyCb, FALSE);
// NotifyCb receives PS_CREATE_NOTIFY_INFO; writing a negative
// info->CreationStatus BLOCKS the creation — how sensors quarantine
\`\`\`

Production ETW adds autologgers and the Threat-Intelligence providers on
top, but the shape is identical: an event emitted at creation time, before
any hiding can happen. A process that appears in telemetry but not in the
list was hidden *after birth* — timestamp evidence no DKOM can rewrite.
Module 15 turns this into a full EDR-sensor lab with hand-written callback
machine code.

## The cross-check matrix

| edit | breaks #1 | caught by |
|---|---|---|
| DKOM unlink | yes | #2 threads, #3 handles, #4 telemetry, pool carve |
| handle stripping (anti-#3) | no | #1/#2/#4 unchanged — mismatch elsewhere |
| thread-object forgery (anti-#2) | no | #1/#3/#4 unchanged |

No single edit satisfies all four records at once — that asymmetry is why
EDRs ship several sensors and why this course keeps saying: *one list is an
opinion, several independent lists are evidence.*

## Try it now

Boot the debugger and confirm rows #1–#3 exist in a pristine world:

\`\`\`
kd> !process 0 0                  # row 1: the list everyone walks
kd> !process 0 4                  # row 2: every process has live threads
kd> !process kfsample 7           # ...with ApcState pointing home
kd> !handles                      # row 3: who holds handles to whom
kd> !handles kfsample             # ...filtered to one owner's table
\`\`\`

Then jump to m1.l2, unlink \`kftarget.exe\`, and watch which rows still
remember it: \`!process 0 0\` goes quiet while \`!process <eproc> 7\` on the
carved address still prints its thread, \`ApcState->kftarget.exe\` — and
\`!handles\` still shows kfsample's handle against it.
`;
