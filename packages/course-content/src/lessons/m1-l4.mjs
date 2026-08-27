/** Lesson body: m1.l4 — Building KF-Sentinel v1 (defense, markdown). */

export default `## From breaking the kernel to guarding it

Modules 1 taught you three ways to lie to Windows from ring 0: hide a
process by unlinking it, map code without loading it, and ship both inside
a module nobody has heard of. Now you build the thing that catches them.
**KF-Sentinel** is your progressive anticheat/EDR: every module adds one
sensor to it, and every later attack lab has to get past what came before.

## The shape of a kernel sensor

Production EDRs and anticheats share one skeleton:

1. **Acquire truth** that does not depend on what you are checking. The
   process list can be edited, so your second opinion comes from carving
   memory for signatures — data the attacker forgot to hide.
2. **Cross-check two sources**. One source lies; two independent sources
   rarely lie *consistently*. A name carved out of an EPROCESS pool window
   while ActiveProcessLinks no longer references it is the DKOM tell.
3. **Classify against an allow-list**. The loaded-module list tells you
   which ranges are legitimate code. Executable-looking bytes outside every
   listed range are unbacked execution — the manual-mapping tell.
4. **Emit telemetry** (\`DbgPrint\` here, ETW/event tracing in production)
   instead of acting on your own. Decisions belong in policy engines with
   human review, not in the sensor.

## Sensor 1 — list-vs-carve process check

The walk side uses exactly the offsets from m1.l2:

\`\`\`
head.Flink -> [EPROC.links] <-> ... ; count entries, collect names
\`\`\`

The carve side scans the synthetic EPROCESS pool window byte-wise for the
image-name signature. Your starter bakes the window bounds; production
sensors discover them from \`MmGetPhysicalMemoryRanges\` plus pool-tag
statistics. When the carve finds \`kftarget.exe\` but the list walk cannot,
you have proven DKOM from inside the kernel:

| source | sees kftarget? |
|---|---|
| ActiveProcessLinks walk | no |
| pool carve for "kftarget" | yes → hidden |

## Sensor 2 — unbacked executable classification

Telemetry hands you a suspicious page. Is it code? Does any loaded module
own it? Walking the loader list (\`PsLoadedModuleList\`-style, our linked
ring at a known head) gives you every legitimate range:

\`\`\`
cur = LdrHead->Flink;
while (cur != LdrHead) {
    base = *(ULONG64*)((char*)cur + 0x30);  // DllBase
    size = *(ULONG64*)((char*)cur + 0x40);  // SizeOfImage
    if (va >= base && va < base + size) covered = TRUE;
    cur = cur->Flink;
}
\`\`\`

Executable prologues outside every range are how manual-mapped payloads,
shellcode pages and cheat drivers look *identical* — no module name, no
MZ header story, just anonymous executable bytes.

## Custom debugger extensions in this lab

None new — deliberately. Every command you need already exists: \`!process
0 0\`, \`lm\`, \`dt nt!_EPROCESS <addr>\`. What is new is that a *driver*
reproduces their answers from inside the guest. That is the difference
between using tooling and building it.

## Defensive framing — what real products do

- **EDR process inventories** never trust one list: EDRs cross-reference
  ActiveProcessLinks against handle tables, KTHREAD→ApcState references and
  ETW process-start events. Any single-source mismatch raises detection.
  Those three second opinions deserve unpacking (the m1.l0 primer is the
  deep dive; here is the field guide):
  - **KTHREAD→ApcState** — every \`_ETHREAD\` embeds a \`_KTHREAD\`, and its
    \`ApcState.Process\` field records which address space the thread is
    currently attached to. For a normal thread that is its own \`_EPROCESS\`.
    So even if you unlink an \`_EPROCESS\` from the list, every one of its
    threads still *points at it* from kernel memory the edit never touched.
    Detectors walk each thread's ring and read that pointer.
  - **Handle tables** — every \`_EPROCESS\` carries an \`ObjectTable\`: the
    record of kernel objects *this process holds handles to*, one row per
    open handle. If any process ever opened a handle to yours (an EDR's
    own scan, a log collector, your sample's parent), that reference sits
    in the opener's table — invisible to list edits, enumerable via
    \`NtQuerySystemInformation(SystemHandleInformation)\` or \`!handles\`
    here.
  - **ETW process-start events** — the kernel announces every process
    creation to registered observers: driver callbacks
    (\`PsSetCreateProcessNotifyRoutineEx\`) and the ETW
    Threat-Intelligence providers user-mode sensors subscribe to. The
    announcement happens at birth, before any hiding can occur, so a
    process present in telemetry but absent from the list was hidden
    *after* it started — timestamped evidence no list edit rewrites.
- **Anticheat integrity roots**: games re-walk PsLoadedModuleList from an
  independent root (often hypervisor-backed) and compare against a signed
  baseline captured at boot. Kernel-mode cheats must then fight the
  hypervisor — see phase 4 of this platform's roadmap.
- **Pool tag accounting**: \`!poolfind\`-style attribution lets defenders
  notice allocations whose tags belong to no known driver.
- Your compiled sensor is small, but its architecture — acquire, compare,
  classify, emit — is the same shape as systems shipping at scale.

Compile the starter, load it into the sentinel world, read its findings
from the DbgPrint buffer, submit.
`;
