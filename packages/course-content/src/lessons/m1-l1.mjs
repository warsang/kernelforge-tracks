/** Lesson body: m1.l1 — The x64 kernel landscape (markdown). */
export default `## What you are looking at

The console on this page is a WinDbg-flavored front-end over **ntsim** — an
emulated x64 Windows kernel whose every structure offset comes from real
per-build tables (Vergilius project dumps of actual Windows builds). When you
boot a lab you get a live kernel *model*: processes, loaded modules, a KPCR,
and a DbgPrint buffer — all inspectable, nothing to install.

## Kernel virtual address space

On x64 Windows the kernel lives in the top half of the address space
(canonical addresses with the high bits set):

| range | contents |
|---|---|
| \`0xFFFF8000'...\` and above | kernel code, pools, driver images |
| below \`0x00008000'...\` | user space (not modeled in these labs) |

The core executive image is **ntoskrnl.exe**. Around it sit HAL, drivers, and
anything a rootkit chose to map.

## Loaded modules

\`\`\`
kd> lm
kd> !drivers
kd> x nt!Ps*
\`\`\`

lists each module's base, end, and name. Windows ships a known set
(\`ntoskrnl.exe\`, \`hal.dll\`, ...); anything else in the list deserves a second
look. Boot the lab and find the module that does not belong. Note its exact
file name — that is your first answer.

## Processes and _EPROCESS

Every process is described by an \`_EPROCESS\` structure allocated from
non-paged pool. The kernel keeps them in a circular doubly-linked list rooted
at \`nt!PsActiveProcessHead\`. Walk it yourself:

\`\`\`
kd> !process 0 0        # list every process: EPROCESS, Cid, ImageFileName
kd> !process <pid>      # full field walk of one _EPROCESS
kd> dt nt!_EPROCESS     # layout-only view straight from build tables
\`\`\`

\`!process 0 0\` prints one line per process. Somewhere in the list is a
canary process named \`kfsample.exe\`; its decimal PID (**Cid**) is your
second answer.

## Field work

- \`dt _EPROCESS <addr>\` walks any address through the active build's table.
- \`r\` shows the register context; \`k\` shows where rip sits.
- \`? <expr>\` evaluates addresses (\`? nt!PsActiveProcessHead\`-style math);
  \`u <addr>\` disassembles; \`da\`/\`du\` read strings out of memory.
- \`!analyze -v\` summarizes state including recent DbgPrint output.

## Native commands vs debugger extensions

Real WinDbg has two layers, and so do we:

| layer | examples | where it lives |
|---|---|---|
| native engine commands | \`lm\`, \`dt\`, \`r\`, \`k\`, \`eb\`, \`db\`, \`s\`, \`u\`, \`uf\`, \`x\`, \`?\`, \`da\`, \`du\` | built into the debugger |
| **debugger extensions** | everything starting with \`!\`: \`!process\`, \`!drvobj\`, \`!dh\`... | separate DLLs loaded on demand |

Any \`!\` command is an *extension*: extra analysis code bolted onto the
debugger, exactly like the EDR/anticheat helper DLLs you would load next to
a real kd. Throughout this course every time we hand you an extension we say
so explicitly — and show you the driver-mode C that produces the same
information from inside a running system instead of from a debugger.

**What a driver does instead of \`lm\`/\`!process\`:** it walks the same lists
in kernel mode, or registers callbacks to learn about changes as they happen:

\`\`\`c
// Process inventory the way an EDR sensor does it — event-driven, not polled
NTSTATUS SensorRegisterCallbacks(void)
{
    // fires for every process creation in the system
    return PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCb, FALSE);
}

VOID ProcessNotifyCb(HANDLE parentId, HANDLE pid, PUNICODE_STRING imageName,
                     PS_CREATE_NOTIFY_INFO *info)
{
    // info == NULL means the process is EXITING
    DbgPrint("sensor: %wZ pid=%llu %s\\n", imageName, (ULONG64)pid,
             info ? "create" : "exit");
    // production sensors forward this to a user-mode collector over IOCTL /
    // filtered communication port — the birth certificate of every process
}
\`\`\`

## Defensive framing

Everything a defender's tooling does — Process Explorer, EDR process
inventories, live-kd — is built on walking exactly these structures. Three
things separate a defender from a debugger tourist:

1. **Baseline discipline**: you cannot spot "the module that does not belong"
   without knowing the signed, expected set. EDRs ship allow-lists keyed by
   image name + signer + hash; anticheats snapshot at boot and re-verify.
2. **Event-driven telemetry**: polling lists loses races; the callback APIs
   (\`PsSetCreateProcessNotifyRoutineEx\`, \`PsSetCreateThreadNotifyRoutine\`,
   \`PsSetLoadImageNotifyRoutine\`) push every change to your sensor.
3. **Cross-validation habit**: one list is an opinion, several independent
   lists are evidence. This habit is the spine of this whole course.

In module 1's final lesson you compile the first version of **KF-Sentinel**
— your own anticheat sensor — and use these exact habits to catch a hidden
process and unbacked code from ring 0.
`;
