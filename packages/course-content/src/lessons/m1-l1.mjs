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
\`\`\`

lists each module's base, end, and name — exactly like WinDbg's \`lm\`.
Windows ships a known set (\`ntoskrnl.exe\`, \`hal.dll\`, ...); anything else in
the list deserves a second look. Boot the lab and find the module that does
not belong. Note its exact file name — that is your first answer.

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
- \`!analyze -v\` summarizes state including recent DbgPrint output.

## Defensive framing

Everything a defender's tooling does — \`Process Explorer\`, EDR process
inventories, live-kd — is built on walking exactly these structures. To spot
a compromised machine you must first know what an uncompromised list looks
like.
`;
