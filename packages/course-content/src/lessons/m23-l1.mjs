/** Lesson body: m23.l1 — DKOM field labs (markdown).
 *  Hands-on: PPL removal + Cid spoofing. Field guide for the rest of the
 *  #11 lab list: handle-pointer swap, SMEP toggle, CR0.WP page work and the
 *  Van1338 notify-race. */
export default `## DKOM beyond hiding

m1.l2 taught the classic unlink. Every other kernel object with a pointer,
flag or id is equally editable — this module walks the six edits that
matter, two hands-on.

## Lab 1 — strip PPL from lsass (hands-on)

**PPL** (\`_EPROCESS.Protection\`, a \`_PS_PROTECTION\` bit-pack: Type<<4 |
Signer) is why \`ZwOpenProcess\` against lsass answers ACCESS_DENIED even
from SYSTEM. The whole castle rests on ONE byte:

\`\`\`
kd> !openprocess 108                       # -> STATUS_ACCESS_DENIED
kd> !eproc lsass                           # note Protection (+0x87a)
kd> eb <lsass+Protection-offset> 00        # DKOM: Light|WinTcb -> none
kd> !openprocess 108 0x143a                # -> STATUS_SUCCESS + handle
secret=kf-ppl-off
\`\`\`

Detection: PPL drops are loud to anyone diffing Protection bytes over time
(exactly what m15's sensor does) — the byte has no legitimate runtime
writer.

## Lab 2 — wear System's Cid (hands-on)

Overwrite kftarget's \`UniqueProcessId\` (+0x440) with 4 and the process
list shows TWO entries claiming Cid 4:

\`\`\`
kd> !process 0 0
...
PROCESS ffffb80000003590  SessionId: none  Cid: 0004 ... ImageFileName: kftarget.exe
\`\`\`

Why that is mostly theater: only the LIST label changed. The thread's
\`CLIENT_ID\`, its ApcState back-pointer and every open handle still carry
the old identity — the same cross-check asymmetry as m1.l0 row #2/#3.
Spoofing to 0 is the "invisible PID" variant; both break tooling more than
they hide you.

## The field guide (labs in progress)

- **Handle-pointer swap**: find an existing RWX handle some process (e.g.
  notepad) holds via \`!handles\`/SystemHandleInformation, rewrite the
  HANDLE_TABLE_ENTRY's Object pointer at the OWNER's table to point at your
  game EPROCESS — the owner now wields a "game handle" without ever opening
  one. Detection: handle values pointing at objects whose object-type/quota
  history disagrees with the owner.
- **SMEP toggle**: CR4.SMEP (bit 21) is what makes kernel pages execute but
  user pages fault when in ring 0. Clearing it (DKOM-flavored writes go
  through \`mov cr4\` intercepts here) lets a ret2usr payload run — the m12
  SMM labs show the escalation shape; our HVCI analog already bugchecks
  WP-clears (m2.l3), and SMEP-clears are the next check to land.
- **CR0.WP vs per-page supervisor flips**: clearing CR0.WP (bit 16)
  write-enables ALL read-only pages globally and instantly trips the HVCI
  analog. The surgical alternative: flip a single PTE's Supervisor bit or
  map the frame RW through a self-managed alias — no global flag moves.
- **Notify-race (Van1338)**: callback arrays are read twice — once to
  enumerate, once to invoke. Free/unmap your callback between those reads
  and the kernel invokes freed memory or skips you; race the window with a
  concurrent unload thread. Detection: re-walk the array after each
  invocation and compare.

## Flags

Lab 1: the Protection byte hex BEFORE your edit; the NTSTATUS name the
denied open returns; the secret printed by the first successful
\`!openprocess 108\`. Lab 2: how many processes list Cid 0004 after the
spoof; which per-thread structure still records kftarget's true identity.
`;
