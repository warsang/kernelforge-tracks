/** Lesson body: m20.l2 — Userland hooking techniques (markdown). */
export default `## Ring 3 plays the same game with different tables

Usermode hooks redirect a process's own API calls. No PatchGuard watches
them — the "verifier" is instead anticheat integrity scans of your host
process (m17) and the fact that any hook you install can be undone by the
next update. The taxonomy:

### IAT hooks — redirect the pointer

Every imported function a module calls goes through its Import Address
Table. Overwrite one entry and every \`call [iat]\` in that module routes
to you, without touching a single byte of code:

\`\`\`
before:  call [iat: kernel32!OpenProcess]  -> kernel32!OpenProcess
after:   call [iat: my_openprocess]        -> trampoline -> real thing
\`\`\`

Cheapest technique, per-module scope only, and defeated trivially by
callers who resolve with \`GetProcAddress\` at runtime — which anticheats
do precisely because IATs are the first place everyone looks.

### EAT hooks — poison the directory

Flip it around: rewrite the export address table of the *provider* DLL so
every future \`GetProcAddress("OpenProcess")\` hands out your address. One
write, process-wide effect — but only late binders consult the EAT, and
static imports resolved at load time never look at it again.

### Inline hooks — the ring-0 classic, ported down

The same jmp-over-patch you used in m3, applied to a usermode target:
copy the original prologue into a trampoline, write your jump, route calls
through your logic back into the trampoline. The strongest general-purpose
technique; module 6's sogen lab builds exactly this against
\`cl_sendinput\`. Detection is byte-comparison of each interesting export's
first instructions against the on-disk image (module 19's grid walk).

### VEH / hardware-breakpoint hooks — leave no byte changed

Register a vectored exception handler, then plant debug registers (DR0-DR3)
or a \`PAGE_GUARD\` mapping on the target. The exception dispatch routes
execution through you; .text stays byte-for-byte pristine so integrity
scanners see nothing. You pay per-access exception cost, debug registers
are scarce (four) and visible in the thread context.

### Thread hijack — no import, no table

Suspend the victim thread, swap its RIP via
\`GetThreadContext\`/\`SetThreadContext\`, point it at your gadget, resume.
Nothing is patched anywhere — but synchronization is painful and it scales
badly across threads.

## Which one when?

| goal | pick | avoid |
|---|---|---|
| redirect one module's calls, fast prototype | IAT | production AC targets |
| catch late-binders globally in-process | EAT | static imports |
| full control of one function | inline | heavily integrity-scanned targets |
| pristine-.text requirement (live AC) | VEH/DRx | performance-critical paths |
| zero footprint, single-threaded victim | thread hijack | anything multithreaded |

Module 6 walks the inline path hands-on; module 17 makes you survive an
anticheat gauntlet that detects half of this table.

## Flags

Answer from the text — then go run the hands-on labs it points at:

1. Three-letter name of the technique that overwrites a module's Import
   Address Table entries.
2. Three-letter name of the technique that leaves .text pristine and
   redirects execution via vectored exceptions or debug registers.
`;
