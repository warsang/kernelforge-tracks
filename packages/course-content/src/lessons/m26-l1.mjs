/** Lesson body: m26.l1 — ETW architecture & the user-mode blindfold (markdown). */
export default `## Telemetry's front door

Every Windows telemetry stream funnels through **ETW** (Event Tracing for
Windows): providers register with a GUID, build events in user mode, and
hand them to \`ntdll!EtwEventWrite\`, which validates the caller's
**RegHandle** and routes the event toward kernel trace buffers and the
consumers attached to them (Sysmon, EDR agents, your anticheat).

That makes the wrapper layer the cheapest kill in the whole pipeline:

\`\`\`
before:  EtwEventWrite: 48 89 5c 24 08 ...   ; real prologue
after :  EtwEventWrite: 31 c0 c3             ; xor eax,eax; ret
\`\`\`

One three-byte patch and every event from every provider in the process
"dies quietly": no crash, no failed API, no log line — just a growing gap
between what happened and what was reported. The RegHandle variant is even
quieter: zero the handle your process cached at registration and events
fail validation before anything is built.

## The lab world (\`etw-blind\`)

The emulated game process emits through a materialized ntdll stub page:

\`\`\`
!providers            ; SauerGame + AC-Telemetry RegHandles
!etwpump 8            ; emit 8 modeled events
!etwtrace             ; delivered vs suppressed
x 0x7749e2a0          ; the wrapper bytes you are about to change
eb 0x7749e2a0 31 c0 c3
!etwpump 8 ; !etwtrace   -> all DROPPED (wrapper patched)
hookscan              ; the EDR view: ntdll page modified
\`\`\`

Restore the pristine bytes (hookscan prints them), pump again, and the
trace reads honest end-to-end.

## Who catches this in the real world

- **PatchGuard: silent** — this is userland memory.
- **EDR self-protection**: agents re-check \`ntdll!.text\` against a clean
  remap of the on-disk image and reload/repair on drift; many also issue
  direct syscalls so their OWN telemetry never traverses the wrappers.
- **Gap alarms**: consumers expect heartbeats. A quiet stream is itself a
  signal — exactly what \`!etwtrace\` shows you.
- **Anticheats** hook-scan ntdll in-process like m17 taught, for precisely
  this reason.
`;
