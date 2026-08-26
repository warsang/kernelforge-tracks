/** Lesson body: m26.l2 — kernel logger-context tampering (markdown). */
export default `## Blinding the kernel's own recorder

User-mode patches only blind one process. The kernel's shared streams —
the **Circular Kernel Context Logger (CKCL)** class of sessions — feed
Sysmon and every EDR from one pool-resident **\`_WMI_LOGGER_CONTEXT\`**.
Its \`EnableFlags\` bitmask decides which event classes the kernel even
builds. Zero it and providers keep returning success while the trace
buffers starve:

| field | offset | meaning |
|---|---|---|
| LoggerId | +0x00 | session id |
| EnableFlags | +0x10 | event-class gate — the blindfolding knob |
| GetCpuClock | +0x14 | timestamp source selector |

This is DKOM with a telemetry payoff: find the context, write one dword.
No code bytes change, no hooks remain, and — because logger contexts are
pool objects, not protected structures — **PatchGuard never looks**.

## The lab world (\`etw-kernel\`)

A CKCL-shaped context sits at a fixed VA with baseline flags 0xff:

\`\`\`
kd> !etwloggers                 ; healthy: EnableFlags=0x000000ff
kd> !etwpump 8                  ; delivered: 8  suppressed: 0
<compile ATTACK-ETWTAMPER; it zeroes EnableFlags at CKCL+0x10>
kd> !etwpump 8                  ; delivered: 0  suppressed: 8
kd> !etwloggers                 ; verdict: BLINDED (+ repair line)
\`\`\`

The suppression is SILENT by design: providers still succeed, no bugcheck,
no event. That silence is exactly why defenders checksum these contexts.

## Who catches this in the real world

- **PatchGuard: silent** (again — pool object, not protected state).
- **EDR/Sysmon agents** running in-kernel checksum their own sessions'
  control fields and re-assert them; a flipped EnableFlags is convicted on
  the next poll (your Sentinel v7 lab).
- **Windows 11 tamper protection**: secured loggers reject external edits
  outright — the model here predates that hardening.
- **Consumer gap alarms**, same as the user-mode half of this module.
`;
