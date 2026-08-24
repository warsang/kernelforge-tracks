/** Lesson body: m3.l1 — Inline hooks & control flow (markdown). */
export default `## What an inline hook is

Instead of replacing a pointer table (SSDT-style), an **inline hook** rewrites
the first bytes of a function's prologue to jump somewhere else — usually a
\`jmp rel32\` (\`E9 xx xx xx xx\`) into the attacker's code. Every caller,
kernel or user, now flows through the attacker first. The original instruction
bytes are typically copied to a trampoline so the hook can call the real
function and still look innocent.

## Reading a detour from a debugger

You cannot ask the kernel "are you hooked?" — you compare memory against
truth. Truth here is the pristine prologue recorded when each \`nt!\` export
was materialized:

\`\`\`
kd> !hookscan                       # diff live bytes vs pristine for every export
kd> !hookscan PsLookupProcessByProcessId
\`\`\`

A clean export prints its expected bytes; a hooked one shows both byte
streams plus where the jump lands (symbolized as module+offset). Repair is
the same primitive you used in the manual-map lab:

\`\`\`
kd> eb <thunk_addr> f4              # restore the original first byte(s)
\`\`\`

Because behavior gates on *live bytes*, restoring them instantly unhooks the
call — no reboot, no state flag.

## Prove it

\`\`\`
kd> !hooktest <Export> [args...]    # exercise the modeled call path
\`\`\`

Run it before and after your repair; the difference in return value **is**
the hook's payload.

## The lab

The world ships \`kfhook.sys\`. It detoured one executive routine so that
lookups for one specific PID come back \`STATUS_INVALID_PARAMETER\` — that
process has become unkillable-by-name for anything above it in the stack.

1. \`!hookscan\` → which export is detoured? (answer 1: exact export name)
2. The hook suppresses exactly one decimal PID. Find it — the detour page's
   strings and \`!hooktest\` probes will tell you. (answer 2)
3. Restore the prologue with \`eb\`, then \`!hooktest\` the lookup again:
   submit the symbolic NTSTATUS that comes back. (answer 3)

## Defensive framing

Inline hooks on \`nt!\` exports are the granddaddy of rootkit techniques and
still show up in game cheats (render/present hooks) and implants alike.
Detection families worth knowing: periodic prologue attestation (exactly what
you just did), call-target validation on the hot path, hypervisor EPT-based
shadow execution views, and control-flow guard technologies (XCFG / kCFG)
that make wild jumps fail before they land.
`;
