/** Lesson body: m6.l1 — Userland hooks & input flow (markdown). */
export default `## Rewriting control flow in process space

Module 3 taught kernel detours (\`E9 rel32\` over an nt! export). The same
five-byte patch works identically in userland — and under a userspace
emulator you can watch every byte of it.

A "cheat" has been injected into the emulated game: the engine's input
function \`cl_sendinput\` was detoured so every input packet first detours
into a stub that rewrites view angles (aim assist) before jumping back.

## Finding and reading a detour

The console gives you the same toolkit as the kernel debugger, plus
userland-specific commands:

    kd> hookscan                  # diff .text against pristine snapshot
    kd> u 0x<addr>                # unassemble around a suspicious site

An \`E9\` opcode at a function's first byte is the classic trampoline:
target = site + 5 + rel32. Repair is mechanical, exactly like Module 3 —

    kd> eb <site> <original bytes shown by hookscan>
    kd> hookscan                  # clean again

## Proving the fix

With the prologue restored, \`!inputtest\` replays a scripted input batch
through the modeled engine path. While hooked, angles come back rewritten;
honest code returns them untouched and the engine prints its all-clear
secret.

## The lab

Boot \`sauer-hook\`, then:

1. \`hookscan\` → submit the VA of the detoured function.
2. Resolve the \`E9\` target from the printed rel32 → submit the stub VA.
3. Restore the original prologue with \`eb\` (bytes shown by hookscan),
   re-run \`hookscan\`, then \`!inputtest\` → submit the secret string.

## Defensive framing

Inline patching is the cheapest cheat primitive there is; defenses layer
integrity checks over hot functions (.text page guards, periodic hashing),
control-flow guard style validation before indirect transfers, and — on
modern Windows — virtualization-based integrity that makes user-mode
.text pages read-only W^X. In emulator-land we can also diff pristine vs
live memory at instruction granularity, which is exactly what \`hookscan\`
models.
`;
