/** Lesson body: m5.l1 — Tracing & anti-tracing (markdown). */
export default `## The trap flag: hardware single-stepping

A debugger "steps" a program by flipping **one bit** in the CPU: bit 8 of
EFLAGS/RFLAGS, the **trap flag (TF)**. The dance is pure silicon:

1. Debugger sets \`TF = 1\` in the thread's flags register.
2. The CPU executes exactly ONE instruction.
3. Hardware raises debug exception vector 1 (\`INT 1\`,
   \`EXCEPTION_SINGLE_STEP\`, NTSTATUS \`STATUS_SINGLE_STEP\`) at the next
   instruction boundary — and **auto-clears TF** on delivery.
4. The OS traps the event and hands it to the attached debugger, which
   refreshes registers/memory in its UI and waits.

Every register peek, every memory window, every "step over" in WinDbg or
x64dbg is this loop. Which makes bit 8 a tripwire: software can watch for
it too.

## Variant A — reading your own trap flag

\`PUSHFQ\`/\`POPFQ\` move the flag register through memory like any value:

    pushfq                  ; live RFLAGS onto the stack (TF = 1 if traced)
    pop     rax
    test    rax, 100h       ; bit 8 set?
    jnz     debugger_found  ; -> crash routine / decoy logic / silent exit

No API is called, no handle touched — nothing a traditional hook can see.
The CPU itself is the informant.

## Variant B — injecting TF to hijack the exception flow

Instead of passively reading TF, protection code *manufactures* the
exception and checks who answers it:

    pushfq
    or      qword [rsp], 100h   ; arm bit 8 on the stack copy
    popfq                       ; load it back - TF now really set
    nop                         ; <- next instruction raises INT 1

- **Running clean:** the program's own vectored exception handler (VEH)
  catches \`EXCEPTION_SINGLE_STEP\` internally and execution continues
  seamlessly.
- **Under a tracer:** the debugger intercepts INT 1 FIRST — it assumes the
  event is its own single-step machinery firing — swallows it, and the
  guest VEH never runs. The driver notices its handler starved and you are
  burned.

## Advanced — MOV SS stalling

A debugger may try to launder the flags before \`pushfq\` reports them. The
counter-move abuses an ISA rule: loading a segment register suppresses
interrupts, traps **and debug exceptions** until after the following
instruction:

    mov     ax, ss
    mov     ss, ax          ; inhibit window opens
    pushfq                  ; executes UNMASKED - tf still true on stack
    pop     rax             ; accurate snapshot before anyone intervenes

The pending single-step exception cannot fire until after \`pushfq\`, so the
snapshot always sees reality. This exact idiom ships in real packers and
anti-cheats today.

## The lab

The world boots \`kftrace.sys\`, a protection driver holding a payload
secret behind three such tripwires, with \`TraceVeh\` registered as its
vectored handler and \`g_AntiTraceEnabled\` as the master gate:

1. "!traceinfo" → map the defenses; submit TraceVeh's address. (answer 1)
2. "!trace on" arms a simulated tracer (TF set, INT 1 intercepted) — run
   "!selftest" once and count how many EXCEPTION_SINGLE_STEP events were
   swallowed before TraceVeh ever saw one. (answer 2)
3. Detach, clear the gate byte with "eb", rerun "!selftest": every check
   reads clean and the secret prints. Submit it. (answer 3)

## Defensive framing

Anti-tracing is why "just step through it" fails against hardened binaries:
detection via variant A/B costs the analyst hours and silently poisons the
investigation. Defenders reuse the same primitives in reverse — EDRs and
instrumentation frameworks detect *foreign* VEHs and TF games inside
protected processes, and hypervisor-based stepping hides the debugger below
the guest so no guest-visible flag ever flips. Know both directions: the
bit is only eight dollars of state, but who may read or write it decides
who is watching whom.
`;
