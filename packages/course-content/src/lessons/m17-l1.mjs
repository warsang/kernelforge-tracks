/** Lesson body: m17.l1 — userland anti-cheat bypass gauntlet (markdown). */
export default `## Ring 3 wants a fight

Before kernel drivers enter the picture, commercial anti-cheats run a
whole battery in user mode. This world reproduces the classic set from
the TryBypassMe crackmes and ssno's TAC teardown: **process-name and
window-title blacklists**, **multi-method debugger detection**
(PEB.BeingDebugged, NtGlobalFlag & 0x70, ProcessDebugPort), **runtime
XOR-encrypted stats with shadow-copy canaries**, and a **CRC-guarded AC
thread**.

## The lab

1. \`!actrace\` dumps every vector with live state — five total; that
   count is your first answer.
2. Spoof what the blacklists see (\`!spoof-process\`, \`!spoof-window\`)
   — exactly like renaming cheatengine.exe and hex-editing its window
   title in the real crackme.
3. Clean the PEB artifacts the debugger left (BeingDebugged byte,
   NtGlobalFlag mask, debug port).
4. Raise stats through the game's own API \`!setstat\`: it keeps the XOR
   encryption and the AC shadow copy coherent. Poke values raw and the
   canary vector trips on the next evaluation.
5. \`!godmode\` re-runs all vectors; quiet + god-tier stats prints your
   secret.

## Why the canary matters

Encrypted-live + shadow-copy is how ACs catch "dumb WPM" trainers:
any write that skips their update path desynchronizes the pair. Real
sensors add write-who instrumentation (guard pages, VEH) on top — same
idea at ring 0 becomes ObRegisterCallbacks handle stripping.

### Further reading

- UnknownCheats — TryBypassME v1-v3 + Kernel Edition thread (vector-by-vector solutions)
- ssno.cc — "Reverse Engineering Call Of Duty Anti-Cheat" (TAC vectors, honeypot working-set scan)
- ridpath/gamehacking-cheatsheet — anti-anticheat evasion matrix
- everdox.blogspot.com — debugger-detection primitives (KUSER_SHARED_DATA, time-slip DPC)
- secret.club — "Process on a diet" (job-object anti-debug), thread-based checks
`;
