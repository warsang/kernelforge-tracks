/** Lesson body: m10.l1 — Static analysis with Ghidra-grade tooling (markdown). */
export default `## Reading binaries the way analysts do

Every lab so far let you watch live state. Reverse engineering starts
earlier: a blob of bytes, no symbols, no debugger attached yet. This
module wires **Ghidra's decompiler engine** into the platform as an
in-browser analysis pane over the same emulated worlds you already know.

## From bytes to functions

Before any decompilation, recovery has to answer two questions:

1. Where do functions start? Clang-emitted x64 prologues are highly
   regular (\`push rbp\` / \`mov rbp,rsp\` frames or \`.pdata\`-described
   routines); a boundary scanner walks executable sections and records
   candidates.
2. What do they call? \`E8 rel32\`/\`E9 rel32\` resolve to call/jump
   targets inside the image — the raw material of a call graph.

The console exposes this directly:

    kd> !funcs kfhook.sys      # recovered function table
    kd> !decomp <addr|symbol>  # decompile when the analysis pane loads

## The lab

Boot the \`api-hook\` world (Module 3's detoured driver) and use the
static-analysis commands instead of the live-behavior ones:

1. \`!funcs kfhook.sys\` → submit how many functions the boundary scan
   recovers.
2. Submit the VA where the scan places the *second* recovered function.
3. The detoured export's prologue is a \`E9 rel32\` trampoline into
   kfhook.sys (\`!hookscan\` resolves it for you). Submit that target VA
   as full 16-digit hex with 0x prefix.

## Defensive framing

Static analysis is how defenders triage unknown drivers before ever
executing them: prologue anomalies, calls into non-routine pages,
orphaned functions without symbols. Browser-side decompilation means
that triage workflow now runs entirely offline in a tab — no VM, no
license server, nothing leaves the machine.
`;
