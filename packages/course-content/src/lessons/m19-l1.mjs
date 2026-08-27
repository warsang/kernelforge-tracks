/** Lesson body: m19.l1 — reversing the sensor statically (markdown). */
export default `## Read the sensor without running it

Dynamic analysis tripped alarms in m15; static analysis never executes a
byte. Over kfwatch.sys you recover function boundaries from prologue
signatures (\`!funcs\`), resolve rel32 transfers, and read fixture-shaped
pseudo-C via \`!pseudocode <addr>\` — a deterministic decompiler path for
known sensor idioms while the full Ghidra wasm engine stays vendored-out.

## The lab

1. \`!funcs kfwatch.sys\` — boundary scan over the .text grid; submit
   the recovered function count.
2. Submit the registered process-callback VA you found in m15
   (!notifyroutines still knows).
3. \`!pseudocode <callback>\` renders the handler as C: Length check,
   two qword compares against L"kfim"/L"plan", the 't' word probe, and
   the CreationStatus store at +0x40 — i.e., decimal offset 64, the
   exact kill-switch DbgMan documents in csagent.sys.

## From here

The same loop drives momo5502's integrity-check teardowns and Arxan
unwrapping: recover boundaries, resolve transfers, name idioms. When the
vendored Ghidra decompiler lands, !decomp upgrades from structural notes
to full pseudocode without changing this lab.

### Further reading

- 0xdbgman — Inside a kernel sensor, Section 2 (CS_BuildCreationEvent layout)
- momo5502.com — "Reverse Engineering Integrity Checks in Black Ops 3", MW2 AI-decompilation posts
- secret.club — Striga x86-to-LLVM lifting; MBA deobfuscation via equality saturation
- whereisr0da.github.io / codeneverdies.github.io — static RE field notes
`;
