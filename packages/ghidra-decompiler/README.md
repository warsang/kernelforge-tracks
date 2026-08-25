# @kernelforge/ghidra-decompiler

Static analysis for the debugger panes:

- `findFunctions(mem, start, len)` — deterministic x64 prologue/boundary scan
- `resolveRel32(mem, addr)` — E9/E8 target resolution
- `analyzeExtent(mem, start, len)` — boundaries + rel32 sites in one pass
- `writeFunctionGrid(mem, start, len)` — byte-stable code-fill helper used by
  scenario worlds so static labs are deterministic
- `decompile(...)` — real pseudocode via the vendored Ghidra native
  decompiler wasm (`vendor/README.md`); loud `DecompilerUnavailableError`
  until vendored
