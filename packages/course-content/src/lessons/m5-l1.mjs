/** Lesson body: m5.l1 — Userland recon under a userspace emulator (markdown). */
export default `## From kernel space to process space

Everything so far lived in kernel land: EPROCESS lists, IRQL, pool guards.
This module drops you **inside a game process** running under a userspace
emulator (the same model of emulator the sogen project popularizes): no OS
underneath, just your PE image, the system DLLs it imports from, and an
emulator that controls every byte.

A graphical debugger docks above the console for this track: a disassembly
view with breakpoint gutter, registers, a hex memory viewer, module list,
and a pseudocode tab — the same layout you'd find in x64dbg or the sogen
playground. It reads the same world state your console commands mutate, so
\`scan\` hits light up in the memory viewer. The kd> console below stays the
primary interface; the panels are there to build the visual reflexes you
will need with real tools.

Game hacking starts the same way malware analysis does:

1. \`lm\` — enumerate loaded modules and their base addresses.
2. Find the game image (\`sauerbraten.exe\`) and its static layout.
3. Locate state worth reading: entities, health, positions.

## Finding the local player

The world ships a heap region with a fixed-layout entity array. Each entity:

| offset | field | notes |
|---|---|---|
| +0x00 | void* vtable | 8 bytes |
| +0x08 | int type | 0 = bot, 1 = player |
| +0x0c | int team | |
| +0x10..0x1b | float x,y,z | position triple |
| +0x24 | int health | what we want |
| +0x2c | char name[16] | NUL-padded |

You will not be told where the array lives. Use the console to hunt:

    kd> lm                        # modules; note sauerbraten.exe base
    kd> scan 0x02100000 0x10000 100 4    # find dword 100 (full health)
    kd> x 0x<addr>                # hexdump around a hit — look for names
    kd> !damage 25                # world takes 25 damage; re-scan to filter

The two-scan trick is the classic: values that survive both scans while
neighbors go stale are live state. The entity whose name reads \`kfgamer\`
is *you*.

## The lab

Boot \`sauer-recon\`, then:

1. \`lm\` → submit sauerbraten.exe's image base (full 0x-hex).
2. Two-scan for the local player entity → submit its address.
3. Work out the health offset inside the entity (use \`!damage\` +
   re-scan) → submit it as 0x-prefixed hex.

## Defensive framing

Every anti-cheat you will meet later (VAC, EAC, BattlEye) exists because
this workflow is trivial without them: unsigned memory readers, signature
scans over .text, entity-list walking. Understanding the offense is the
prerequisite for designing detection: handle stripping, integrity-checked
entity arrays, obfuscated/virtualized state layouts.
`;
