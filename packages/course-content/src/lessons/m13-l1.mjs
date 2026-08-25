/** Lesson body: m13.l1 — SMBASE relocation persistence (markdown). */
export default `## Persistence below ring 0

Entering SMM saves the interrupted CPU state into the **SMRAM save-state
area**, 512 bytes just below \`SMBASE+0x10000\`. On \`RSM\` the CPU loads
that area back — including a field that tells it *where the save area and
handler live next time*: SMBASE itself.

The canonical anchor every SMM exploit knows:

    SMBASE field: old_SMBASE + 0xFB04   (SDM Vol.3, ch.34)

If your (already-patched) handler rewrites that dword before RSM, the CPU
**relocates**. The next SMI enters at \`NEW_BASE+0x8000\` — code of your
choosing, in ring -2, invisible to the OS.

## The lab

On \`smm-reloc\` your driver:

1. Opens SMRAM (you know this dance from Module 12).
2. Plants a stub at \`NEW_BASE+0x8000\` that stamps \`MF2K\` into the
   second landing page.
3. Patches the *current* handler to store \`NEW_BASE\` at
   \`OLD_BASE+0xFB04\`.
4. Closes SMRAM and fires port 0xB2.

The lab runs two SMIs for you. After the first, RSM relocates; the second
enters your planted stub. \`!smram\` shows \`relocated=1\` and the new base.

## Defense

Firmware must lock SMRAM (\`D_LCK=1\`) before boot and validate the
save-state on entry. Once D_LCK is set, this entire module's attacks are
dead — try setting it first in your driver and watch the relocation fail.
`;
