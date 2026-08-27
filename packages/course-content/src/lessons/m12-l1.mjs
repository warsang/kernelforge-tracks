/** Lesson body: m12.l1 — Ring-0 → SMM escalation (markdown). */
export default `## The vault nobody locked

On the \`smm-vault\` world the firmware parks a secret inside SMRAM and
an SMI handler that runs at \`SMBASE+0x8000\`. Power-on SMRAMC is
\`G_SMRAME=1, D_LCK=0\` — closed but **unlocked**. One PCI config write
opens the door:

    mov dword ptr [0xCF8], 0x8000009Ch   ; bus0 dev0 fn0 reg 0x9c
    mov al, 09h                          ; D_OPEN | G_SMRAME
    out 0xCFC, al

With \`D_OPEN=1\` ring 0 can read/write SMRAM exactly like normal DRAM.

## Writing the exploit

Your driver must:

1. Open SMRAM (config write above).
2. Overwrite the SMI handler at \`TSEG_BASE+0x8000\` with your own bytes —
   a stub that copies the secret into a landing page the lab watches.
3. Close SMRAM again (\`SMRAMC = 0x01\`) to cover your tracks.
4. Latch an SMI: \`out 0xB2, 1\`.

The lab dispatches the latched SMI for you after DriverEntry returns,
then dumps the landing page. If your handler ran, the secret is there.

## Why students should care

This is the exact shape of every "SMM injection" bug: a missing lock plus
handler patching equals code execution below the OS. Vendors fix it by
setting \`D_LCK\` in firmware before the OS boots — try setting it in your
driver *after* the heist and watch \`!smmc\` refuse future opens.

## Flag checklist

- Landing page ASCII shows the secret → flag 1.
- After your driver sets \`D_LCK\`, what does \`!smmc\` report for D_OPEN? → flag 2.
`;
