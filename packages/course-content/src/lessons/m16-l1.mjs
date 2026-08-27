/** Lesson body: m16.l1 — SSDT & syscall hooking (markdown). */
export default `## The table every syscall obeys

Native APIs funnel through a dispatch table: entry N holds the address
of service N. On x64 Windows there is no single SSDT you can patch from
user mode any more — but rootkits and BYOVD payloads still detour the
*targets*, and integrity monitors still guard both layers. This world
models \`KiServiceTable\` as real u64 entries over API thunks; hooking
reuses the exact E9-rel32 machinery from module 3.

## The lab

1. \`!ssdt\` prints every service with its resolved target and marks
   inline detours. One service hides pid 888 from \`NtOpenProcess\`.
2. Resolve the E9 rel32: \`target = site + 5 + rel32\`. Submit the
   detour target VA inside kfvillain.sys.
3. Restore the pristine prologue with \`eb\` (!hookscan shows the
   expected bytes), re-run \`!ssdt\` until clean, and prove the lookup
   succeeds with \`!hooktest NtOpenProcess 888\`.

## PatchGuard & HyperGuard

Why can't malware do this on a stock box? Kernel PatchGuard re-verifies
critical structures — including service dispatch — and bugchecks on
tamper (0x109). With VBS, Secure Kernel Patch Guard extends the idea to
hypervisor-protected extents (Yarden Shafir's SKPG series). Labs like
this exist because defenders must rehearse the attack to build the tripwire.

### Further reading

- secret.club — "Bypassing kernel function pointer integrity checks", iPower's CVEAC-2020 EAC integrity bypass
- windows-internals.com — HyperGuard/SKPG parts 1-3
- revers.engineering — PatchGuard: Detection of Hypervisor Based Introspection P1/P2
`;
