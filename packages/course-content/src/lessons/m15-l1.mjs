/* eslint-disable max-len */
/** Lesson body: m15.l1 — kernel callbacks & EDR sensors (markdown). */
export default `## Where EDRs actually see you

A KF-Watch-class sensor owns six kernel vantage points: process-create,
thread-create, image-load notifications, object callbacks, registry
callbacks and a file-system minifilter. This lab boots the first one for
real: \`kfwatch.sys\` registered a \`PsSetCreateProcessNotifyRoutineEx\`
callback whose **machine code executes on the emulated CPU** — under the
JS interpreter and QEMU alike.

The Ex callback receives \`(PEPROCESS, PPS_CREATE_NOTIFY_INFO)\`. When it
writes a negative NTSTATUS into \`CreateInfo->CreationStatus\` (+0x40),
the process is never born. That single store is CrowdStrike's kill
switch — DbgMan's teardown walks the same path in csagent.sys.

## The lab

1. \`!notifyroutines\` lists every registered callback with symbols.
2. \`!notifytest kfimplant.exe\` drives a spawn through PspProcessNotify;
   watch it die with STATUS_ACCESS_DENIED (0xC0000022).
3. Disassemble the callback (\`db\`/\`u\` around its VA) and find the name
   compare: Length==0x1A, then two qword immediates L"kfim"/L"plan",
   then the 't' word.
4. Blind it: patch one immediate so the compare can never match, rerun
   \`!notifytest\`, and capture the telemetry-gap secret.

## Defensive framing

Everything you just did — enumerate callbacks, read their code, patch
one byte — mirrors real audit tooling (Sysmon-style visibility, callback
listing via \\Callback objects) AND real attackers. The difference is
authorization. Note what the sensor still saw: registration itself is
loud, and tampering with a registered callback is exactly what
PatchGuard-class integrity monitors exist to catch.

### Further reading

- 0xdbgman — "Inside a kernel sensor: How CrowdStrike Catches You" (six callback sources, CreationStatus kill)
- windows-internals.com (Yarden Shafir) — "Thread and Process State Change" (EDR hook evasion), ObRegisterCallbacks masks
- secret.club — drew, "Hiding execution of unsigned code in system threads"
`;
