/** Lesson body: m24.l1 — dispatch-layer hooks: attack theory (markdown). */
export default `## The hooks PatchGuard never looks at

Module 20 taught the bet: hook something PG-protected and a sweep ends
you. But half the kernel's control flow lives in structures PatchGuard
does **not** re-validate — because they are driver-owned, pool-resident,
and legally mutable at runtime:

| structure | what it controls | why rootkits love it |
|---|---|---|
| \`DRIVER_OBJECT.MajorFunction[28]\` | which routine services each IRP class for one driver | one qwrite filters/alters all I/O through that stack |
| \`_OBJECT_TYPE_INITIALIZER\` procedures (\`OpenProcedure\`, \`CloseProcedure\`, \`ParseProcedure\`...) | per-object-type access hooks under every handle grant | deny or log object opens below every user-mode check |
| \`HalPrivateDispatchTable\` entries | timing/context primitives the kernel calls constantly | subvert time, performance counters |

PatchGuard guards the SSDT, the IDT/GDT, core MSRs and ntoskrnl code
pages. It does **not** walk DRIVER_OBJECTs or OBJECT_TYPEs — legitimate
drivers rewrite those slots on every DriverEntry. That is exactly why the
classic Windows rootkits (and more than one game cheat) persist here.

## IRP MajorFunction hooking

Every \`\[DeviceIoControl\]\` against a stack lands in
\`DriverObject->MajorFunction\[IRP_MJ_DEVICE_CONTROL\]\`. Rewrite that slot
and you own the driver's entire IOCTL surface — no byte of any module's
.text changes:

\`\`\`
before:  MajorFunction[0x0e] -> kfser!IoCtlDeviceControl   (inside image)
after:   MajorFunction[0x0e] -> kfsnoop!FilterIoctl        (foreign)
\`\`\`

The behavioral tell: send one IOCTL and read the completion. Our victim's
honest handler completes with Status=SUCCESS / Information=4; the
foreigner answers \`0xDEAD0001\`.

## OBJECT_TYPE_INITIALIZER hooks

Object types carry optional procedure pointers consulted on access:
\`OpenProcedure\` (filter opens), \`ParseProcedure\` (redirect lookups),
\`CloseProcedure\`/\`DeleteProcedure\` (life-cycle taps). Hooking
\`Process.OpenProcedure\` means every \`ObOpen\` in the system asks your
code first — below any ACL check, below PPL. Baseline is usually NULL,
which makes both the edit and the repair trivially visible.

## Who catches this in the real world

- **PatchGuard: silent.** These tables are not protected state.
- **EDR kernel sensors**: baseline every table at load ("attest"), then
  periodically re-diff. Any wired slot pointing outside its owner's image
  range — or any initializer procedure that grew a pointer where NULL was
  recorded — is convicted. This lab builds exactly that sensor.
- **Minifilter altitude order**: filter managers notice strangers in their
  stacks.
- **HVCI/VBS: irrelevant here** — no code page or CR/MSR state changes.
`;
