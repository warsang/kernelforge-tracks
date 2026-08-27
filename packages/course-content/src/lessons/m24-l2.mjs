/** Lesson body: m24.l2 — dispatch-layer hooks: defense theory (markdown). */
export default `## Attestation: baseline at load, convict on drift

You cannot stop a ring-0 peer from writing a qword. You CAN make the
write worthless by noticing it — the same way m3's prologue attestation
worked, pointed at tables instead of code bytes:

1. **Baseline at load.** After a driver's DriverEntry finishes its
   legitimate wiring, snapshot all 28 MajorFunction slots (and every
   object type's initializer). Legitimate rewrites happen once, early.
2. **Re-diff periodically** (or on demand). Two convictions matter:
   - **containment**: a wired slot whose handler is not inside
     \`[DriverStart, DriverStart+DriverSize)\` of its own driver and not
     the \`IopInvalidDeviceRequest\` default is FOREIGN — resolve which
     loaded module owns it for attribution.
   - **baseline drift**: any slot/procedure that differs from its
     load-time value. Containment catches strangers; drift catches
     everything else (including in-image rewires).
3. **Behavioral cross-check.** Send one IOCTL through the live slot and
   compare the completion against the honest contract
   (Status/Information). Bytes lie less when behavior must match.

## The lab's sensor

KF-Sentinel v5 walks both surfaces from inside your own compiled driver:

\`\`\`
SENTINEL-V5: attesting DRIVER_OBJECT kfser @ fffff8055a710000
SENTINEL-V5: FOREIGN DISPATCH IRP_MJ_DEVICE_CONTROL -> fffff8055a720800
SENTINEL-V5: Process.OpenProcedure HOOKED -> fffff8055a720900
SENTINEL-V5: 2 dispatch-layer conviction(s)
SENTINEL-V5: secret=kf-sentinel-v5-ok
\`\`\`

Real products do this from their own kernel driver plus user-mode
service, and they attribute before alerting — "points into
kfsnoop.sys" is actionable, "points somewhere weird" is noise.

## Who catches this in the real world

- **EDR kernel sensors** (CrowdStrike/Falcon-class): MajorFunction +
  callback-array + type-initializer diffing is standard telemetry; the
  foreign-module resolution you just did is exactly their attribution step.
- **PatchGuard: still silent** — that silence is the threat model.
- **Microsoft-defended surfaces**: tampering with object types for
  protected processes (PPL) trips additional defenses — but only because
  someone is watching, not because PG cares.

## Repair discipline

Restore the exact baseline qword with \`eb\` (\`!dispatchscan\` /
\`!objtype\` print copy-pasteable repair lines), then re-prove:
\`!ioctltest\` completes honestly, \`!obopen\` grants again, both scans
read clean.
`;
