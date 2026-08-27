/** Lesson body: m26.l3 — ETW defense: attestation & gap alarms (markdown). */
export default `## Defending telemetry on both sides of the boundary

Two surfaces took damage in this module; each gets its own sensor design.

## User-mode: trust nothing you didn't map

The wrapper patch survived because the process trusts ntdll's bytes.
Defenders stop doing that:

1. **Clean remap**: load a second copy of ntdll from disk, diff the
   \`.text\` of interesting exports against the live one, repair or alert
   on drift (this is \`hookscan\` with an authoritative baseline).
2. **Direct syscalls**: sensitive callers build the syscall number and
   issue \`syscall\` themselves — no wrapper bytes to patch. Your anticheat
   gauntlet (m17) met the userland version of this arms race.
3. **Heartbeat accounting**: count emissions vs deliveries; a growing
   suppressed counter IS the detection (\`!etwtrace\` totals line).

## Kernel-mode: attest what PG ignores

KF-Sentinel v7 applies the m24 pattern to telemetry state:

1. **Baseline at boot**: record every logger context's EnableFlags.
2. **Periodic re-diff**: any drift — especially zero — is a conviction;
   the sensor re-asserts the baseline value rather than repairing once.
3. **Behavioral cross-check**: pump known events through the gate and
   compare delivered vs emitted (\`!etwpump\`). Bytes can lie less when
   events must flow.

\`\`\`
SENTINEL-V7: attesting logger CKCL @ fffff8055a740000
SENTINEL-V7: EnableFlags DRIFT 0x000000ff -> 0x00000000 (BLINDED)
SENTINEL-V7: secret=kf-sentinel-v7-ok
\`\`\`

## Who catches this in the real world

- **EDR kernel agents** do exactly this poll-and-assert loop on their own
  sessions; tampering attempts become high-signal detections because the
  only writers are the agent and you.
- **PatchGuard: still silent** — the structural blind spot this module
  exists to teach.
`;
