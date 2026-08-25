/** Lesson body: m4.l2 — KF-Sentinel v4: pool integrity monitor (defense, markdown). */

export default `## Guards, but enforced by you

Module 4's attack lab used the debugger as the integrity monitor: \`!poolfind\`
read guard bytes, \`eb\` repaired them, \`!poolverify\` swept. Your v4 sensor
does all of that from a driver — no debugger attached, which is how it must
work on a player's machine at 3 AM.

## The monitor loop

Production pool monitors run periodically (work item or timer DPC) and do:

1. **Sweep guards** — every tracked allocation's trailing pattern must read
   back exactly. Your starter sweeps three 'KfPb' blocks with baked
   addresses; production tracks every allocation it owns via
   \`ExAllocatePoolWithTag\` wrappers that record {va, size, tag, guard}.
2. **Attribute** — tag + address identify the owning driver. Corruption
   next to your block usually means *someone else* overflowed; the report
   includes both sides of the fence.
3. **Quarantine** — flip the region non-executable, copy bytes aside for
   forensics, and fail closed if control flow could reach the smashed area.
   Driver Verifier's special pool is the OS-level version: each allocation
   gets its own pages plus guard PAGEs that fault on first touch.

\`\`\`c
PUCHAR guard = (PUCHAR)(userVa + blockSize);
for (i = 0; i < GUARD_LEN && guard[i] == 0xA5; i++) {}
if (i != GUARD_LEN) { /* telemetry: overflow @ userVa, first bad byte i */ }
\`\`\`

## Reading corruption like an investigator

| observation | inference |
|---|---|
| guard[0] smashed only | linear overflow just past end |
| deep-guard damage | wild pointer / UAF write |
| header magic gone | underflow or free-list attack |
| intact today, smashed tomorrow | slow drip — timer-based exploit |

## Custom debugger extensions used

- \`!poolfind <tag>\` — **lab extension**: lists tagged allocations + guard
  health. Driver-equivalent: keep your own allocation registry (the wrapper
  above) and read guard bytes per entry — precisely the v4 sweep.
- \`!poolverify\` — **lab extension**: full sweep + repair hints. The
  in-driver version differs in one way that matters: it can *act*
  (quarantine, kill process, bugcheck on policy) where the debugger only
  reports.

## Defensive framing — the escalation ladder

- **Special pool** (Driver Verifier): per-allocation pages + guard pages;
  any touch out of bounds faults immediately instead of corrupting silently.
- **Pool-tag quotas**: caps per tag so one leaky/corrupting driver cannot
  exhaust the pool; \`!poolfind\`-style attribution feeds enforcement.
- **kCFG**: even when corruption succeeds, function-pointer targets inside
  smashed pools fail control-flow validation.
- **Hardware memory tagging (ARM MTE-class)**: every allocation gets a tag;
  mismatched accesses fault in hardware — guards become free and instant.
- Your sensor closes the loop this course promised: module 1 taught DKOM,
  manual mapping, hooks and overflow as attacks; Sentinel v1–v4 detect all
  four from ring 0. Later modules escalate to userland and hypervisor games
  precisely because kernel defenses like yours work.

Compile the starter against the pool-corrupt world and confirm your monitor
convicts the same block you once repaired by hand.
`;
