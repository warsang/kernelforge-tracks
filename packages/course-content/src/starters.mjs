/**
 * Compiler-lab starter sources. Single home so fixtures for tests are built
 * from the EXACT text students see (see scripts notes in docs/plan.md).
 *
 * Guest-visible constants are deterministic per world and documented in the
 * lesson bodies: build-table offsets (22H2), modeled-list heads, thunk VAs.
 */

export const SENTINEL_V1_STARTER = `// KF-Sentinel v1 - process & module integrity sensor (m1.l4)
//
// Your EDR's first two sensors:
//   1. LIST-vs-CARVE cross-check: walk ActiveProcessLinks, then carve the
//      EPROCESS pool window for image-name signatures. Anything carved but
//      not linked = DKOM-hidden process.
//   2. Unbacked-executable detection: telemetry flagged a pool page full of
//      function prologues; classify it against the loaded-module list.
//
// Deterministic anchors for this world (a real sensor resolves these from
// PDB-backed build tables at runtime):
#include <ntddk.h>

#define OFF_UNIQUE_PROCESS_ID   0x440
#define OFF_ACTIVE_PROC_LINKS   0x448
#define OFF_IMAGE_FILE_NAME     0x5a8
#define PROC_LIST_HEAD          0xffffb80000000000ULL
#define CARVE_BASE              0xffffb80000001000ULL
#define CARVE_LEN               0x8000ULL
#define LDR_HEAD                0x4ff00000ULL     // modeled PsLoadedModuleList
#define PROBE_VA                0xfffff90000020000ULL

static ULONG SentinelListCount(void)
{
    PLIST_ENTRY head = (PLIST_ENTRY)PROC_LIST_HEAD;
    PLIST_ENTRY cur  = head->Flink;
    ULONG n = 0;
    while (cur != head && n < 512) { n++; cur = cur->Flink; }
    return n;
}

static BOOLEAN CarveFindVictim(const CHAR *needle, ULONG len,
                               ULONG64 *pidOut, ULONG64 *vaOut)
{
    // names land at 8-byte alignment inside _EPROCESS (stride 0xA40), so
    // an 8-byte sweep keeps the scan exact without missing candidates
    for (ULONG64 va = CARVE_BASE; va + len < CARVE_BASE + CARVE_LEN; va += 8) {
        PUCHAR p = (PUCHAR)va;
        ULONG i = 0;
        while (i < len && p[i] == (UCHAR)needle[i]) i++;
        if (i == len) {
            ULONG64 eproc = va - OFF_IMAGE_FILE_NAME;
            *pidOut = *(ULONG64 *)(eproc + OFF_UNIQUE_PROCESS_ID);
            *vaOut  = va;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN ProbeCoveredByModule(ULONG64 va)
{
    PLIST_ENTRY head = (PLIST_ENTRY)LDR_HEAD;
    PLIST_ENTRY cur  = head->Flink;
    ULONG n = 0;
    while (cur != head && n < 128) {
        ULONG64 entry = (ULONG64)cur;
        ULONG64 dllBase = *(ULONG64 *)(entry + 0x30);
        ULONG64 size    = *(ULONG64 *)(entry + 0x40);
        if (dllBase != 0 && va >= dllBase && va < dllBase + size) return TRUE;
        cur = cur->Flink;
        n++;
    }
    return FALSE;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    // --- sensor 1: list vs carve -----------------------------------------
    ULONG linked = SentinelListCount();
    DbgPrint("SENTINEL-V1: process list walk -> %u linked entries\\n", linked);

    ULONG64 pid = 0, hitVa = 0;
    if (CarveFindVictim("kftarget", 8, &pid, &hitVa)) {
        DbgPrint("SENTINEL-V1: carve hit 'kftarget.exe' pid=%u @ %p\\n",
                 (unsigned long long)pid, (PVOID)hitVa);
        DbgPrint("SENTINEL-V1: signature present but NOT on the list "
                 "-> DKOM DETECTED\\n");
    } else {
        DbgPrint("SENTINEL-V1: no hidden-process signatures found\\n");
    }

    // --- sensor 2: unbacked executable page -------------------------------
    if (!ProbeCoveredByModule(PROBE_VA)) {
        DbgPrint("SENTINEL-V1: probe page %p holds executable code but is "
                 "covered by NO loaded module -> UNBACKED EXEC DETECTED\\n",
                 (PVOID)PROBE_VA);
    } else {
        DbgPrint("SENTINEL-V1: probe page belongs to a listed module - clean\\n");
    }

    DbgPrint("SENTINEL-V1: sweep complete secret=kf-sentinel-v1-ok\\n");
    return STATUS_SUCCESS;
}
`;

export const SENTINEL_V2_STARTER = `// KF-Sentinel v2 - IRQL watchdog & DPC starvation sensor (m2.l2)
//
// Module 2's rogue driver pinned the processor above DISPATCH_LEVEL so its
// victim stays frozen and queued DPCs never run. Code executing above
// DISPATCH is invisible to many instrumentation callbacks, so the watchdog
// runs where the misbehavior happens: it SAMPLES the IRQL from inside a
// driver and forces the ladder back down.
//
// Real deployments sample from a timer DPC or a periodic work item and
// raise a telemetry event instead of touching the IRQL directly - here you
// get to see both halves of the dance.

#include <ntddk.h>

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KIRQL sampled = KeGetCurrentIrql();
    DbgPrint("SENTINEL-WATCHDOG: sampled IRQL = %u\\n", (int)sampled);

    if (sampled > DISPATCH_LEVEL) {
        DbgPrint("SENTINEL-WATCHDOG: CPU pinned above DISPATCH - threads and "
                 "queued DPCs are starving\\n");
        KeLowerIrql(DISPATCH_LEVEL);
        DbgPrint("SENTINEL-WATCHDOG: ladder restored to %u; stranded DPCs can "
                 "run again (drain with !dpcdrain)\\n", (int)KeGetCurrentIrql());
        DbgPrint("SENTINEL-WATCHDOG: secret=kf-watchdog-ok\\n");
    } else {
        DbgPrint("SENTINEL-WATCHDOG: IRQL within operating range - nothing to do\\n");
    }
    return STATUS_SUCCESS;
}
`;

export const SENTINEL_V3_STARTER = `// KF-Sentinel v3 - prologue attestation engine (m3.l2)
//
// The classic EDR/anticheat control-flow sensor: hash or compare the first
// bytes of every critical kernel export against a known-good baseline taken
// from a clean boot. A single relocated byte is noise; an E9 in position
// zero is an inline detour.
//
// In this world the known-good baseline is trivial (the model materializes
// each export as F4 = HALT marker), but the SHA-256 table you would ship in
// production plays exactly the same role. The import resolves to the
// export's real address inside your kernel - that is all the sensor needs.

#include <ntddk.h>

// known-good baseline (production: sha256 of N prologue bytes per export)
#define BASELINE_FIRST_BYTE 0xF4

static NTSTATUS AttestExport(const char *name, PVOID fn)
{
    PUCHAR prologue = (PUCHAR)fn;
    UCHAR live = prologue[0];
    if (live != BASELINE_FIRST_BYTE) {
        DbgPrint("SENTINEL-ATTEST: %s @ %p FIRST BYTE %02x != baseline %02x "
                 "-> INLINE HOOK DETECTED\\n", name, fn, (int)live,
                 (int)BASELINE_FIRST_BYTE);
        return STATUS_INVALID_IMAGE_HASH;
    }
    DbgPrint("SENTINEL-ATTEST: %s @ %p prologue matches baseline\\n", name, fn);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS worst = STATUS_SUCCESS;

    worst |= AttestExport("PsLookupProcessByProcessId",
                          (PVOID)PsLookupProcessByProcessId);
    worst |= AttestExport("DbgPrint", (PVOID)DbgPrint);

    if (worst != STATUS_SUCCESS) {
        DbgPrint("SENTINEL-ATTEST: control-flow integrity COMPROMISED "
                 "secret=kf-attest-ok\\n");
    }
    return worst;
}
`;

export const SENTINEL_V4_STARTER = `// KF-Sentinel v4 - pool integrity monitor (m4.l2)
//
// Driver Verifier's special pool puts guards around allocations; production
// AC/EDRs go further and sweep guard pages periodically so corruption is
// caught BEFORE the distant bugcheck. Here you sweep the trailing A5 guards
// of three tracked 'KfPb' blocks yourself - the same bytes !poolverify
// audits from the debugger, now enforced by your own driver.
//
// Block layout (deterministic in this world):
//   user VA = POOL_BASE + n * 0x200, size = 0x80, guard @ user_va + size.

#include <ntddk.h>

#define POOL_BASE   0xfffff90000001000ULL
#define STRIDE      0x200
#define BLOCK_SIZE  0x80
#define GUARD_LEN   16
#define GUARD_BYTE  0xA5
#define BLOCKS      3

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    ULONG corrupted = 0;
    for (ULONG n = 0; n < BLOCKS; n++) {
        ULONG64 userVa = POOL_BASE + (ULONG64)n * STRIDE;
        PUCHAR guard = (PUCHAR)(userVa + BLOCK_SIZE);
        ULONG bad = GUARD_LEN;
        for (ULONG i = 0; i < GUARD_LEN; i++) {
            if (guard[i] != GUARD_BYTE) { bad = i; break; }
        }
        if (bad != GUARD_LEN) {
            corrupted++;
            DbgPrint("SENTINEL-POOLMON: block %u @ %p guard[%u]=%02x "
                     "CORRUPTED\\n", n, (PVOID)userVa, bad, (int)guard[bad]);
        } else {
            DbgPrint("SENTINEL-POOLMON: block %u @ %p guard intact\\n",
                     n, (PVOID)userVa);
        }
    }

    if (corrupted) {
        DbgPrint("SENTINEL-POOLMON: %u of %d allocations violated - overflow "
                 "in progress somewhere upstream secret=kf-poolmon-ok\\n",
                 corrupted, BLOCKS);
    } else {
        DbgPrint("SENTINEL-POOLMON: pool clean\\n");
    }
    return corrupted ? STATUS_INVALID_BUFFER_SIZE : STATUS_SUCCESS;
}
`;
