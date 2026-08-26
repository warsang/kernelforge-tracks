# Kernel API coverage — ntsim vs Speakeasy / KDemu / Qiling

Status after `feat/kernel-api-layer`. Sources consulted:
- Speakeasy: github.com/mandiant/speakeasy (winenv/api/kernelmode/ntoskrnl.py; IAT-sentinel dispatch)
- KDemu: github.com/ShallowFeather/KDemu (real-dump memory + DbgEng-backed APIs, LIEF PE loading)
- Qiling: qilingframework/qiling wiki "Windows Emulation" (PE loader, virtual registry, rootfs DLLs)

## What each project models

| Capability | Speakeasy | KDemu | Qiling | ntsim (now) |
|---|---|---|---|---|
| CPU engine | Unicorn | Unicorn (+ native fallbacks) | Unicorn | JsInterpreter **or** Unicorn wasm |
| Source of kernel memory | modeled | **real dump** | modeled/rootfs | modeled **or real dump fixture** |
| Driver PE load (.sys) + imports | ✔ | ✔ (LIEF, overwrites dump images) | ✔ | partial (`pe.mjs` baseline; manual-map lab teaches it) |
| ntoskrnl export emulation breadth | hundreds via @apihook | whatever DbgEng answers | large win32 set; kernel subset | **~60 core routines** (this change), fail-visible unknowns |
| `MmGetSystemRoutineAddress` resolution | ✔ | ✔ | n/a (user-mode focus for API hooks) | ✔ resolves registered thunks |
| Pool allocator | ✔ w/ tagging | real pool from dump | ✔ | ✔ tagged bump allocator |
| LIST_ENTRY family | ✔ | ✔ (native memory) | user-mode only | ✔ real memory ops (differentially tested) |
| Interlocked RMW | ✔ | native | ✔ | ✔ on guest memory |
| Registry | modeled hive | real registry via dump host | **in-memory virtual registry** (pre-seedable) | ✔ pre-seedable Map-backed hive (`ZwOpenKey/QueryValueKey`) |
| Version reporting (RtlGetVersion/PsGetVersion) | ✔ spoofable | real | spoofable per-profile | ✔ 10.0.19045 fixed this build |
| Process/thread context (EPROCESS/ETHREAD/KPCR) | structs modeled | **real dump** | user-mode PEB/TEB | **real dump** (KDemu snapshot): EPROCESS ring, KPCR→PRCB→CurrentThread at true VAs |
| Notify routines registration | ✔ records callbacks | n/a | n/a | ✔ recorded (invocation pending) |
| DPC/timer queueing | ✔ retire + execute (`!dpcdrain`, `!dpcpump`, KTIMER model) | native | n/a | queued model with drain-time routine re-read, periodic timers, per-core directed delivery |
| CR0 / control registers | modeled (KfReadCr0/KfWriteCr0 thunks; WP history) | native MOV CRx | n/a | thunk-shimmed intrinsics; HVCI gate raises 0x109 on WP clears |
| Bugcheck semantics | report | real bugcheck data | n/a | ✔ KeBugCheckEx halts vCPU + records params |
| Unknown-API behavior | logs & continues | answered by DbgEng | returns failure | logs + STATUS_NOT_IMPLEMENTED (**visible**) |
| Determinism/replay | seeded RNG | dump-frozen | depends on rootfs | byte-stable (JsInterpreter) + differential suite |

## Our implemented exports (packages/ntsim/src/winapi.mjs)

Memory: ExAllocatePool{,WithTag,2}, ExFreePool{,WithTag}, RtlCopyMemory/
RtlCopyBytes/memcpy/memmove/RtlMoveMemory, RtlFillMemory/memset,
RtlZeroMemory, RtlCompareMemory
Strings: RtlInitUnicodeString, RtlInitAnsiString, strlen, wcslen, strcmp,
RtlEqualUnicodeString, RtlAnsiStringToUnicodeString, RtlUnicodeToUTF8
Lists: InitializeListHead, IsListEmpty, InsertHeadList, InsertTailList,
RemoveHeadList, RemoveEntryList
Interlocked: Increment, Decrement, Exchange, ExchangeAdd, CompareExchange
Process/thread: PsGetCurrentProcessId/Process/Thread, IoGetCurrentProcess,
PsGetProcessId, PsLookupProcessByProcessId
Version: RtlGetVersion, PsGetVersion (10.0.19045)
Sync/time: KeInitializeSpinLock, Acquire/ReleaseSpinLock, KfRaiseIrql,
KeRaiseIrql/LowerIrql, KeRaiseIrqlToDpcLevel, KeInitializeDpc,
KeInsertQueueDpc, KeSetTargetProcessorDpc (directed), KfReleaseDirectedDpcs,
KeQueryPerCpuIrql/KeQueryDpcQueueDepth (lab extensions), KfReadCr0/KfWriteCr0/
KfCli/KfSti (intrinsic shims), KeInitializeTimer, KeSetTimer/KeSetTimerEx/
CancelTimer, KeQueryTickCount/SystemTime, KeStallExecutionProcessor,
KeDelayExecutionThread, KeWaitForSingleObject, KeBugCheckEx
Objects: Ob(De)ReferenceObject, Obf(De)ReferenceObject
Registry: ZwOpenKey, ZwClose, ZwQueryValueKey, ZwQueryKey (+registrySeed helper)
I/O stubs: IoAllocateIrp/IoFreeIrp/IoCompleteRequest/IofCallDriver,
IoCreateDevice/IoDeleteDevice
Resolution: MmGetSystemRoutineAddress
Pre-existing: DbgPrint, KeGetCurrentIrql

## Deliberate gaps (roadmap)

1. ~~Deferred procedure *invocation*~~ — done: `drainDpcs` (retire-only),
   `retireQueuedDpcs`/`advanceTicks` execute routines through the CPU, and
   `!dpcpump [n]` advances the lab clock.
2. IRP completion propagation into driver-supplied completion routines.
3. Object manager with typed handles (ObCreateObjectType-style).
4. Token theft/privilege checks for token-swap labs.
5. Full PE import resolution inside the loader (manual-map lab teaches the concept first).
