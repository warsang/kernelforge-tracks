/*
 * wdm.h — kernel-mode primitives (teaching subset of the real WDK wdm.h).
 * Covers what ntsim's API layer implements: pool, IRQL, DPC, spinlocks,
 * process/thread ops, and the DbgPrint family.
 */
#pragma once

#include <ntdef.h>
#include <ntstatus.h>

/* --- driver object / dispatch --------------------------------------------- */

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_SHUTDOWN                 0x10

#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

#define FILE_READ_DATA                  0x0001
#define FILE_WRITE_DATA                 0x0002
#define FILE_ANY_ACCESS                 0

#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

typedef struct _DRIVER_OBJECT {
    short Type;
    short Size;
    void *DeviceObject;
    unsigned long Flags;
    void *DriverStart;
    unsigned long DriverSize;
    void *DriverSection;
    void *DriverExtension;
    UNICODE_STRING DriverName;
    void *HardwareDatabase;
    void *FastIoDispatch;
    void *DriverInit;
    void *DriverStartIo;
    void (*DriverUnload)(struct _DRIVER_OBJECT *);
    long MajorFunction[28];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef struct _DEVICE_OBJECT {
    short Type;
    short Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT *DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    void *DeviceExtension;
    unsigned long Flags;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _IRP {
    long something; /* teaching stub: labs use ntsim IOCTL hooks directly */
} IRP, *PIRP;

typedef NTSTATUS (*PDRIVER_INITIALIZE)(PDRIVER_OBJECT, PUNICODE_STRING);

/* --- pool ------------------------------------------------------------------ */

typedef enum _POOL_TYPE {
    NonPagedPool = 0,
    NonPagedPoolExecute = 0,
    PagedPool = 1,
    NonPagedPoolMustSucceed = 2,
    DontUseThisType = 3,
    NonPagedPoolCacheAligned = 4,
    PagedPoolCacheAligned = 5,
    NonPagedPoolCacheAlignedMustS = 6,
    MaxPoolType = 7,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = 516,
} POOL_TYPE;

#define POOL_TAGGING 1

/* Prototypes implemented by ntsim's winapi layer (hooked thunks). */
void *ExAllocatePoolWithTag(POOL_TYPE PoolType, unsigned long long NumberOfBytes, ULONG Tag);
void *ExAllocatePool(POOL_TYPE PoolType, unsigned long long NumberOfBytes);
void ExFreePoolWithTag(void *P, ULONG Tag);
void ExFreePool(void *P);

/* --- IRQL ------------------------------------------------------------------ */

enum {
  PASSIVE_LEVEL = 0,
  APC_LEVEL = 1,
  DISPATCH_LEVEL = 2,
  CMCI_LEVEL = 5,
  CLOCK_LEVEL = 13,
  IPI_LEVEL = 14,
  POWER_LEVEL = 15,
  HIGH_LEVEL = 15,
};

typedef unsigned char KIRQL, *PKIRQL;

KIRQL KeGetCurrentIrql(void);
VOID KeRaiseIrql(KIRQL NewIrql, PKIRQL OldIrql);
KIRQL KeRaiseIrqlToDpcLevel(void);
VOID KeLowerIrql(KIRQL NewIrql);

/* --- spinlocks -------------------------------------------------------------- */

typedef unsigned long long KSPIN_LOCK, *PKSPIN_LOCK;
typedef KSPIN_LOCK KGUARDED_MUTEX;

VOID KeInitializeSpinLock(PKSPIN_LOCK SpinLock);
KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock);
VOID KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql);

/* --- DPC / timer ------------------------------------------------------------ */

typedef VOID (*PKDEFERRED_ROUTINE)(
    void *Dpc, void *DeferredContext, void *SystemArgument1, void *SystemArgument2);

typedef struct _KDPC {
    SHORT Type;
    UCHAR Number;
    UCHAR Importance;
    struct _KDPC *DpcListEntry;
    PKDEFERRED_ROUTINE DeferredRoutine;
    void *DeferredContext;
    void *SystemArgument1;
    void *SystemArgument2;
    void *DpcData;
} KDPC, *PKDPC;

typedef struct _KTIMER {
    LIST_ENTRY Header;
    ULONGLONG DueTime;
    LIST_ENTRY TimerListEntry;
    void *Dpc;
    ULONG Period;
} KTIMER, *PKTIMER;

VOID KeInitializeDpc(PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, void *DeferredContext);
BOOLEAN KeInsertQueueDpc(PKDPC Dpc, void *SA1, void *SA2);
BOOLEAN KeRemoveQueueDpc(PKDPC Dpc);
VOID KeInitializeTimer(PKTIMER Timer);
BOOLEAN KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc);
BOOLEAN KeCancelTimer(PKTIMER Timer);

/* --- processes / threads ----------------------------------------------------- */

typedef struct _PEPROCESS *PEPROCESS;   /* opaque: layout comes from Vergilius tables */
typedef struct _PETHREAD  *PETHREAD;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LONG KPRIORITY;

/* KAPC_STATE (teaching subset): mirrors the real layout's Process field;
 * ntsim saves/restores Process (+0x10) and ApcStateIndex (+0x18) only */
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];     /* reserved — not modeled */
    struct _PEPROCESS *Process;    /* saved ApcState.Process @ +0x10 */
    unsigned char ApcStateIndex;   /* saved ApcStateIndex   @ +0x18 */
} KAPC_STATE, *PKAPC_STATE;

VOID KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);
VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

HANDLE PsGetCurrentProcessId(void);
HANDLE PsGetCurrentThreadId(void);
PEPROCESS PsGetCurrentProcess(void);
PETHREAD PsGetCurrentThread(void);
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread);
VOID ObDereferenceObject(void *Object);
LONG PsSetCreateProcessNotifyRoutineRoutine_placeholder; /* removed below */

/* --- misc kernel services students reach for --------------------------------- */

unsigned long long DbgPrint(const char *Format, ...);
VOID DbgBreakPoint(void);
void KeStallProcessor(unsigned long long MicroSeconds); /* ntsim: busy-wait */
LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER *Frequency);

/* --- object manager surface (used by AC labs) --------------------------------- */

#define OB_OPERATION_HANDLE_CREATE      0x0001
#define OB_OPERATION_HANDLE_DUPLICATE   0x0002

typedef struct _OB_PRE_OPERATION_INFORMATION {
    unsigned short Operation;
    unsigned int ObjectTypeIndex;
    void *Object;
} OB_PRE_OPERATION_INFORMATION;
