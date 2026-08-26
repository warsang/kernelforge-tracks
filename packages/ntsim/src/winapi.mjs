/**
 * winapi.mjs — native ntoskrnl export emulation layer for NtKernel.
 *
 * Design mirrors the philosophy of Speakeasy/Qiling: intercept common kernel
 * exports and model them over the emulated address space instead of executing
 * real code. Everything operates through the kernel's SparseMemory so both
 * CPU backends observe identical effects (differential-tested).
 *
 * Coverage policy:
 *  - Implemented routines behave faithfully enough for typical driver flows.
 *  - Unknown exports resolve to a logged "unimplemented" thunk returning
 *    STATUS_NOT_IMPLEMENTED (0xC0000001) — failures are visible, never silent.
 */

import { M64 } from "./cpu.mjs";
import { installWinApiExt } from "./winapi-ext.mjs";

const STATUS_SUCCESS = 0x00000000n;
const STATUS_NOT_IMPLEMENTED = 0xc0000001n;
const STATUS_INVALID_PARAMETER = 0xc000000dn;
const STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034n;

function ptrSizeMask(v) {
  return BigInt.asUintN(64, BigInt(v));
}

/** UNICODE_STRING reader/writer helpers over memory. */
function usRead(mem, va) {
  const length = mem.u16(va);
  const buffer = mem.u64(va + 8n);
  const str = length ? mem.readUtf16(buffer, Math.min(length / 2, 1024)) : "";
  return { length, capacity: mem.u16(va + 2n), buffer, str };
}

export function installWinApi(kernel) {
  const mem = kernel.mem;
  const t = kernel.tables;

  // ------------------------------------------------------------- state
  kernel.registry = new Map(); // path -> Map(valueName -> {type,data})
  kernel.notifyRoutines = { process: [], thread: [], image: [] };
  kernel.tickCount = 0x100000n;
  kernel.systemTime = 0x01d9000000000000n; // FILETIME-ish constant
  kernel.unsupportedExports = [];
  kernel.bugcheck = null;
  kernel.handles = new Map();
  let nextHandle = 4n;

  const regHandle = (key) => {
    const h = nextHandle++;
    kernel.handles.set(h, key);
    return h;
  };

  // ---------------------------------------------------------- utilities
  const impls = {};
  const k = {
    define(name, fn) {
      impls[name] = fn;
      kernel.defineApi(name, function (...args) {
        try {
          return fn.apply(null, args);
        } catch (e) {
          kernel.dbgLog.push(`[winapi] ${name} threw: ${e.message}`);
          return STATUS_NOT_IMPLEMENTED;
        }
      });
    },
    _impl(name) {
      return (...args) => impls[name](...args);
    },
    alloc: (size) => kernel.allocPool(Number(size), "winapi"),
    usRead: (va) => usRead(mem, va),
    usWrite(usVa, str, bufVa) {
      const bytes = str.length * 2;
      mem.w16(usVa, bytes);
      mem.w16(usVa + 2n, bytes + 2);
      mem.w64(usVa + 8n, bufVa);
      mem.writeUtf16(bufVa, str, 512);
    },
  };

  // ------------------------------------------------------- memory & pool

  const poolTagStr = (tag) => String.fromCharCode(
    Number(tag & 0xffn), Number((tag >> 8n) & 0xffn),
    Number((tag >> 16n) & 0xffn), Number((tag >> 24n) & 0xffn));

  k.define("ExAllocatePool", (poolType, size) => k.alloc(size));
  k.define("ExAllocatePoolWithTag", (poolType, size, tag) => {
    // PagedPool (type 1) above APC_LEVEL would bugcheck a real machine.
    if ((Number(poolType) & 1) === 1 && kernel.currentIrql > 1) {
      kernel.dbgLog.push(
        `[pool] ExAllocatePoolWithTag(PagedPool) at IRQL ${kernel.currentIrql} ` +
        `> APC_LEVEL — real Windows bugchecks here (returning NULL)`);
      return 0n;
    }
    return kernel.allocPool(Number(size), tag ? poolTagStr(tag) : "ntsm");
  });
  k.define("ExAllocatePool2", (flags, size, tag) => (size > 0x7fffffffn ? 0n : k.alloc(size)));
  k.define("ExFreePool", () => undefined);
  k.define("ExFreePoolWithTag", (addr, tag) => kernel.freePool(addr));

  k.define("RtlCopyMemory", (dst, src, len) => {
    mem.write(dst, mem.read(src, Number(len)));
    return dst;
  });
  k.define("RtlCopyBytes", (...a) => impls.RtlCopyMemory(...a));
  k.define("memcpy", (...a) => impls.RtlCopyMemory(...a));
  k.define("memmove", (...a) => impls.RtlCopyMemory(...a));
  k.define("RtlMoveMemory", (...a) => impls.RtlCopyMemory(...a)("RtlCopyMemory"));
  k.define("RtlFillMemory", (dst, len, val) => {
    mem.write(dst, new Uint8Array(Number(len)).fill(Number(val) & 0xff));
    return dst;
  });
  k.define("memset", (dst, val, len) => {
    mem.write(dst, new Uint8Array(Number(len)).fill(Number(val) & 0xff));
    return dst;
  });
  k.define("RtlZeroMemory", (dst, len) => {
    mem.write(dst, new Uint8Array(Number(len)));
    return dst;
  });
  k.define("RtlCompareMemory", (a, b, len) => {
    const xa = mem.read(a, Number(len));
    const xb = mem.read(b, Number(len));
    let n = 0n;
    for (let i = 0; i < xa.length && xa[i] === xb[i]; i++) n++;
    return n;
  });

  // ------------------------------------------------------------ strings

  k.define("RtlInitUnicodeString", (usVa, strVa) => {
    if (!strVa) { mem.w16(usVa, 0); mem.w16(usVa + 2n, 0); mem.w64(usVa + 8n, 0n); return usVa; }
    const chars = [];
    for (let i = 0; i < 1024; i++) {
      const c = mem.u16(strVa + BigInt(i * 2));
      if (!c) break;
      chars.push(c);
    }
    const bytes = chars.length * 2;
    mem.w16(usVa, bytes);
    mem.w16(usVa + 2n, bytes + 2);
    mem.w64(usVa + 8n, strVa);
    return usVa;
  });
  k.define("RtlInitAnsiString", (asVa, strVa) => {
    if (!strVa) { mem.w16(asVa, 0); mem.w16(asVa + 2n, 0); mem.w64(asVa + 8n, 0n); return asVa; }
    let n = 0;
    while (n < 1024 && mem.u8(strVa + BigInt(n))) n++;
    mem.w16(asVa, n);
    mem.w16(asVa + 2n, n + 1);
    mem.w64(asVa + 8n, strVa);
    return asVa;
  });
  k.define("strlen", (va) => {
    let n = 0n;
    while (n < 4096n && mem.u8(va + n)) n++;
    return n;
  });
  k.define("wcslen", (va) => {
    let n = 0n;
    while (n < 2048n && mem.u16(va + n * 2n)) n++;
    return n;
  });
  k.define("strcmp", (a, b) => {
    for (let i = 0; i < 1024; i++) {
      const ca = mem.u8(a + BigInt(i)), cb = mem.u8(b + BigInt(i));
      if (ca !== cb) return BigInt(ca) - BigInt(cb);
      if (!ca) return 0n;
    }
    return 0n;
  });
  k.define("RtlEqualUnicodeString", (aVa, bVa, caseIns) => {
    const a = usRead(mem, aVa).str.toLowerCase();
    const b = usRead(mem, bVa).str.toLowerCase();
    void caseIns;
    return a === b ? 1n : 0n;
  });
  k.define("RtlAnsiStringToUnicodeString", (usDst, asSrc, alloc) => {
    const len = mem.u16(asSrc);
    const buf = mem.u64(asSrc + 8n);
    const str = len ? mem.readAnsi(buf, Math.min(len, 1024)) : "";
    const outBuf = alloc ? k.alloc((str.length + 1) * 2) : buf;
    k.usWrite(usDst, str, outBuf);
    return STATUS_SUCCESS;
  });
  k.define("RtlUnicodeToUTF8", (dst, dstLen, srcUs) => {
    const { str } = usRead(mem, srcUs);
    const bytes = [...new TextEncoder().encode(str)];
    const n = Math.min(bytes.length, Number(dstLen));
    mem.write(dst, Uint8Array.from(bytes.slice(0, n)));
    return BigInt(n);
  });

  // -------------------------------------------------------------- lists

  k.define("InitializeListHead", (head) => {
    mem.w64(head, head);
    mem.w64(head + 8n, head);
    return undefined;
  });
  k.define("IsListEmpty", (head) => (mem.u64(head) === head ? 1n : 0n));
  k.define("InsertHeadList", (head, entry) => {
    const first = mem.u64(head);
    mem.w64(entry, first);
    mem.w64(entry + 8n, head);
    mem.w64(first + 8n, entry);
    mem.w64(head, entry);
    return undefined;
  });
  k.define("InsertTailList", (head, entry) => {
    const last = mem.u64(head + 8n); // head.Blink
    mem.w64(entry, head);            // entry->Flink = Head
    mem.w64(entry + 8n, last);       // entry->Blink = last
    mem.w64(last, entry);            // last->Flink = entry
    mem.w64(head + 8n, entry);       // Head->Blink = entry
    return undefined;
  });
  k.define("RemoveHeadList", (head) => {
    const first = mem.u64(head);
    const next = mem.u64(first);
    mem.w64(head, next);
    mem.w64(next + 8n, head);
    return first;
  });
  k.define("RemoveEntryList", (entry) => {
    const flink = mem.u64(entry);
    const blink = mem.u64(entry + 8n);
    mem.w64(blink, flink);
    mem.w64(flink + 8n, blink);
    return blink === entry ? 1n : 0n;
  });

  // -------------------------------------------------------- interlocked

  const rmw32 = (va, fn) => {
    const cur = mem.u32(va);
    mem.w32(va, fn(cur) >>> 0);
    return cur;
  };
  k.define("InterlockedIncrement", (va) => BigInt(rmw32(va, (c) => c + 1)) + 1n);
  k.define("InterlockedDecrement", (va) => BigInt(rmw32(va, (c) => c - 1)) - 1n);
  k.define("InterlockedExchange", (va, v) => BigInt(rmw32(va, () => Number(v) >>> 0)));
  k.define("InterlockedExchangeAdd", (va, v) => BigInt(rmw32(va, (c) => c + Number(v))));
  k.define("InterlockedCompareExchange", (va, exchange, comparand) =>
    BigInt(rmw32(va, (c) => (c === Number(comparand) ? Number(exchange) : c))));

  // ---------------------------------------------------- process / thread

  const currentEproc = () => {
    const tid = kernel.currentThread;
    if (tid) {
      const cidOff = (() => { try { return t.offsetOf("_ETHREAD", "Cid"); } catch { return null; } })();
      if (cidOff !== null) {
        const pid = mem.u64(tid + cidOff);
        const e = kernel.findEprocessByPid(pid);
        if (e) return e;
      }
    }
    return kernel.findEprocessByPid(4n); // fall back to System
  };
  k.define("PsGetCurrentProcessId", () => {
    const e = currentEproc();
    return e ? mem.u64(e + t.offsetOf("_EPROCESS", "UniqueProcessId")) : 4n;
  });
  k.define("PsGetCurrentProcess", () => currentEproc() ?? 0n);
  k.define("IoGetCurrentProcess", () => currentEproc() ?? 0n);
  k.define("PsGetCurrentThread", () => kernel.currentThread ?? 0n);
  k.define("PsGetProcessId", (eproc) => mem.u64(eproc + t.offsetOf("_EPROCESS", "UniqueProcessId")));
  k.define("PsLookupProcessByProcessId", (pid, out) => {
    const e = kernel.findEprocessByPid(pid);
    if (!e) return 0xc000000bn;
    mem.w64(out, e);
    return STATUS_SUCCESS;
  });

  // ------------------------------------------------------------- version

  const writeVersion = (structVa) => {
    mem.w32(structVa, 0x11c);            // dwOSVersionInfoSize
    mem.w32(structVa + 4n, 10);          // major
    mem.w32(structVa + 8n, 0);           // minor
    mem.w32(structVa + 12n, 19045);      // build (22H2)
    mem.w32(structVa + 16n, 2);          // platform = VER_PLATFORM_WIN32_NT
    return structVa;
  };
  k.define("RtlGetVersion", (info) => writeVersion(info));
  k.define("PsGetVersion", (info, _, __, ___) => {
    if (info) writeVersion(info);
    return 19045n;
  });

  // --------------------------------------------------------- sync / time

  k.define("KeInitializeSpinLock", (sl) => { mem.w32(sl, 0); return undefined; });
  k.define("KeAcquireSpinLock", (sl, oldIrql) => {
    mem.w8(oldIrql, 2); // DISPATCH_LEVEL
    kernel.currentIrql = Math.max(kernel.currentIrql, 2);
    return undefined;
  });
  k.define("KeReleaseSpinLock", (sl, newIrql) => {
    kernel.lowerIrql(Number(newIrql) & 0xff);
    return undefined;
  });
  // KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK) — raises to DISPATCH_LEVEL,
  // returns the PREVIOUS level in rax (no out-param on this variant).
  k.define("KeAcquireSpinLockRaiseToDpc", (sl) => {
    void sl;
    const old = kernel.currentIrql ?? 0;
    kernel.currentIrql = Math.max(old, 2);
    return BigInt(old);
  });
  // KIRQL params are 8-bit: clang targets may write only the low byte of the
  // argument register (stale high bits are legal garbage under the Win x64
  // ABI). Mask via BigInt BEFORE Number() — huge register-sized values lose
  // precision as doubles and the naive &0xff silently yields wrong levels.
  const kirql = (v) => Number(BigInt.asUintN(8, BigInt(v ?? 0)));
  k.define("KfRaiseIrql", (newIrql) => kernel.raiseIrql(kirql(newIrql)));
  k.define("KeRaiseIrql", (newIrql, oldOut) => {
    const old = kernel.raiseIrql(kirql(newIrql));
    mem.w8(oldOut, old);
    return undefined;
  });
  k.define("KeLowerIrql", (newIrql) => {
    kernel.lowerIrql(kirql(newIrql));
    return undefined;
  });
  k.define("KeRaiseIrqlToDpcLevel", () => BigInt(kernel.raiseIrql(2)));
  k.define("KeGetCurrentIrql", () => BigInt(kernel.currentIrql ?? 2));

  // control-register model: KfReadCr0/KfWriteCr0/KfCli/KfSti are the thunk
  // targets behind the __readcr0/__writecr0/_disable/_enable header shims.
  k.define("KfReadCr0", () => kernel.cr0);
  k.define("KfWriteCr0", (value) => { kernel.writeCr0(value); return undefined; });
  k.define("KfCli", () => { kernel.interruptsEnabled = false; return undefined; });
  k.define("KfSti", () => { kernel.interruptsEnabled = true; return undefined; });
  /** lab extension: sample another logical core's IRQL (directed-DPC labs). */
  k.define("KeQueryPerCpuIrql", (num) => BigInt(kernel.cpuIrql(Number(BigInt.asUintN(8, BigInt(num ?? 0n))))));
  k.define("KeInitializeDpc", (dpc, deferred, ctx) => {
    mem.w64(dpc, 0x4b444350n); // 'DPCk' marker
    mem.w64(dpc + 8n, ptrSizeMask(deferred));
    mem.w64(dpc + 16n, ptrSizeMask(ctx));
    return undefined;
  });
  k.define("KeInsertQueueDpc", (dpc, sysArg1, sysArg2) => {
    void sysArg1; void sysArg2;
    // already-queued DPCs are not requeued (returns FALSE in real Windows)
    const va = ptrSizeMask(dpc);
    const target = kernel.dpcTargetCpu.get(va) ?? 0;
    const ok = kernel.queueDpc(
      va,
      mem.u64(dpc + 8n),
      mem.u64(dpc + 16n),
      { targetCpu: target },
    );
    // directed delivery: a DPC targeted at another core raises that core to
    // DISPATCH_LEVEL the moment it arrives (the lab's KiDpcInterrupt analog)
    if (ok && target > 0) {
      kernel.setCpuIrql(target, Math.max(kernel.cpuIrql(target), 2));
      kernel.dbgLog.push(`nt: KiDpcInterrupt: directed DPC 0x${va.toString(16)} raised core ${target} to DISPATCH_LEVEL`);
    }
    return ok ? 1n : 0n;
  });
  k.define("KeRemoveQueueDpc", (dpc) => {
    const va = ptrSizeMask(dpc);
    const idx = kernel.pendingDpcs.findIndex((d) => d.dpcVa === va && !d.drained);
    if (idx < 0) return 0n;
    const d = kernel.pendingDpcs[idx];
    d.drained = true;
    if ((d.targetCpu ?? 0) > 0) kernel.setCpuIrql(d.targetCpu, 0); // unpin core
    return 1n;
  });
  /** lab extension: release every directed (spin) DPC and unpin its core. */
  k.define("KfReleaseDirectedDpcs", () => {
    let released = 0;
    for (const d of kernel.pendingDpcs) {
      if (d.drained || !(d.targetCpu > 0)) continue;
      d.drained = true;
      released++;
      kernel.setCpuIrql(d.targetCpu, 0);
      kernel.dbgLog.push(`nt: directed DPC 0x${d.dpcVa.toString(16)} released core ${d.targetCpu}`);
    }
    return BigInt(released);
  });
  k.define("KeInitializeTimer", () => undefined);
  // DueTime is a LARGE_INTEGER passed by value (8 bytes -> rdx). Negative =
  // relative. Lab simplification: |DueTime| is ticks on kernel.tickCount.
  k.define("KeSetTimer", (timer, dueTime, dpc) => {
    const rel = BigInt.asIntN(64, BigInt.asUintN(64, BigInt(dueTime ?? 0n)));
    const delta = rel < 0n ? -rel : rel;
    const wasPending = kernel.setTimer(
      ptrSizeMask(timer), (kernel.tickCount ?? 0n) + delta, 0, ptrSizeMask(dpc));
    return wasPending ? 1n : 0n;
  });
  k.define("KeSetTimerEx", (timer, dueTime, period, dpc) => {
    const rel = BigInt.asIntN(64, BigInt.asUintN(64, BigInt(dueTime ?? 0n)));
    const delta = rel < 0n ? -rel : rel;
    const wasPending = kernel.setTimer(
      ptrSizeMask(timer), (kernel.tickCount ?? 0n) + delta,
      Number(BigInt.asUintN(32, BigInt(period ?? 0n))), ptrSizeMask(dpc));
    return wasPending ? 1n : 0n;
  });
  k.define("KeCancelTimer", (timer) =>
    kernel.cancelTimer(ptrSizeMask(timer)) ? 1n : 0n);
  k.define("KeQueryTickCount", (countPtr) => {
    kernel.tickCount += 1n;
    mem.w64(countPtr, kernel.tickCount);
    return undefined;
  });
  k.define("KeQuerySystemTime", (timePtr) => {
    kernel.systemTime += 0x989680n; // ~1s steps
    mem.w64(timePtr, kernel.systemTime);
    return undefined;
  });
  k.define("KeStallExecutionProcessor", () => undefined);
  k.define("KeDelayExecutionThread", () => STATUS_SUCCESS);
  k.define("KeWaitForSingleObject", (obj, reason, mode, alertable, timeoutPtr) => {
    void obj; void reason; void mode; void alertable;
    if (timeoutPtr && mem.u64(timeoutPtr) === 0n) return STATUS_SUCCESS;
    return STATUS_SUCCESS; // modeled waits never block
  });
  k.define("KeBugCheckEx", (code, p1, p2, p3, p4) => {
    kernel.bugcheck = { code: ptrSizeMask(code), params: [p1, p2, p3, p4].map(ptrSizeMask) };
    kernel.crash = { code: "0x" + ptrSizeMask(code).toString(16) };
    kernel.cpu.halted = true;
    return undefined;
  });

  // ------------------------------------------------------ notify routines

  const notify = (kind) => (cb, remove) => {
    const arr = kernel.notifyRoutines[kind];
    const idx = arr.indexOf(ptrSizeMask(cb));
    if (remove) { if (idx >= 0) arr.splice(idx, 1); }
    else if (idx < 0) arr.push(ptrSizeMask(cb));
    return STATUS_SUCCESS;
  };
  k.define("PsSetCreateProcessNotifyRoutine", notify("process"));
  k.define("PsSetCreateThreadNotifyRoutine", (cb) => {
    kernel.notifyRoutines.thread.push(ptrSizeMask(cb));
    return STATUS_SUCCESS;
  });
  k.define("PsSetLoadImageNotifyRoutine", (cb) => {
    kernel.notifyRoutines.image.push(ptrSizeMask(cb));
    return STATUS_SUCCESS;
  });
  k.define("PsRemoveCreateThreadNotifyRoutine", (cb) => {
    const arr = kernel.notifyRoutines.thread;
    const idx = arr.indexOf(ptrSizeMask(cb));
    if (idx >= 0) arr.splice(idx, 1);
    return STATUS_SUCCESS;
  });
  k.define("PsRemoveLoadImageNotifyRoutine", (cb) => {
    const arr = kernel.notifyRoutines.image;
    const idx = arr.indexOf(ptrSizeMask(cb));
    if (idx >= 0) arr.splice(idx, 1);
    return STATUS_SUCCESS;
  });

  // ------------------------------------------------------------ objects

  k.define("ObReferenceObject", () => undefined);
  k.define("ObDereferenceObject", () => undefined);
  k.define("ObfReferenceObject", () => undefined);
  k.define("ObfDereferenceObject", () => undefined);

  // -------------------------------------------------- virtual registry

  k.define("ZwOpenKey", (handleOut, access, objAttr) => {
    void access;
    // OBJECT_ATTRIBUTES.ObjectName @ +0x10 -> UNICODE_STRING
    const name = objAttr ? usRead(mem, mem.u64(objAttr + 0x10n)).str : "";
    const norm = "\\" + name.replace(/^\\*/, "");
    for (const key of kernel.registry.keys()) {
      if (key.toLowerCase() === norm.toLowerCase()) {
        mem.w64(handleOut, regHandle(key));
        return STATUS_SUCCESS;
      }
    }
    return STATUS_OBJECT_NAME_NOT_FOUND;
  });
  k.define("ZwClose", (handle) => {
    kernel.handles.delete(ptrSizeMask(handle));
    return STATUS_SUCCESS;
  });
  k.define("ZwQueryValueKey", (handle, valueNameVa, keyType, infoBuf, infoLen, resultLenOut) => {
    void keyType; void infoLen;
    const key = kernel.handles.get(ptrSizeMask(handle));
    if (!key) return STATUS_INVALID_PARAMETER;
    const vn = usRead(mem, valueNameVa).str;
    const entry = kernel.registry.get(key)?.get(vn);
    if (!entry) return STATUS_OBJECT_NAME_NOT_FOUND;
    // KEY_VALUE_PARTIAL_INFORMATION: Type u32, DataLength u32, Data[]
    mem.w32(infoBuf, entry.type);
    mem.w32(infoBuf + 4n, entry.data.length);
    mem.write(infoBuf + 8n, entry.data);
    mem.w32(resultLenOut, 8 + entry.data.length);
    return STATUS_SUCCESS;
  });
  k.define("ZwQueryKey", (handle, keyInfoClass, infoBuf, len, resultLenOut) => {
    void keyInfoClass; void len;
    const key = kernel.handles.get(ptrSizeMask(handle));
    if (!key) return STATUS_INVALID_PARAMETER;
    const subkeys = [...kernel.registry.keys()].filter((p) =>
      p.toLowerCase().startsWith(key.toLowerCase() + "\\")).length;
    mem.w32(infoBuf + 0x0c, subkeys); // SubKeys field offset in KEY_BASIC_INFORMATION-ish
    mem.w32(resultLenOut, 0x18);
    return STATUS_SUCCESS;
  });

  /** Seed helper exposed for scenarios/tests. */
  kernel.registrySeed = (path, values) => {
    const m = new Map(Object.entries(values).map(([vn, v]) => [vn, {
      type: 1, // REG_SZ
      data: new Uint8Array([...v.split("").map((c) => c.charCodeAt(0)), 0]),
    }]));
    kernel.registry.set(path, m);
  };

  // ------------------------------------------- routine address resolution

  k.define("MmGetSystemRoutineAddress", (usNameVa) => {
    const name = usRead(mem, usNameVa).str;
    const thunk = kernel.apiThunks.get(name);
    if (thunk) return thunk;
    kernel.unsupportedExports.push(name);
    kernel.dbgLog.push(`[winapi] MmGetSystemRoutineAddress("${name}") -> unresolved`);
    return 0n;
  });

  // Everything below (devices/IRPs, registry writes+enum, virtual FS,
  // sections, interlocked64, events/mutexes/resources, time, extended
  // strings, Se/Ob/Mm/Po/Etw/WMI/FsRtl coverage) lives in winapi-ext.mjs.
  installWinApiExt(kernel, { impls, k, usRead, usWrite: k.usWrite });
}
