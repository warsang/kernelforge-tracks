/**
 * winapi-ext.mjs — expanded ntoskrnl export coverage (analyzer tier).
 *
 * Organized to mirror speakeasy/ktrace-style harness breadth:
 *   devices/IRPs, registry writes + enumeration, virtual filesystem,
 *   sections, 64-bit interlocked, events/mutexes/resources, time,
 *   extended string ops, Se/Ob/Mm/Po/Etw/WMI/FsRtl/misc.
 *
 * Fidelity tiers, in order of preference:
 *   1. real semantics over emulated state
 *   2. recorded stub (visible trace + plausible return)
 *   3. generic provisioned thunk (kernel.provisionUnknownApi) — any import
 *      a binary can throw at us resolves; failures stay visible.
 */

import {
  createDriverObject,
  createDeviceObject,
  DEVICE_OBJECT,
  DRIVER_OBJECT,
  IRP,
  IO_STACK_LOCATION,
} from "./devices.mjs";

const STATUS_SUCCESS = 0x00000000n;
const STATUS_INVALID_PARAMETER = 0xc000000dn;
const STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034n;

function ptrSizeMask(v) {
  return BigInt.asUintN(64, BigInt(v));
}

/** Minimal printf: %d %u %x %X %p %s %S %wZ %c. Consumes args array. */
function formatAnsi(mem, fmtVa, args) {
  const fmt = mem.readAnsi(fmtVa, 512);
  let ai = 0;
  const next = () => args[ai++] ?? 0n;
  return fmt.replace(/%(-?\d+)?(?:l+)?([diuxXpcsSwZ])/g, (_m, _w, conv) => {
    const v = next();
    switch (conv) {
      case "d": case "i": return BigInt.asIntN(64, v).toString();
      case "u": return v.toString();
      case "x": case "X": return v.toString(16);
      case "p": return `0x${v.toString(16).padStart(16, "0")}`;
      case "c": return String.fromCharCode(Number(v & 0xffn));
      case "s": return mem.readAnsi(v);
      case "S": case "wZ": {
        const len = mem.u16(v);
        return len ? mem.readUtf16(mem.u64(v + 8n), Math.min(len / 2, 512)) : "";
      }
      default: return `%${conv}`;
    }
  });
}

export function installWinApiExt(kernel, ctx) {
  const { impls, k, usRead } = ctx;
  const mem = kernel.mem;
  const t = kernel.tables;

  // ------------------------------------------------------ devices & IRPs

  k.define("IoCreateDevice", (driverObj, extSize, name, type, chars, reserved, devOut) => {
    void chars; void reserved;
    const drv = kernel.driverObjects?.get(ptrSizeMask(driverObj))
      ?? createDriverObject(kernel, "unnamed", { va: ptrSizeMask(driverObj) });
    const dev = createDeviceObject(kernel, drv, {
      extensionSize: Number(extSize ?? 0),
      type: Number(BigInt(type ?? 0n) & 0xffffn),
    });
    if (name) {
      const devName = usRead(mem, name).str;
      const bufVa = dev.va + 0xf0n;
      mem.writeUtf16(bufVa, devName.slice(0, 120));
    }
    mem.w64(devOut, dev.va);
    return STATUS_SUCCESS;
  });

  k.define("IoDeleteDevice", (devObj) => {
    const va = ptrSizeMask(devObj);
    kernel.devices = (kernel.devices ?? []).filter((d) => d.va !== va);
    return undefined;
  });

  k.define("IoCreateSymbolicLink", (linkUs, targetUs) => {
    kernel.symbolicLinks = kernel.symbolicLinks ?? [];
    kernel.symbolicLinks.push({
      link: usRead(mem, linkUs).str,
      target: usRead(mem, targetUs).str,
    });
    return STATUS_SUCCESS;
  });

  k.define("IoDeleteSymbolicLink", (linkUs) => {
    const s = usRead(mem, linkUs).str.toLowerCase();
    kernel.symbolicLinks = (kernel.symbolicLinks ?? [])
      .filter((x) => x.link.toLowerCase() !== s);
    return STATUS_SUCCESS;
  });

  /** Forward an IRP into a modeled device's MajorFunction dispatch. */
  const callModeledDevice = (devObjVa, irpVa) => {
    const rec = (kernel.devices ?? []).find((d) => d.va === ptrSizeMask(devObjVa));
    if (!rec || !irpVa) return null;
    const stack = mem.u64(irpVa + BigInt(IRP.CURRENT_STACK_LOCATION));
    if (!stack) return null;
    const major = mem.u8(stack);
    const handler = mem.u64(rec.driver.va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION + major * 8));
    mem.w64(devObjVa + BigInt(DEVICE_OBJECT.CURRENT_IRP), irpVa);
    const r = kernel.callFunctionSeh
      ? kernel.callFunctionSeh(handler, [devObjVa, irpVa])
      : kernel.cpu.callFunction(handler, [devObjVa, irpVa]);
    mem.w64(devObjVa + BigInt(DEVICE_OBJECT.CURRENT_IRP), 0n);
    if (r.status !== "ok") return 0xc0000001n;
    return BigInt(mem.u32(irpVa + BigInt(IRP.IO_STATUS_STATUS)));
  };

  k.define("IofCallDriver", (devObj, irp) => {
    const r = callModeledDevice(devObj, irp);
    if (r !== null) return r;
    if (irp) mem.w32(irp + BigInt(IRP.IO_STATUS_STATUS), 0xc0000001); // unmodeled stack
    return 0xc0000001n;
  });
  k.define("IoCallDriver", (...a) => impls.IofCallDriver(...a));
  k.define("PoCallDriver", (...a) => impls.IofCallDriver(...a));

  k.define("IoAttachDeviceToDeviceStack", (srcDev, tgtDev) => {
    mem.w64(srcDev + BigInt(DEVICE_OBJECT.ATTACHED_DEVICE), ptrSizeMask(tgtDev));
    return srcDev; // approximation: real returns the layer attached TO
  });
  k.define("IoDetachDevice", () => undefined);

  k.define("IoMarkIrpPending", (irp) => {
    const stack = ptrSizeMask(irp) ? mem.u64(irp + BigInt(IRP.CURRENT_STACK_LOCATION)) : 0n;
    if (stack) mem.w8(stack + BigInt(IO_STACK_LOCATION.CONTROL), mem.u8(stack + BigInt(IO_STACK_LOCATION.CONTROL)) | 0x01);
    return undefined;
  });

  k.define("IoSkipCurrentIrpStackLocation", (irp) => {
    const cur = mem.u64(irp + BigInt(IRP.CURRENT_STACK_LOCATION));
    if (cur) mem.w64(irp + BigInt(IRP.CURRENT_STACK_LOCATION), cur - BigInt(IRP.STACK_SIZE));
    return undefined;
  });

  k.define("IoCopyCurrentIrpStackLocationToNext", (irp) => {
    const cur = mem.u64(irp + BigInt(IRP.CURRENT_STACK_LOCATION));
    if (!cur) return undefined;
    const next = cur - BigInt(IRP.STACK_SIZE);
    mem.write(next, mem.read(cur, IO_STACK_LOCATION.COMPLETION_ROUTINE)); // params+flags
    mem.w64(next + BigInt(IO_STACK_LOCATION.COMPLETION_ROUTINE), 0n);
    mem.w64(next + BigInt(IO_STACK_LOCATION.CONTEXT), 0n);
    mem.w64(irp + BigInt(IRP.CURRENT_STACK_LOCATION), next);
    return undefined;
  });
  k.define("IoSetCompletionRoutine", () => undefined); // guest writes slots directly

  k.define("IoAllocateIrp", (stackSize) => k.alloc(IRP.HEADER_SIZE + Number(stackSize ?? 1) * IRP.STACK_SIZE));
  k.define("IoFreeIrp", () => undefined);

  k.define("IoCompleteRequest", (irp, priority) => {
    void priority;
    if (irp) {
      // record, don't clobber: driver already wrote IoStatus
      kernel.lastCompletedIrp = {
        va: ptrSizeMask(irp),
        status: mem.u32(irp + BigInt(IRP.IO_STATUS_STATUS)),
        information: mem.u64(irp + BigInt(IRP.IO_STATUS_INFORMATION)),
      };
    }
    return undefined;
  });
  // IofCompleteRequest is the fastcall export drivers actually link against.
  k.define("IofCompleteRequest", (...a) => impls.IoCompleteRequest(...a));

  k.define("IoAllocateMdl", (virtAddr, len, secondary, chargeQuota, irp) => {
    void chargeQuota;
    const mdl = k.alloc(0x40);
    mem.w64(mdl + 0x08, ptrSizeMask(virtAddr));
    mem.w32(mdl + 0x10, Number(len));
    if (irp && !secondary) mem.w64(irp + IRP.MDL_ADDRESS, mdl);
    return mdl;
  });
  k.define("IoFreeMdl", () => undefined);
  k.define("MmProbeAndLockPages", () => STATUS_SUCCESS);
  k.define("MmUnlockPages", () => undefined);

  // ---------------------------------------------------------- work items

  kernel.workItemDevices = kernel.workItemDevices ?? new Map();
  k.define("IoAllocateWorkItem", (devObj) => {
    const wi = k.alloc(0x40);
    kernel.workItemDevices.set(ptrSizeMask(wi), ptrSizeMask(devObj));
    return wi;
  });
  k.define("IoFreeWorkItem", (wi) => { kernel.workItemDevices.delete(ptrSizeMask(wi)); return undefined; });
  k.define("IoInitializeWorkItem", () => undefined);
  k.define("IoUninitializeWorkItem", () => undefined);
  k.define("IoQueueWorkItem", (ioWi, worker, queueType, context) => {
    void queueType;
    kernel.pendingWorkItems.push({
      device: kernel.workItemDevices.get(ptrSizeMask(ioWi)) ?? 0n,
      worker: ptrSizeMask(worker),
      context: ptrSizeMask(context),
    });
    return undefined;
  });
  k.define("ExInitializeWorkItem", (wi, routine, c) => {
    mem.w64(wi, ptrSizeMask(routine));
    mem.w64(wi + 8n, ptrSizeMask(c));
    return undefined;
  });
  k.define("ExQueueWorkItem", (wi, queueType) => {
    void queueType;
    kernel.pendingWorkItems.push({
      device: 0n,
      worker: mem.u64(wi),
      context: mem.u64(wi + 8n),
    });
    return undefined;
  });

  // ---------------------------------------------------------------- APCs

  k.define("KeInitializeApc", (apc, thread, env, kernRoutine, rundown, normalRoutine, mode, c) => {
    void env; void mode; void rundown;
    mem.w64(apc + 0x00, ptrSizeMask(thread));
    mem.w64(apc + 0x08, kernRoutine ? ptrSizeMask(kernRoutine) : 0n);
    mem.w64(apc + 0x10, normalRoutine ? ptrSizeMask(normalRoutine) : 0n);
    mem.w64(apc + 0x18, ptrSizeMask(c));
    return undefined;
  });
  k.define("KeInsertQueueApc", (apc, sysArg1, sysArg2, priority) => {
    void priority;
    kernel.pendingApcs.push({
      normalRoutine: mem.u64(apc + 0x10),
      normalContext: mem.u64(apc + 0x18),
      systemArgument1: ptrSizeMask(sysArg1),
      systemArgument2: ptrSizeMask(sysArg2),
    });
    return 1n;
  });
  k.define("KeRemoveQueueApc", () => 1n);

  // ------------------------------------------------ process attach (KAPC_STATE)
  //
  // KeStackAttachProcess rotates the calling thread's KTHREAD.ApcState into
  // another process's address space: the current state is saved both into
  // KTHREAD.SavedApcState and the caller's PKAPC_STATE buffer, then
  // ApcState.Process points at the target EPROCESS and ApcStateIndex flips
  // to 1. Detach restores from the caller's buffer. ntsim models the
  // metadata rotation exactly — address spaces themselves are abstracted
  // away elsewhere (cf. MmCopyVirtualMemory below).
  //
  // Detection relevance: an attached thread's ApcState.Process still names
  // its target EPROCESS even after that process is DKOM-unlinked.
  // Offsets resolve lazily through kernel.tables: this module installs at
  // construction time, before loadTablesFromDir may swap in the real build.
  const off = (type, field) => {
    try { return kernel.tables.offsetOf(type, field); } catch { return null; }
  };
  const eprocName = (eproc) => {
    const o = off("_EPROCESS", "ImageFileName");
    return o === null || !eproc ? "?" : mem.readAnsi(eproc + o, 15);
  };
  // MODELED KAPC_STATE buffer divergence: callers receive
  //   +0x10 ULONG64 saved ApcState.Process
  //   +0x18 UCHAR   saved ApcStateIndex
  // (offsets mirror the real struct so student C code can read .Process)
  const APC_BUF_PROC = 0x10n;
  const APC_BUF_IDX = 0x18n;
  k.define("KeStackAttachProcess", (proc, apcState) => {
    const thr = kernel.currentThread;
    const kApcOff = off("_KTHREAD", "ApcState");
    if (!thr || kApcOff === null) {
      kernel.dbgLog.push("[attach] KeStackAttachProcess: no thread context — no-op");
      return undefined;
    }
    const kSavedApcOff = off("_KTHREAD", "SavedApcState");
    const kApcIdxOff = off("_KTHREAD", "ApcStateIndex");
    proc = ptrSizeMask(proc);
    const oldProc = mem.u64(thr + kApcOff);
    const oldIdx = kApcIdxOff !== null ? mem.u8(thr + kApcIdxOff) : 0;
    if (apcState) {
      mem.w64(apcState + APC_BUF_PROC, oldProc);
      mem.w8(apcState + APC_BUF_IDX, oldIdx);
    }
    if (kSavedApcOff !== null) mem.w64(thr + kSavedApcOff, oldProc);
    mem.w64(thr + kApcOff, proc);
    if (kApcIdxOff !== null) mem.w8(thr + kApcIdxOff, oldIdx | 1);
    kernel.dbgLog.push(
      `[attach] thread ${thr.toString(16)}: ApcState.Process ` +
      `${eprocName(oldProc)} -> ${eprocName(proc)} (ApcStateIndex=${oldIdx | 1})`);
    return undefined;
  });
  k.define("KeUnstackDetachProcess", (apcState) => {
    const thr = kernel.currentThread;
    const kApcOff = off("_KTHREAD", "ApcState");
    if (!thr || kApcOff === null) {
      kernel.dbgLog.push("[attach] KeUnstackDetachProcess: no thread context — no-op");
      return undefined;
    }
    const kSavedApcOff = off("_KTHREAD", "SavedApcState");
    const kApcIdxOff = off("_KTHREAD", "ApcStateIndex");
    let savedProc = apcState ? mem.u64(apcState + APC_BUF_PROC) : 0n;
    let savedIdx = apcState ? mem.u8(apcState + APC_BUF_IDX) : 0;
    if (!savedProc && kSavedApcOff !== null) savedProc = mem.u64(thr + kSavedApcOff);
    mem.w64(thr + kApcOff, ptrSizeMask(savedProc));
    if (kSavedApcOff !== null) mem.w64(thr + kSavedApcOff, 0n);
    if (kApcIdxOff !== null) mem.w8(thr + kApcIdxOff, savedIdx & ~1);
    kernel.dbgLog.push(
      `[attach] thread ${thr.toString(16)}: detached -> ApcState.Process ` +
      `${eprocName(savedProc)} (ApcStateIndex=${savedIdx & ~1})`);
    return undefined;
  });

  // --------------------------------------------- process / thread / callbacks

  // Process handles live in the shared kernel.handles map as typed records.
  let nextProcHandle = 0x3100n;
  const procHandle = (eproc, pid) => {
    const h = nextProcHandle++;
    kernel.handles.set(h, { type: "process", eproc, pid });
    return h;
  };
  let nextThreadId = 0x4n;

  k.define("ZwOpenProcess", (phOut, desiredAccess, objAttr, clientId) => {
    void desiredAccess; void objAttr;
    // CLIENT_ID.UniqueProcess @ +0x00
    const pid = clientId ? mem.u64(clientId) : 0n;
    const eproc = kernel.findEprocessByPid?.(pid);
    if (!eproc) {
      kernel.dbgLog.push(`[ps] ZwOpenProcess(pid=${pid}) -> not found`);
      return STATUS_INVALID_PARAMETER;
    }
    const h = procHandle(eproc, pid);
    if (phOut) mem.w64(phOut, h);
    kernel.dbgLog.push(`[ps] ZwOpenProcess(pid=${pid}) -> handle 0x${h.toString(16)}`);
    return STATUS_SUCCESS;
  });

  k.define("ZwTerminateProcess", (h, exitStatus) => {
    const rec = kernel.handles.get(ptrSizeMask(h));
    const pid = rec && typeof rec === "object" ? rec.pid : ptrSizeMask(h);
    kernel.dbgLog.push(`[ps] ZwTerminateProcess(handle=0x${ptrSizeMask(h).toString(16)} pid=${pid} status=0x${ptrSizeMask(exitStatus).toString(16)})`);
    return STATUS_SUCCESS;
  });

  // Real semantics read Irp->Tail/creator process; in the virtual world IRPs
  // originate from System, so the honest answer is its pid.
  k.define("IoGetRequestorProcessId", () => 4n);

  k.define("PsCreateSystemThread", (
    threadHandleOut, desiredAccess, objAttr, processHandle, clientId,
    startRoutine, startContext,
  ) => {
    void desiredAccess; void objAttr; void processHandle;
    const h = nextProcHandle++ | 0x8000000000000000n; // kernel-handle flavor
    if (threadHandleOut) mem.w64(threadHandleOut, h);
    if (clientId) { // CLIENT_ID { UniqueProcess=System(4), UniqueThread }
      mem.w64(clientId, 4n);
      mem.w64(clientId + 8n, nextThreadId++);
    }
    kernel.pendingThreads.push({
      handle: ptrSizeMask(h),
      startRoutine: ptrSizeMask(startRoutine),
      startContext: ptrSizeMask(startContext),
    });
    kernel.dbgLog.push(`[thread] PsCreateSystemThread -> handle 0x${ptrSizeMask(h).toString(16)} start 0x${ptrSizeMask(startRoutine).toString(16)} ctx 0x${ptrSizeMask(startContext).toString(16)}`);
    return STATUS_SUCCESS;
  });

  k.define("PsTerminateSystemThread", (status) => {
    const s = ptrSizeMask(status);
    kernel.dbgLog.push(`[thread] PsTerminateSystemThread(status=0x${s.toString(16)})`);
    return s === 0n ? STATUS_SUCCESS : s;
  });

  // The interpreter resolves table-SEH itself (seh.mjs); drivers still import
  // the routine to satisfy the linker. Keep it callable and harmless.
  k.define("__C_specific_handler", () => 0n);

  // OB_CALLBACK_REGISTRATION:
  //   +0x00 u16 Version, +0x02 u16 OperationRegistrationCount, +pad
  //   +0x08 UNICODE_STRING Altitude, +0x18 pad, +0x20 void* RegistrationContext,
  //   +0x28 OB_OPERATION_REGISTRATION* (ObjectType, PreOp, PostOp triplets)
  kernel.obCallbacks = kernel.obCallbacks ?? [];
  k.define("ObRegisterCallbacks", (cbReg) => {
    cbReg = ptrSizeMask(cbReg);
    if (!cbReg) return STATUS_INVALID_PARAMETER;
    const count = mem.u16(cbReg + 2n);
    const altitude = usRead(mem, cbReg + 8n).str;
    const opsBase = mem.u64(cbReg + 0x28n);
    const entries = [];
    for (let i = 0; i < Math.min(count, 8); i++) {
      entries.push({
        objectType: mem.u64(opsBase + BigInt(i * 24)),
        preOp: mem.u64(opsBase + BigInt(i * 24 + 8)),
        postOp: mem.u64(opsBase + BigInt(i * 24 + 16)),
      });
    }
    kernel.obCallbacks.push({ registration: cbReg, altitude, entries });
    kernel.dbgLog.push(`[ob] ObRegisterCallbacks altitude "${altitude}" ops=${count} pre=[${entries.map((e) => "0x" + e.preOp.toString(16)).join(", ")}]`);
    return STATUS_SUCCESS;
  });
  k.define("ObUnRegisterCallbacks", (registration) => {
    registration = ptrSizeMask(registration);
    const idx = kernel.obCallbacks.findIndex((r) => r.registration === registration);
    if (idx >= 0) kernel.obCallbacks.splice(idx, 1);
    kernel.dbgLog.push(`[ob] ObUnRegisterCallbacks(reg=0x${registration.toString(16)})`);
    return undefined;
  });

  // ------------------------------------------------------------ KMDF loader

  // WDF drivers gate init on these succeeding; record bindings for reports.
  kernel.wdfBindings = kernel.wdfBindings ?? [];
  k.define("WdfVersionBind", (driverObject, registryPath, bindParams, bindInfo) => {
    void driverObject;
    const ver = bindParams ? mem.u64(ptrSizeMask(bindParams) + 0x10n) : 0n; // WDF_VERSION
    kernel.wdfBindings.push({ kind: "bind", version: ver, bindInfo: ptrSizeMask(bindInfo) });
    kernel.dbgLog.push(`[wdf] WdfVersionBind version=0x${ver.toString(16)} -> SUCCESS`);
    return STATUS_SUCCESS;
  });
  k.define("WdfVersionUnbind", () => {
    kernel.dbgLog.push("[wdf] WdfVersionUnbind");
    return STATUS_SUCCESS;
  });
  k.define("WdfVersionBindClass", (bindParams) => {
    const ver = bindParams ? mem.u64(ptrSizeMask(bindParams) + 0x10n) : 0n;
    kernel.wdfBindings.push({ kind: "bindClass", version: ver });
    kernel.dbgLog.push(`[wdf] WdfVersionBindClass version=0x${ver.toString(16)} -> SUCCESS`);
    return STATUS_SUCCESS;
  });
  k.define("WdfVersionUnbindClass", () => {
    kernel.dbgLog.push("[wdf] WdfVersionUnbindClass");
    return STATUS_SUCCESS;
  });
  k.define("WdfLdrQueryInterface", (queryParams) => {
    kernel.dbgLog.push(`[wdf] WdfLdrQueryInterface(params=0x${ptrSizeMask(queryParams).toString(16)}) -> SUCCESS`);
    return STATUS_SUCCESS;
  });

  // KeRemoveQueueDpc lives in winapi.mjs (drained-flag model on kernel.queueDpc
  // records) — do not shadow it here.

  // ------------------------------------------------------------ registry

  const normKey = (name) => "\\" + name.replace(/^\\*/, "");
  const keyHandleFromObjAttr = (objAttr) => {
    if (!objAttr) return null;
    const name = usRead(mem, mem.u64(objAttr + 0x10n)).str;
    const norm = normKey(name);
    for (const key of kernel.registry.keys()) {
      if (key.toLowerCase() === norm.toLowerCase()) return { handle: null, key, exists: true };
    }
    return { handle: null, key: norm, exists: false };
  };
  // regHandle lives in winapi.mjs's closure — emulate via kernel.handles seq
  let regHandleSeq = 0x2000_0000n;
  const regHandle = (key) => {
    const h = ++regHandleSeq;
    kernel.handles.set(h, key);
    return h;
  };

  k.define("ZwOpenKeyEx", (...a) => impls.ZwOpenKey(...a));
  k.define("NtOpenKey", (...a) => impls.ZwOpenKey(...a));
  k.define("ZwCreateKey", (handleOut, access, objAttr, titleIndex, classUs, options, dispositionOut) => {
    void access; void titleIndex; void classUs; void options;
    const info = keyHandleFromObjAttr(objAttr);
    if (!info.exists) {
      kernel.registry.set(info.key, new Map());
      if (dispositionOut) mem.w32(dispositionOut, 1); // REG_CREATED_NEW_KEY
      mem.w64(handleOut, regHandle(info.key));
    } else {
      if (dispositionOut) mem.w32(dispositionOut, 2); // REG_OPENED_EXISTING_KEY
      mem.w64(handleOut, regHandle(info.key));
    }
    return STATUS_SUCCESS;
  });
  k.define("NtCreateKey", (...a) => impls.ZwCreateKey(...a));

  k.define("ZwSetValueKey", (handle, valueName, titleIndex, type, data, dataLen) => {
    void titleIndex;
    const key = kernel.handles.get(ptrSizeMask(handle));
    if (!key || typeof key !== "string") return STATUS_INVALID_PARAMETER;
    const vn = usRead(mem, valueName).str;
    kernel.registry.get(key)?.set(vn, {
      type: Number(type) & 0xff,
      data: Uint8Array.from(mem.read(data, Number(dataLen))),
    });
    return STATUS_SUCCESS;
  });
  k.define("NtSetValueKey", (...a) => impls.ZwSetValueKey(...a));

  k.define("ZwDeleteValueKey", (handle, valueName) => {
    const key = kernel.handles.get(ptrSizeMask(handle));
    if (!key || typeof key !== "string") return STATUS_INVALID_PARAMETER;
    const vn = usRead(mem, valueName).str;
    return kernel.registry.get(key)?.delete(vn) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
  });

  k.define("ZwEnumerateValueKey", (handle, index, infoClass, infoBuf, infoLen, resultLenOut) => {
    void infoClass; void infoLen;
    const key = kernel.handles.get(ptrSizeMask(handle));
    if (!key || typeof key !== "string") return STATUS_INVALID_PARAMETER;
    const names = [...(kernel.registry.get(key)?.keys() ?? [])];
    const i = Number(index);
    if (i >= names.length) return 0x8000001an; // STATUS_NO_MORE_ENTRIES
    const name = names[i];
    // KEY_VALUE_BASIC_INFORMATION: TitleIndex u32, Type u32, NameLength u32, Name[] UTF16
    mem.w32(infoBuf + 0, i);
    mem.w32(infoBuf + 4, kernel.registry.get(key).get(name)?.type ?? 1);
    mem.w32(infoBuf + 8, name.length * 2);
    for (let c = 0; c < name.length; c++) mem.w16(infoBuf + 12n + BigInt(c * 2), name.charCodeAt(c));
    mem.w32(resultLenOut, 12 + name.length * 2);
    return STATUS_SUCCESS;
  });

  k.define("ZwEnumerateKey", (handle, index, infoClass, infoBuf, infoLen, resultLenOut) => {
    void infoClass; void infoLen;
    const key = kernel.handles.get(ptrSizeMask(handle));
    if (!key || typeof key !== "string") return STATUS_INVALID_PARAMETER;
    const subs = [...kernel.registry.keys()]
      .filter((p) => p.toLowerCase().startsWith(key.toLowerCase() + "\\"))
      .map((p) => p.slice(key.length + 1));
    const i = Number(index);
    if (i >= subs.length) return 0x8000001an;
    const name = subs[i].split("\\")[0];
    // KEY_BASIC_INFORMATION: LastWriteTime u64, TitleIndex u32, NameLength u32, Name[] UTF16
    mem.w64(infoBuf, 0n);
    mem.w32(infoBuf + 8, i);
    mem.w32(infoBuf + 12, name.length * 2);
    for (let c = 0; c < name.length; c++) mem.w16(infoBuf + 16n + BigInt(c * 2), name.charCodeAt(c));
    mem.w32(resultLenOut, 16 + name.length * 2);
    return STATUS_SUCCESS;
  });
  k.define("ZwFlushKey", () => STATUS_SUCCESS);
  k.define("NtClose", (...a) => impls.ZwClose(...a));

  // Cm callbacks
  kernel.cmCallbacks = [];
  k.define("CmRegisterCallback", (fn, c, cookieOut) => {
    const cookie = kernel.cmCallbacks.length + 1;
    kernel.cmCallbacks.push({ fn: ptrSizeMask(fn), ctx: ptrSizeMask(c), cookie });
    mem.w32(cookieOut, cookie);
    return STATUS_SUCCESS;
  });
  k.define("CmRegisterCallbackEx", (fn, _alt, c, cookieOut) =>
    impls.CmRegisterCallback(fn, c, cookieOut));
  k.define("CmUnRegisterCallback", (cookie) => {
    kernel.cmCallbacks = kernel.cmCallbacks.filter((c) => c.cookie !== Number(cookie));
    return STATUS_SUCCESS;
  });

  // -------------------------------------------------------- virtual FS

  kernel.fs = kernel.fs ?? new Map(); // path -> Uint8Array
  let fileHandleSeq = 0x4000_0000n;
  const FILE_OPEN = 1, FILE_CREATE = 2, FILE_OVERWRITE_IF = 5, FILE_OPEN_IF = 4;

  const pathFromObjAttr = (objAttr) => objAttr ? usRead(mem, mem.u64(objAttr + 0x10n)).str : "";

  k.define("ZwCreateFile", (handleOut, access, objAttr, iosb, allocSize, attrs, share, disp, options, eaBuf, eaLen) => {
    void access; void iosb; void allocSize; void attrs; void share; void options; void eaBuf; void eaLen;
    const p = pathFromObjAttr(objAttr);
    if (!p) return STATUS_INVALID_PARAMETER;
    const exists = kernel.fs.has(p);
    const d = Number(disp);
    if (!exists && !(d === FILE_CREATE || d === FILE_OVERWRITE_IF || d === FILE_OPEN_IF || d === 0 /*supersede*/)) {
      return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (!exists) kernel.fs.set(p, new Uint8Array(0));
    const h = fileHandleSeq++;
    kernel.handles.set(h, { __file: p });
    mem.w64(handleOut, h);
    return STATUS_SUCCESS;
  });
  k.define("NtCreateFile", (...a) => impls.ZwCreateFile(...a));
  k.define("ZwOpenFile", (handleOut, access, objAttr, iosb, share, options) =>
    impls.ZwCreateFile(handleOut, access, objAttr, iosb, 0n, 0n, share, FILE_OPEN, options, 0n, 0n));
  k.define("NtOpenFile", (...a) => impls.ZwOpenFile(...a));

  const fileOf = (handle) => kernel.handles.get(ptrSizeMask(handle))?.__file ?? null;

  k.define("ZwWriteFile", (handle, ev, apcR, apcCtx, iosb, buffer, len, byteOffsetPtr, key) => {
    void ev; void apcR; void apcCtx; void key;
    const p = fileOf(handle);
    if (!p) return STATUS_INVALID_PARAMETER;
    const off = byteOffsetPtr ? Number(mem.u64(byteOffsetPtr)) : 0;
    const bytes = Uint8Array.from(mem.read(buffer, Number(len)));
    const cur = kernel.fs.get(p) ?? new Uint8Array(0);
    const end = Math.max(cur.length, off + bytes.length);
    const merged = new Uint8Array(end);
    merged.set(cur);
    merged.set(bytes, off);
    kernel.fs.set(p, merged);
    if (iosb) { mem.w32(iosb, 0); mem.w64(iosb + 8n, BigInt(bytes.length)); }
    return STATUS_SUCCESS;
  });
  k.define("NtWriteFile", (...a) => impls.ZwWriteFile(...a));

  k.define("ZwReadFile", (handle, ev, apcR, apcCtx, iosb, buffer, len, byteOffsetPtr, key) => {
    void ev; void apcR; void apcCtx; void key;
    const p = fileOf(handle);
    if (!p) return STATUS_INVALID_PARAMETER;
    const off = byteOffsetPtr ? Number(mem.u64(byteOffsetPtr)) : 0;
    const data = kernel.fs.get(p) ?? new Uint8Array(0);
    const n = Math.min(Number(len), Math.max(0, data.length - off));
    mem.write(buffer, data.subarray(off, off + n));
    if (iosb) { mem.w32(iosb, 0); mem.w64(iosb + 8n, BigInt(n)); }
    return STATUS_SUCCESS;
  });
  k.define("NtReadFile", (...a) => impls.ZwReadFile(...a));

  k.define("ZwQueryInformationFile", (handle, iosb, info, len, infoClass) => {
    void iosb;
    const p = fileOf(handle);
    if (!p) return STATUS_INVALID_PARAMETER;
    const size = BigInt((kernel.fs.get(p) ?? new Uint8Array(0)).length);
    if (Number(infoClass) === 5 && len >= 0x18) { // FileStandardInformation
      mem.w64(info, size);
      mem.w64(info + 8n, size);
      mem.w32(info + 0x10, 1);
      mem.w8(info + 0x14, 0);
      mem.w8(info + 0x15, 0);
    }
    return STATUS_SUCCESS;
  });
  k.define("ZwDeleteFile", (objAttr) => {
    kernel.fs.delete(pathFromObjAttr(objAttr));
    return STATUS_SUCCESS;
  });

  // ----------------------------------------------------------- sections

  kernel.sections = kernel.sections ?? new Map(); // path -> bytes
  let sectionSeq = 0x6000_0000n;
  k.define("ZwOpenSection", (handleOut, access, objAttr) => {
    void access;
    const p = pathFromObjAttr(objAttr);
    if (!kernel.sections.has(p)) return STATUS_OBJECT_NAME_NOT_FOUND;
    const h = sectionSeq++;
    kernel.handles.set(h, { __section: p });
    mem.w64(handleOut, h);
    return STATUS_SUCCESS;
  });
  k.define("ZwMapViewOfSection", (handle, process, baseOut, zeroBits, commitSize, offsetPtr, viewSizePtr, inherit, alloc, prot) => {
    void process; void zeroBits; void offsetPtr; void inherit; void alloc; void prot;
    const p = kernel.handles.get(ptrSizeMask(handle))?.__section;
    if (!p) return STATUS_INVALID_PARAMETER;
    const data = kernel.sections.get(p) ?? new Uint8Array(0);
    const want = viewSizePtr ? Number(mem.u64(viewSizePtr)) : 0;
    const n = Math.max(Math.min(Number(commitSize ?? 0n), data.length), Math.min(want, data.length), 1);
    const va = k.alloc(n);
    mem.write(va, data.subarray(0, n));
    mem.w64(baseOut, va);
    if (viewSizePtr) mem.w64(viewSizePtr, BigInt(n));
    return STATUS_SUCCESS;
  });
  k.define("ZwUnmapViewOfSection", () => STATUS_SUCCESS);

  // ---------------------------------------------------- interlocked (64)

  const rmw64 = (va, fn) => {
    const cur = mem.u64(va);
    mem.w64(va, fn(cur));
    return cur;
  };
  const rmw32 = (va, fn) => {
    const cur = mem.u32(va);
    mem.w32(va, fn(cur) >>> 0);
    return cur;
  };
  k.define("InterlockedIncrement64", (va) => rmw64(va, (c) => c + 1n) + 1n);
  k.define("InterlockedDecrement64", (va) => rmw64(va, (c) => c - 1n) - 1n);
  k.define("InterlockedExchange64", (va, v) => rmw64(va, () => ptrSizeMask(v)));
  k.define("InterlockedExchangePointer", (va, v) => rmw64(va, () => ptrSizeMask(v)));
  k.define("InterlockedCompareExchange64", (va, exch, comparand) =>
    rmw64(va, (c) => (c === ptrSizeMask(comparand) ? ptrSizeMask(exch) : c)));
  k.define("InterlockedCompareExchangePointer", (va, exch, comparand) =>
    rmw64(va, (c) => (c === ptrSizeMask(comparand) ? ptrSizeMask(exch) : c)));
  k.define("InterlockedOr", (va, v) => BigInt(rmw32(va, (c) => c | Number(v))));
  k.define("InterlockedAnd", (va, v) => BigInt(rmw32(va, (c) => c & Number(v))));
  k.define("InterlockedXor", (va, v) => BigInt(rmw32(va, (c) => c ^ Number(v))));
  k.define("InterlockedPushEntrySList", (head, entry) => {
    const next = mem.u64(head);
    mem.w64(entry, next);
    mem.w64(head, ptrSizeMask(entry));
    return next;
  });
  k.define("InterlockedPopEntrySList", (head) => {
    const first = mem.u64(head);
    if (!first) return 0n;
    mem.w64(head, mem.u64(first));
    return first;
  });
  k.define("RtlInitializeSListHead", (head) => { mem.w64(head, 0n); return undefined; });

  // --------------------------------------------- events / mutex / resource

  k.define("KeInitializeEvent", (ev, type, state) => {
    mem.w32(ev, Number(state) & 0xff);
    mem.w32(ev + 4n, Number(type) & 0xff);
    return undefined;
  });
  k.define("KeSetEvent", (ev, wait, alertable) => {
    void wait; void alertable;
    const prev = mem.u32(ev);
    mem.w32(ev, 1);
    return BigInt(prev);
  });
  k.define("KeResetEvent", (ev) => {
    const prev = mem.u32(ev);
    mem.w32(ev, 0);
    return BigInt(prev);
  });
  k.define("KeClearEvent", (ev) => { mem.w32(ev, 0); return undefined; });
  k.define("KeReadStateEvent", (ev) => BigInt(mem.u32(ev)));
  k.define("KeInitializeMutex", (m, level) => { mem.w32(m, 1); mem.w32(m + 4n, level); return undefined; });
  k.define("KeReleaseMutex", (m, wait) => { void wait; mem.w32(m, 1); return 0n; });
  k.define("KeTryToAcquireFastMutex", () => 1n);
  k.define("KeEnterCriticalRegion", () => undefined);
  k.define("KeLeaveCriticalRegion", () => undefined);
  k.define("KeEnterGuardedRegion", () => undefined);
  k.define("KeLeaveGuardedRegion", () => undefined);
  k.define("KeWaitForMultipleObjects", () => STATUS_SUCCESS);
  k.define("KeQueryActiveProcessors", () => 1n);
  k.define("KeGetCurrentProcessorNumber", () => 0n);
  k.define("KeGetCurrentProcessorNumberEx", (_out) => 0n);
  k.define("KeQueryMaximumProcessorCount", () => 4n);
  k.define("KeSetTargetProcessorDpc", () => undefined);
  k.define("KeSetImportanceDpc", () => undefined);

  k.define("ExInitializeFastMutex", (fm) => {
    mem.w32(fm, 1); mem.w32(fm + 4n, 0); mem.w64(fm + 8n, 0n);
    return undefined;
  });
  k.define("ExAcquireFastMutex", () => { kernel.currentIrql = 1; return undefined; }); // APC_LEVEL
  k.define("ExReleaseFastMutex", () => { kernel.currentIrql = 0; return undefined; });
  k.define("ExAcquireFastMutexUnsafe", () => undefined);
  k.define("ExReleaseFastMutexUnsafe", () => undefined);

  k.define("ExInitializeResourceLite", (r) => { mem.write(r, new Uint8Array(0x50)); return STATUS_SUCCESS; });
  k.define("ExAcquireResourceExclusiveLite", (r, wait) => { void r; void wait; return 1n; });
  k.define("ExAcquireResourceSharedLite", (r, wait) => { void r; void wait; return 1n; });
  k.define("ExReleaseResourceLite", () => undefined);
  k.define("ExDeleteResourceLite", () => STATUS_SUCCESS);
  k.define("ExIsResourceAcquiredExclusiveLite", () => 1n);

  k.define("KeInitializeSemaphore", (s, count, limit) => {
    mem.w32(s, Number(count)); mem.w32(s + 4n, Number(limit));
    return undefined;
  });

  // ----------------------------------------------------------------- time

  k.define("KeQueryPerformanceCounter", (perfCountPtr) => {
    kernel.perfCounter = (kernel.perfCounter ?? 0n) + 10000n;
    if (perfCountPtr) mem.w64(perfCountPtr, kernel.perfCounter);
    return kernel.perfCounter;
  });
  k.define("KeQueryTimeIncrement", () => 156250n);
  k.define("ExSystemTimeToLocalTime", (sysIn, localOut) => {
    mem.w64(localOut, mem.u64(sysIn));
    return undefined;
  });
  k.define("ExLocalTimeToSystemTime", (localIn, sysOut) => {
    mem.w64(sysOut, mem.u64(localIn));
    return undefined;
  });
  k.define("RtlTimeToTimeFields", (ft, tf) => {
    // TIME_FIELDS: Year Month Day Hour Minute Second Milliseconds Weekday (8 x u16)
    const fields = [2026, 8, 25, 12, 0, 0, 0, 2]; // deterministic anchor date
    fields.forEach((v, i) => mem.w16(tf + BigInt(i * 2), v));
    void ft;
    return tf;
  });
  k.define("RtlTimeFieldsToTime", (_tf, ft, outDays) => {
    mem.w64(ft, kernel.systemTime ?? 0x01d9000000000000n);
    if (outDays) mem.w32(outDays, 0);
    return STATUS_SUCCESS;
  });

  // ------------------------------------------------------- extended strings

  k.define("RtlCompareUnicodeString", (aVa, bVa, caseIns) => {
    const a = usRead(mem, aVa).str;
    const b = usRead(mem, bVa).str;
    const [x, y] = caseIns ? [a.toLowerCase(), b.toLowerCase()] : [a, b];
    return x < y ? -1n : x > y ? 1n : 0n;
  });
  k.define("RtlEqualString", (aVa, bVa, caseIns) => {
    const rd = (va) => {
      const n = mem.u16(va);
      return n ? mem.readAnsi(mem.u64(va + 8n), Math.min(n, 1024)) : "";
    };
    const a = rd(aVa), b = rd(bVa);
    return (caseIns ? a.toLowerCase() === b.toLowerCase() : a === b) ? 1n : 0n;
  });
  k.define("RtlCompareString", (aVa, bVa, caseIns) => {
    const rd = (va) => {
      const n = mem.u16(va);
      return n ? mem.readAnsi(mem.u64(va + 8n), Math.min(n, 1024)) : "";
    };
    const a = rd(aVa), b = rd(bVa);
    const [x, y] = caseIns ? [a.toLowerCase(), b.toLowerCase()] : [a, b];
    return x < y ? -1n : x > y ? 1n : 0n;
  });
  k.define("RtlCopyUnicodeString", (dst, src) => {
    const s = usRead(mem, src);
    const maxBytes = mem.u16(dst + 2n);
    const copyBytes = Math.min(s.length * 2, maxBytes);
    if (copyBytes > 0 && s.buffer) {
      mem.write(dst + 0n + 8n, mem.read(s.buffer, copyBytes));
    }
    mem.w16(dst, copyBytes);
    return dst;
  });
  k.define("RtlAppendUnicodeStringToString", (dst, src) => {
    const d = usRead(mem, dst);
    const s = usRead(mem, src);
    const free = (mem.u16(dst + 2n) - d.length) / 2;
    const take = Math.min(free, s.str.length);
    if (take > 0) mem.writeUtf16(d.buffer + d.length, s.str.slice(0, take));
    mem.w16(dst, d.length + take * 2);
    return STATUS_SUCCESS;
  });
  k.define("RtlAppendUnicodeToString", (dst, strVa) => {
    if (!strVa) return STATUS_SUCCESS;
    const s = "";
    let chars = [];
    for (let i = 0; i < 1024; i++) {
      const c = mem.u16(strVa + BigInt(i * 2));
      if (!c) break;
      chars.push(c);
    }
    void s;
    const d = usRead(mem, dst);
    const free = (mem.u16(dst + 2n) - d.length) / 2;
    const take = Math.min(free, chars.length);
    if (take > 0) mem.writeUtf16(d.buffer + d.length, String.fromCharCode(...chars.slice(0, take)));
    mem.w16(dst, d.length + take * 2);
    return STATUS_SUCCESS;
  });
  k.define("RtlUpcaseUnicodeString", (dst, src, alloc) => {
    const s = usRead(mem, src);
    const up = s.str.toUpperCase();
    const buf = alloc ? k.alloc((up.length + 1) * 2) : s.buffer;
    mem.writeUtf16(buf, up);
    mem.w16(dst, up.length * 2);
    mem.w16(dst + 2n, (up.length + 1) * 2);
    mem.w64(dst + 8n, buf);
    return STATUS_SUCCESS;
  });
  k.define("RtlIntegerToUnicodeString", (value, base, strUs) => {
    const b = Number(base) || 10;
    const s = BigInt.asUintN(64, BigInt(value)).toString(b);
    mem.writeUtf16(mem.u64(strUs + 8n), s);
    mem.w16(strUs, s.length * 2);
    mem.w16(strUs + 2n, (s.length + 1) * 2);
    return STATUS_SUCCESS;
  });
  k.define("RtlCharToInteger", (strVa, base, out) => {
    let s = "";
    for (let i = 0; i < 64; i++) {
      const c = mem.u8(strVa + BigInt(i));
      if (!c) break;
      s += String.fromCharCode(c);
    }
    const b = Number(base) === 0 ? (s.startsWith("0x") ? 16 : 10) : Number(base);
    const v = BigInt(b === 16 ? s.replace(/^0x/i, "") : s.replace(/^-/, "")).valueOf();
    const neg = s.startsWith("-");
    mem.w32(out, Number((neg ? -v : v) & 0xffffffffn));
    return STATUS_SUCCESS;
  });
  k.define("sprintf", (buf, fmt, ...args) => {
    mem.write(buf, new TextEncoder().encode(formatAnsi(mem, fmt, args) + "\0"));
    return BigInt(formatAnsi(mem, fmt, args).length);
  });
  k.define("_snprintf", (buf, max, fmt, ...args) => {
    const s = formatAnsi(mem, fmt, args).slice(0, Number(max) - 1);
    mem.write(buf, new TextEncoder().encode(s + "\0"));
    return BigInt(s.length);
  });
  k.define("_vsnprintf", (buf, max, fmt, _va) => {
    const s = formatAnsi(mem, fmt, []).slice(0, Number(max) - 1);
    mem.write(buf, new TextEncoder().encode(s + "\0"));
    return BigInt(s.length);
  });
  k.define("swprintf", (buf, fmt, ...args) => {
    mem.writeUtf16(buf, formatAnsi(mem, fmt, args));
    return BigInt(formatAnsi(mem, fmt, args).length);
  });
  k.define("DbgPrintEx", (_comp, _level, fmt, ...args) => {
    kernel.dbgPrint(fmt, args);
    return STATUS_SUCCESS;
  });
  k.define("DbgQueryDebugFilterState", () => 1n);
  k.define("KdEnableDebugger", () => 1n);
  k.define("KdDisableDebugger", () => 0n);
  k.define("__chkstk", () => undefined); // MSVC large-frame prologue helper
  k.define("alloca_probe", () => undefined);
  k.define("_alloca_probe", () => undefined);
  k.define("RtlFillMemoryUlong", (dst, len, pattern) => {
    const p = Number(pattern) >>> 0;
    const n = Number(len);
    for (let i = 0; i < n; i += 4) {
      mem.w32(dst + BigInt(i), p);
    }
    return dst;
  });
  k.define("RtlSecureZeroMemory", (dst, len) => {
    mem.write(dst, new Uint8Array(Number(len)));
    return dst;
  });

  // --------------------------------------------------------- Se / Ob / Ps

  k.define("PsLookupThreadByThreadId", (tid, out) => {
    mem.w64(out, 0xffffb8000000a000n | (BigInt(tid) & 0xfffn)); // synthetic ETHREAD
    return STATUS_SUCCESS;
  });
  k.define("PsGetThreadId", (thread) => mem.u64(thread + t.offsetOf("_ETHREAD", "Cid") + 8n));
  k.define("PsGetThreadProcessId", (thread, outProc) => {
    const cidOff = t.offsetOf("_ETHREAD", "Cid");
    const pid = mem.u64(thread + cidOff);
    if (outProc) mem.w64(outProc, currentEprocByPid(pid) ?? 0n);
    return pid;
  });
  function currentEprocByPid(pid) { return kernel.findEprocessByPid(BigInt.asUintN(64, BigInt(pid))); }
  k.define("PsSetCreateProcessNotifyRoutineEx", (cb, remove) => {
    const arr = kernel.notifyRoutines.process;
    const idx = arr.indexOf(ptrSizeMask(cb));
    if (remove) { if (idx >= 0) arr.splice(idx, 1); }
    else arr.push(ptrSizeMask(cb));
    return STATUS_SUCCESS;
  });
  k.define("PsSetCreateProcessNotifyRoutineEx2", (...a) => impls.PsSetCreateProcessNotifyRoutineEx(...a));

  const tokenOffSafe = () => { try { return t.offsetOf("_EPROCESS", "Token"); } catch { return 0x4b8n; } };
  k.define("PsReferencePrimaryToken", (eproc) => mem.u64(eproc + BigInt(tokenOffSafe())) & ~0xfn);
  k.define("PsDereferencePrimaryToken", () => undefined);
  k.define("SeQueryInformationToken", (_token, infoClass, outInfo) => {
    const blob = k.alloc(0x30);
    mem.write(blob, Uint8Array.from({ length: 0x30 }, (_, i) => (i * 7 + 0x41) & 0xff)); // pattern token
    mem.w64(outInfo, blob);
    return STATUS_SUCCESS;
  });
  k.define("SeAccessCheck", () => 1n);
  k.define("SeSinglePrivilegeCheck", () => 1n);
  k.define("SeLocateProcessImageName", (eproc, outUs) => {
    const buf = k.alloc(0x80);
    mem.writeUtf16(buf, "kfsim.exe");
    mem.w16(outUs, 18);
    mem.w16(outUs + 2n, 20);
    mem.w64(outUs + 8n, buf);
    return STATUS_SUCCESS;
  });
  k.define("RtlAdjustPrivilege", (_priv, enable, thread, prevOut) => {
    void enable;
    if (prevOut) mem.w8(prevOut, 0);
    return STATUS_SUCCESS;
  });

  k.define("ObReferenceObjectByHandle", (handle, access, type, mode, out, handleInfoOut) => {
    void access; void type; void mode;
    const h = ptrSizeMask(handle);
    if (!kernel.handles.has(h)) return 0xc000000bn; // STATUS_INVALID_HANDLE
    mem.w64(out, h); // modeled handles resolve to their own id as object
    if (handleInfoOut) mem.w32(handleInfoOut, 0);
    return STATUS_SUCCESS;
  });
  k.define("ObOpenObjectByName", (objAttr, _type, _mode, _access, _attrs, _ctx, handleOut) => {
    const p = pathFromObjAttr(objAttr);
    const norm = "\\" + p.replace(/^\\*/, "");
    const hit = [...kernel.registry.keys()].some((k2) => k2.toLowerCase() === norm.toLowerCase());
    if (!hit) return STATUS_OBJECT_NAME_NOT_FOUND;
    mem.w64(handleOut, regHandle(norm));
    return STATUS_SUCCESS;
  });
  k.define("ObQueryNameString", (obj, infoBuf, len, resultLen) => {
    // OBJECT_NAME_INFORMATION: UNICODE_STRING + buffer
    const name = "kfsim-object";
    if (len >= 0x20) {
      mem.writeUtf16(mem.u64(infoBuf + 8n) || infoBuf + 0x10n, name);
      mem.w16(infoBuf, name.length * 2);
      mem.w16(infoBuf + 2n, (name.length + 1) * 2);
      mem.w64(infoBuf + 8n, infoBuf + 0x10n);
      mem.writeUtf16(infoBuf + 0x10n, name);
    }
    mem.w32(resultLen, 0x10 + name.length * 2);
    return STATUS_SUCCESS;
  });

  // --------------------------------------------- ZwQuerySystemInformation
  //
  // MODELED LAYOUT (documented divergence): SystemHandleInformation (class
  // 16) and SystemExtendedHandleInformation (class 64) both return an
  // EX-style entry table:
  //   +0x00 ULONG  UniqueProcessId   (owner)
  //   +0x04 ULONG  HandleAttributes
  //   +0x08 ULONG  GrantedAccess
  //   +0x0c USHORT HandleValue
  //   +0x0e USHORT CreatorBackTraceIndex
  //   +0x10 PVOID  Object            (target EPROCESS)
  // entry size 24; buffer = ULONG NumberOfHandles + pad + entries.
  // This is EDR cross-reference source #3: handles other processes hold
  // against a DKOM-hidden target still enumerate here.
  const SYS_HANDLE_ENTRY_SIZE = 24n;
  const sysHandleInfoImpl = (cls, sysInfo, len, retLen) => {
    const c = Number(BigInt.asUintN(32, BigInt(cls)));
    if (c !== 16 && c !== 64) {
      kernel.dbgLog.push(
        `[winapi] ZwQuerySystemInformation(class ${c}) unmodeled -> STATUS_INVALID_INFO_CLASS`);
      return 0xc0000003n;
    }
    const entries = kernel.objectHandles ?? [];
    const needed = 8n + BigInt(entries.length || 1) * SYS_HANDLE_ENTRY_SIZE;
    if (retLen) mem.w64(retLen, needed);
    if (!sysInfo || BigInt(len) < needed) return 0xc0000004n; // INFO_LENGTH_MISMATCH
    const pidOff = (() => {
      try { return kernel.tables.offsetOf("_EPROCESS", "UniqueProcessId"); } catch { return null; }
    })();
    const pidOf = (eproc) =>
      pidOff === null ? 0 : Number(mem.u32(eproc + pidOff));
    mem.w32(sysInfo, entries.length);
    mem.w32(sysInfo + 4n, 0);
    let off2 = 8n;
    for (const h of entries) {
      mem.w32(sysInfo + off2, pidOf(h.ownerEproc));
      mem.w32(sysInfo + off2 + 4n, 0);                   // HandleAttributes
      mem.w32(sysInfo + off2 + 8n, h.grantedAccess >>> 0);
      mem.w16(sysInfo + off2 + 12n, Number(h.handle & 0xffffn));
      mem.w16(sysInfo + off2 + 14n, 0);                  // CreatorBackTraceIndex
      mem.w64(sysInfo + off2 + 16n, h.targetEproc);      // Object
      off2 += SYS_HANDLE_ENTRY_SIZE;
    }
    kernel.dbgLog.push(`[winapi] SystemHandleInformation: ${entries.length} handle(s) enumerated`);
    return STATUS_SUCCESS;
  };
  k.define("ZwQuerySystemInformation", sysHandleInfoImpl);
  k.define("NtQuerySystemInformation", (...a) => impls.ZwQuerySystemInformation(...a));

  // ------------------------------------------------------------------- Mm

  k.define("MmIsAddressValid", (va) => {
    // honest per-page backing check: drivers use this to guard probe reads
    // (pool carving, pointer validation) before dereferencing
    try { return mem.canRead(BigInt(va), 1) ? 1n : 0n; } catch { return 0n; }
  });
  k.define("MmAllocateContiguousMemory", (size) => k.alloc(Number(size)));
  k.define("MmFreeContiguousMemory", () => undefined);
  k.define("MmGetPhysicalMemoryRanges", () => k.alloc(0x100)); // opaque ranges blob
  k.define("MmMapLockedPagesSpecifyCache", (mdl, _mode, _cache, _base, _bugcheck, _priority) => {
    const va = k.alloc(0x1000);
    const sysVa = mem.u64(mdl + 0x08);
    if (sysVa) mem.write(va, mem.read(sysVa, 0x1000));
    return va;
  });
  k.define("MmUnmapLockedPages", () => undefined);
  k.define("MmBuildMdlForNonPagedPool", () => undefined);
  k.define("MmGetMdlVirtualAddress", (mdl) => mem.u64(mdl + 0x08));
  k.define("MmCopyVirtualMemory", (srcProc, src, dstProc, dst, size, mode, outLen) => {
    void srcProc; void dstProc; void mode;
    mem.write(dst, mem.read(src, Number(size)));
    if (outLen) mem.w64(outLen, BigInt(size));
    return STATUS_SUCCESS;
  });
  k.define("ProbeForRead", () => undefined);
  k.define("ProbeForWrite", () => undefined);
  k.define("MmSecureSystemMemory", (addr, len) => { void addr; void len; return 1n; });
  k.define("MmUnsecureSystemMemory", () => undefined);
  k.define("MmPageEntireDriver", () => undefined);
  k.define("MmResetDriverPaging", () => undefined);
  k.define("MmHighestUserAddress", () => 0x7ffffffeffffn);

  // --------------------------------------------------- Po / WMI / Etw / Fs

  k.define("PoRegisterSystemState", () => k.alloc(0x20));
  k.define("PoUnregisterSystemState", () => undefined);
  k.define("PoSetPowerState", () => 0n);
  k.define("PoStartNextPowerIrp", () => undefined);
  k.define("PoRequestPowerIrp", (devObj, minor, powerState, cb, ctx, irpOut) => {
    void devObj; void minor; void powerState; void cb; void ctx;
    if (irpOut) mem.w64(irpOut, 0n);
    return STATUS_SUCCESS;
  });
  k.define("PoSetSystemPowerState", () => STATUS_SUCCESS);

  k.define("IoWMIRegistrationControl", () => STATUS_SUCCESS);
  k.define("IoWMIQueryAllData", () => 0xc0000001n);

  // --------------------------------------------------------------- ETW capture
  //
  // Providers register with EtwRegister(GUID, ...) and emit through
  // EtwWrite/EtwWriteTransfer. We record registrations and decode
  // EVENT_DESCRIPTOR {Level u16, Channel u8, Opcode u8, Task u16, Keyword u64}
  // plus EVENT_DATA_DESCRIPTOR arrays {Ptr u64, Size u32} so the trace shows
  // what a driver tried to tell its (missing) listeners.

  const guidAt = (va) => {
    const hex = (x) => "0x" + BigInt.asUintN(64, BigInt(x ?? 0)).toString(16);
    try {
      if (!va) return "NULL";
      const b = mem.read(va, 16);
      const u32 = (o) => ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0).toString(16).padStart(8, "0");
      const u16 = (o) => (b[o] | (b[o + 1] << 8)).toString(16).padStart(4, "0");
      const d4 = [...b.slice(8, 16)].map((x) => x.toString(16).padStart(2, "0")).join("");
      return `{${u32(0)}-${u16(4)}-${u16(6)}-${d4.slice(0, 4)}-${d4.slice(4)}}`;
    } catch { return hex(va); }
  };
  let nextEtwHandle = 0xe7000001n;

  k.define("EtwRegister", (guid, cb, ctx, handleOut) => {
    void cb; void ctx;
    const h = nextEtwHandle++;
    if (handleOut) mem.w64(handleOut, h);
    kernel.etwLog.push({ kind: "register", handle: ptrSizeMask(h), guid: guidAt(guid) });
    kernel.emitTrace({ kind: "etw", op: "register", summary: `provider ${guidAt(guid)} -> handle 0x${ptrSizeMask(h).toString(16)}` });
    return STATUS_SUCCESS;
  });
  k.define("EtwUnregister", (h) => {
    kernel.etwLog.push({ kind: "unregister", handle: ptrSizeMask(h) });
    kernel.emitTrace({ kind: "etw", op: "unregister", summary: `handle 0x${ptrSizeMask(h).toString(16)}` });
    return STATUS_SUCCESS;
  });

  const describeEtwPayload = (dataCount, dataArray) => {
    try {
      if (!dataArray || !dataCount) return "";
      const n = Math.min(Number(dataCount), 4);
      const chunks = [];
      for (let i = 0; i < n; i++) {
        const d = dataArray + BigInt(i * 16);
        const ptr = mem.u64(d);
        const size = Number(BigInt.asUintN(32, mem.u64(d + 8n)));
        if (!ptr || !size || size > 256) continue;
        const bytes = [...mem.read(ptr, Math.min(size, 32))].map((x) => x.toString(16).padStart(2, "0")).join("");
        chunks.push(`[${size}B] ${bytes}`);
      }
      return chunks.join(" ");
    } catch { return ""; }
  };

  k.define("EtwWrite", (regHandle, desc, filterData, dataCount, dataArray) => {
    void filterData;
    let level = 0, opcode = 0, keyword = 0n;
    try {
      if (desc) {
        level = mem.u16(desc);          // Level @+0
        opcode = mem.u8(desc + 3n);     // Opcode @+3
        keyword = mem.u64(desc + 8n);   // Keyword @+8
      }
    } catch { /* bad descriptor — still record */ }
    const payload = describeEtwPayload(dataCount, dataArray);
    const rec = {
      kind: "write",
      handle: ptrSizeMask(regHandle),
      level,
      opcode,
      keyword: keyword.toString(16),
      payload,
    };
    kernel.etwLog.push(rec);
    kernel.emitTrace({
      kind: "etw",
      op: "write",
      summary: `handle=0x${ptrSizeMask(regHandle).toString(16)} level=${level} opcode=${opcode} keyword=0x${keyword.toString(16)}${payload ? " " + payload : ""}`,
    });
    return STATUS_SUCCESS;
  });
  k.define("EtwWriteTransfer", (regHandle, desc, activity, relatedActivity, dataCount, dataArray) => {
    void activity; void relatedActivity;
    // same descriptor layout as EtwWrite; transfer events carry ActivityIds
    return impls.EtwWrite(regHandle, desc, 0n, dataCount, dataArray);
  });
  k.define("EtwActivityIdControl", (_cur, nextOut) => {
    if (nextOut) mem.w64(nextOut, 0x1122334455667788n);
    return STATUS_SUCCESS;
  });

  k.define("FsRtlIsNameInExpression", (exprUs, nameUs, ignoreCase, upcaseTbl) => {
    void upcaseTbl;
    const expr = usRead(mem, exprUs).str;
    const name = usRead(mem, nameUs).str;
    const up = (s) => (ignoreCase ? s.toUpperCase() : s);
    // glob: * matches any run, ? matches one char
    const rx = new RegExp("^" + up(expr).split("*").map((seg) =>
      seg.split("?").map((q) => q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".")
    ).join(".*") + "$");
    return rx.test(up(name)) ? 1n : 0n;
  });
  k.define("FsRtlNotifyVolumeEvent", () => STATUS_SUCCESS);
  k.define("FsRtlCheckLockForReadAccess", () => 1n);
  k.define("FsRtlAreThereCurrentFileLocks", () => 0n);
}
