/**
 * analyzer.js — run-any-.sys analysis tab.
 *
 * Upload a PE32+ driver, map it into the emulated kernel (every import
 * resolves — modeled or provisioned-stub), execute DriverEntry through the
 * SEH-aware path, drain DPC/work/APC queues, then drive MajorFunction with
 * scripted IOCTLs. Everything client-side; nothing leaves the tab.
 */

import { loadTables } from "./tables.js";
import { analyzeDriver } from "@kernelforge/ntsim-analyzer/src/index.mjs";
import {
  NtKernel,
  mapPe,
  parsePe,
  createDriverObject,
  initDriverObjectName,
  createDeviceObject,
  sendIrp,
  callDriverUnload,
} from "@kernelforge/ntsim/src/index.mjs";

const DRIVER_BASE = 0xfffff80300000000n;

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) e.setAttribute(k, String(v));
  }
  for (const c of children) e.append(c);
  return e;
}

function kv(label, value, cls) {
  return el("div", { class: `kv ${cls ?? ""}` },
    el("span", { class: "k" }, label),
    el("span", { class: "v" }, String(value)),
  );
}

const NTSTATUS_NAME = (s) => {
  const known = {
    "0x00000000": "STATUS_SUCCESS",
    "0xc0000001": "STATUS_NOT_IMPLEMENTED",
    "0xc000000b": "STATUS_INVALID_PARAMETER",
    "0xc0000005": "STATUS_ACCESS_VIOLATION",
    "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
  };
  return known[s] ?? "";
};

export function renderAnalyzer(main) {
  main.innerHTML = "";

  let session = null; // {kernel, drvRec, image, report}

  // ------------------------------------------------------------- layout
  const fileInput = el("input", { type: "file", accept: ".sys,.dll" });
  const engineSel = el("select", {},
    el("option", { value: "js" }, "JsInterpreter (deterministic)"),
    el("option", { value: "hybrid" }, "Hybrid (JS + Unicorn fallback)"),
    el("option", { value: "unicorn" }, "Unicorn (WASM-only)"),
  );
  const nameInput = el("input", { type: "text", placeholder: "uploaded.sys", value: "uploaded.sys", title: "Driver name — seeds DriverName and the Services\\<key> registry path. Auto-filled from the uploaded file." });
  fileInput.addEventListener("change", () => {
    const f = fileInput.files?.[0];
    if (f) nameInput.value = f.name;
  });

  const loadBtn = el("button", { class: "primary" }, "Load & run DriverEntry");

  const ioctlCode = el("input", { type: "text", placeholder: "0x222000", value: "0x222000" });
  const ioctlIn = el("input", { type: "text", placeholder: "input hex (e.g. deadbeef)" });
  const ioctlOut = el("input", { type: "number", value: "64", min: "0", max: "4096" });
  const ioctlBtn = el("button", {}, "Send IOCTL");
  ioctlBtn.disabled = true;

  const autoIrpBtn = el("button", { title: "Send CREATE/CLOSE + every harvested CTL_CODE with synthetic buffers" }, "Auto-drive IRPs");
  autoIrpBtn.disabled = true;

  const unloadBtn = el("button", {}, "Call DriverUnload");
  unloadBtn.disabled = true;

  const out = el("div", { class: "analyzer-out" });
  const log = (msg, cls) => out.append(el("div", { class: `line ${cls ?? ""}` }, msg));

  const card = el("div", { class: "card" },
    el("h1", null, "Driver Analyzer"),
    el("p", { class: "dim" },
      "Upload any x64 .sys — it is manual-mapped into the emulated kernel, every import resolves " +
      "(modeled APIs behave; unknown ones become traced stubs), DriverEntry runs under table-SEH, " +
      "deferred work drains, and you can drive MajorFunction with scripted IOCTLs."),
    el("div", { class: "analyzer-controls" },
      fileInput, nameInput, engineSel, loadBtn),
    el("div", { class: "analyzer-controls" },
      el("span", { class: "dim" }, "IOCTL:"),
      ioctlCode, ioctlIn, el("span", { class: "dim" }, "out bytes:"), ioctlOut,
      ioctlBtn, autoIrpBtn, unloadBtn),
    out,
  );
  main.append(card);

  // ------------------------------------------------------------ helpers

  async function carvedStateOrNull() {
    try {
      const res = await fetch("/dumps/ntsim-state.json");
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  function renderReport(report) {
    const wrap = el("div", { class: "report" });

    const loadSec = el("div", { class: "section" },
      el("h3", null, "Load"),
      kv("base", report.load.base),
      kv("image size", `0x${report.load.imageSize.toString(16)}`),
      kv("relocations", report.load.relocated),
      kv("imports resolved", report.load.imports.length),
      kv("unmodeled (stubbed)", report.load.unmodeledExports.length,
        report.load.unmodeledExports.length ? "warn" : ""),
    );
    if (report.load.unmodeledExports.length) {
      loadSec.append(el("div", { class: "mono dim" },
        report.load.unmodeledExports.slice(0, 24).join(", ") +
        (report.load.unmodeledExports.length > 24 ? " …" : "")));
    }

    const entrySec = el("div", { class: "section" },
      el("h3", null, "DriverEntry"),
      kv("status", report.entry.status, report.entry.status === "ok" ? "ok" : "err"),
    );
    if (report.entry.retval !== undefined) {
      entrySec.append(kv("retval", report.entry.retval));
    }
    if (report.entry.sehHandled) {
      entrySec.append(kv("SEH dispatch", report.entry.sehDetail, "warn"));
    }
    if (report.entry.error) entrySec.append(kv("error", report.entry.error, "err"));

    if (report.deferred) {
      wrap.append(el("div", { class: "section" },
        el("h3", null, "Deferred"),
        kv("DPCs drained", report.deferred.dpcs),
        kv("work items", report.deferred.workItems),
        kv("APCs", report.deferred.apcs),
      ));
    }
    if (report.irqlViolations.length) {
      const sec = el("div", { class: "section" }, el("h3", null, "IRQL violations"));
      for (const v of report.irqlViolations.slice(0, 12)) {
        sec.append(kv(`${v.name}`, `called at IRQL ${v.irql}`, "err"));
      }
      wrap.append(sec);
    }
    if (report.exceptions.length) {
      const sec = el("div", { class: "section" }, el("h3", null, "Exceptions"));
      for (const e of report.exceptions.slice(0, 12)) {
        sec.append(kv(e.faultRip, `${e.handled ? "handled" : "UNHANDLED"} — ${e.detail}`,
          e.handled ? "warn" : "err"));
      }
      wrap.append(sec);
    }

    wrap.append(loadSec, entrySec);

    const trace = report.apiTraceSummary;
    if (trace) {
      const sec = el("div", { class: "section" },
        el("h3", null, `API trace (${trace.totalCalls} calls, ${trace.distinct} distinct)`));
      const names = Object.keys(trace.byName).slice(0, 32);
      sec.append(el("div", { class: "mono dim" }, names.join(", ") +
        (trace.distinct > names.length ? ` … +${trace.distinct - names.length}` : "")));
      wrap.append(sec);
    }

    // chronological call trace (ktrace-style)
    if (report.traceText) {
      const sec = el("div", { class: "section" },
        el("h3", null, `Call trace (${(report.trace ?? []).length} events)`));
      const pre = el("pre", { class: "mono trace-log" });
      pre.textContent = report.traceText;
      sec.append(pre);
      const dl = el("button", { class: "btn btn-sm", type: "button" }, "Download trace");
      dl.addEventListener("click", () => {
        const blob = new Blob([report.traceText], { type: "text/plain" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `${report.load?.driverName ?? "driver"}.trace.txt`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
      const cp = el("button", { class: "btn btn-sm", type: "button" }, "Copy");
      cp.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(report.traceText); } catch { /* denied */ }
      });
      sec.append(el("div", { class: "row gap" }, dl, cp));
      wrap.append(sec);
    }

    if (report.dbgLog.length) {
      const sec = el("div", { class: "section" }, el("h3", null, "DbgPrint"));
      for (const line of report.dbgLog.slice(0, 64)) {
        sec.append(el("div", { class: "mono" }, line));
      }
      wrap.append(sec);
    }
    out.prepend(wrap);
  }

  function renderIoctl(io) {
    const sec = el("div", { class: "section" });
    const statusHex = io.ntstatus !== undefined
      ? `0x${BigInt.asUintN(32, io.ntstatus).toString(16).padStart(8, "0")}`
      : "—";
    sec.append(
      el("h3", null, `IOCTL ${io.majorName ?? "DEVICE_CONTROL"}`),
      kv("ntstatus", `${statusHex} ${NTSTATUS_NAME(statusHex)}`,
        io.ntstatus === 0n ? "ok" : "warn"),
      kv("information", io.information?.toString() ?? "—"),
      kv("steps", io.steps ?? "—"),
    );
    if (io.outputHex) sec.append(el("div", { class: "mono" }, io.outputHex.slice(0, 256)));
    if (io.error) sec.append(kv("error", io.error, "err"));
    out.append(sec);
  }

  function liveLine(msg, cls) {
    out.append(el("div", { class: `line ${cls ?? ""}` }, msg));
  }

  // -------------------------------------------------------------- actions

  loadBtn.addEventListener("click", async () => {
    const file = fileInput.files?.[0];
    if (!file) {
      log("pick a .sys file first", "err");
      return;
    }
    loadBtn.disabled = true;
    loadBtn.textContent = "analyzing…";
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const opts = {
        name: nameInput.value || "uploaded.sys",
        backendName: engineSel.value,
        tables: await loadTables(),
        carvedState: await carvedStateOrNull(),
        runUnload: false,
      };
      if (engineSel.value === "hybrid") {
        opts.makeBackend = async () => {
          const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
          const b = await HybridCpuBackend.create(null);
          return b;
        };
      } else if (engineSel.value === "unicorn") {
        opts.makeBackend = async () => {
          // pure Unicorn — high ISA coverage, WASM bundle lazy-loaded only here
          let mod;
          try {
            mod = await import("@kernelforge/ntsim-unicorn");
          } catch (e) {
            try { mod = await import("@kernelforge/ntsim-unicorn/src/backend.mjs"); } catch (_) { throw e; }
          }
          const createUnicornBackend =
            mod.createUnicornBackend ??
            mod.default?.createUnicornBackend ??
            mod.default ??
            mod.create;
          if (typeof createUnicornBackend !== "function") {
            throw new Error(`ntsim-unicorn: createUnicornBackend factory not found (exports: ${Object.keys(mod).join(", ")})`);
          }
          return await createUnicornBackend(null);
        };
      }
      const report = await analyzeDriver(bytes, opts);
      renderReport(report);
      log(`loaded ${file.name} (${bytes.length} bytes, engine=${opts.backendName})`, "ok");
      ioctlBtn.disabled = false;
      autoIrpBtn.disabled = false;
      unloadBtn.disabled = false;

      if (report.harvestedIoctls?.length) {
        const sec = el("div", { class: "section" },
          el("h3", null, `Harvested CTL_CODEs (${report.harvestedIoctls.length})`));
        sec.append(el("div", { class: "mono dim" },
          report.harvestedIoctls.map((h) => h.hex).join(", ")));
        out.prepend(sec);
      }

      // analyzeDriver returns the live kernel session for interactive IOCTLs
      session = report.__session;
    } catch (e) {
      log(`load failed: ${e.message}`, "err");
    } finally {
      loadBtn.disabled = false;
      loadBtn.textContent = "Load & run DriverEntry";
    }
  });

  ioctlBtn.addEventListener("click", async () => {
    if (!session) return;
    ioctlBtn.disabled = true;
    try {
      const r = await sendIrp(session.kernel, session.device, {
        major: 0x0e, // IRP_MJ_DEVICE_CONTROL
        ioctl: ioctlCode.value.replace(/^0x/i, ""),
        inputHex: ioctlIn.value,
        outputLen: Number(ioctlOut.value) || 0,
      });
      renderIoctl({
        ...r,
        error: r.error ? String(r.error.message ?? r.error) : undefined,
      });
      for (const line of session.kernel.dbgLog.splice(0)) liveLine(line, "mono");
      for (const ex of session.kernel.exceptionTrace.splice(0)) {
        liveLine(`[seh] ${ex.faultRip}: ${ex.handled ? "handled" : "UNHANDLED"} — ${ex.detail}`,
          ex.handled ? "warn" : "err");
      }
      for (const v of session.kernel.irqlViolations.splice(0)) {
        liveLine(`[irql] ${v.name} at IRQL ${v.irql}`, "err");
      }
    } finally {
      ioctlBtn.disabled = false;
    }
  });

  autoIrpBtn.addEventListener("click", async () => {
    if (!session) return;
    autoIrpBtn.disabled = true;
    try {
      const { harvestCtlCodes, autoDriveIrps } =
        await import("@kernelforge/ntsim-analyzer/src/autoirp.mjs");
      const harvested = harvestCtlCodes(session.image.bytes, parsePe(session.image.bytes), {});
      liveLine(`auto-drive: MJ_CREATE + ${harvested.length} harvested code(s) + MJ_CLOSE`, "dim");
      const results = await autoDriveIrps(session.kernel, session.device, {
        sendIrp,
        harvested,
        maxCodes: 32,
      });
      for (const r of results) {
        renderIoctl({ ...r, majorName: r.majorName === "DEVICE_CONTROL" ? `DEVICE_CONTROL ${(r.ioctl ?? 0n)?.toString(16) ?? ""}` : r.majorName });
        for (const line of session.kernel.dbgLog.splice(0)) liveLine(line, "mono");
        for (const ex of session.kernel.exceptionTrace.splice(0)) {
          liveLine(`[seh] ${ex.faultRip}: ${ex.handled ? "handled" : "UNHANDLED"} — ${ex.detail}`,
            ex.handled ? "warn" : "err");
        }
        for (const v of session.kernel.irqlViolations.splice(0)) {
          liveLine(`[irql] ${v.name} at IRQL ${v.irql}`, "err");
        }
      }
      if (session.kernel.bugcheck || session.kernel.crash) {
        liveLine(`bugcheck during auto-drive: ${JSON.stringify(session.kernel.bugcheck ?? session.kernel.crash)}`, "err");
        unloadBtn.disabled = true;
      }
    } finally {
      autoIrpBtn.disabled = false;
    }
  });

  unloadBtn.addEventListener("click", async () => {
    if (!session) return;
    unloadBtn.disabled = true;
    try {
      const r = await callDriverUnload(session.kernel, session.drvRec);
      liveLine(`unload: ${r.status}${r.retval !== undefined ? ` (0x${r.retval.toString(16)})` : ""}`);
    } finally {
      unloadBtn.disabled = false;
    }
  });
}
