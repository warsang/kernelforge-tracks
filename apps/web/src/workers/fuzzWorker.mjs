/**
 * fuzzWorker.mjs — Web Worker for coverage-guided fuzzing of a single IOCTL
 * Runs fuzzIoctl in a separate thread to keep UI responsive.
 * Message protocol:
 *   {type:"run", id, imageBytes, tablesData, ctlCode, base, size, opts}
 * Response:
 *   {type:"done", id, corpus, globalSeen, iterations}
 *   {type:"progress", id, phase, iter, coverage}
 *   {type:"error", id, error}
 */

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel, createDriverObject, initDriverObjectName, createDeviceObject, sendIrp, mapPe, parsePe } from "@kernelforge/ntsim/src/index.mjs";
import { fuzzIoctl } from "@kernelforge/ntsim-analyzer/src/fuzz.mjs";

let tablesCache = null;

async function ensureTables(tablesData) {
  if (tablesCache) return tablesCache;
  if (tablesData) {
    // tablesData is already loaded StructTables JSON, reconstruct
    tablesCache = new StructTables(tablesData);
    return tablesCache;
  }
  // fallback: fetch from /tables (worker has fetch)
  const res = await fetch("/tables/windows-10/22h2/_EPROCESS.json");
  if (!res.ok) throw new Error("tables fetch failed");
  // For simplicity, load minimal tables via import
  const dir = "/tables/windows-10/22h2";
  tablesCache = await StructTables.loadDir(dir, ["_EPROCESS","_ETHREAD","_KLDR_DATA_TABLE_ENTRY"]);
  return tablesCache;
}

self.onmessage = async (e) => {
  const { type, id, imageBytes, ctlCode, base, size, opts, tablesData } = e.data;
  if (type !== "run") return;
  try {
    const tables = await ensureTables(tablesData);
    const kernel = new NtKernel({ tables });
    kernel.bootstrap();
    const drvRec = createDriverObject(kernel, "worker.sys");
    const mapped = mapPe(imageBytes, kernel.mem, BigInt(base), (q)=> kernel.resolveImportProvisioned(q));
    initDriverObjectName(kernel, drvRec, "worker.sys", mapped.base, mapped.imageSize);
    drvRec.image = { base: mapped.base, bytes: imageBytes };
    kernel.materializeModuleRange(mapped.base, mapped.imageSize, { fill: 0 });
    const pe = parsePe(imageBytes);
    const entry = mapped.base + BigInt(pe.entryRva);
    kernel.callFunctionSeh(entry, [drvRec.va, 0n], drvRec.image);
    const device = drvRec.deviceList[0] ?? createDeviceObject(kernel, drvRec, {});
    const result = await fuzzIoctl(kernel, device, ctlCode, {
      sendIrp: (k,d,spec)=> sendIrp(k,d,spec),
      imageBase: BigInt(base),
      imageSize: BigInt(size),
      iterations: opts.iterations ?? 128,
      corpusCap: opts.corpusCap ?? 16,
      onProgress: (evt)=>{
        self.postMessage({type:"progress", id, evt});
      }
    });
    self.postMessage({type:"done", id, result: {
      ctlCode,
      corpus: result.corpus.map(c=> ({ hex: [...c.buf].map(b=>b.toString(16).padStart(2,"0")).join(""), coverage: {blocks: c.coverage.blocks.size}})),
      globalSeen: result.globalSeen.size,
      best: result.best ? { hex: [...result.best.buf].map(b=>b.toString(16).padStart(2,"0")).join(""), nt: result.best.res?.ntstatus?.toString(16)} : null
    }});
  } catch (err) {
    self.postMessage({type:"error", id, error: err.message + "\n" + err.stack});
  }
};
