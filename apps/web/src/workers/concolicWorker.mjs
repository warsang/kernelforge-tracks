/**
 * concolicWorker.mjs — Web Worker for concolic solving of a single IOCTL
 * Similar to fuzzWorker but runs concolicCampaign.
 */

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel, createDriverObject, initDriverObjectName, createDeviceObject, sendIrp, mapPe, parsePe } from "@kernelforge/ntsim/src/index.mjs";
import { concolicCampaign } from "@kernelforge/ntsim-analyzer/src/symbolic/concolic.mjs";

let tablesCache = null;
async function ensureTables(tablesData){
  if(tablesCache) return tablesCache;
  if(tablesData){ tablesCache = new StructTables(tablesData); return tablesCache; }
  const res = await fetch("/tables/windows-10/22h2/_EPROCESS.json");
  if(!res.ok) throw new Error("tables fetch failed");
  tablesCache = await StructTables.loadDir("/tables/windows-10/22h2", ["_EPROCESS","_ETHREAD","_KLDR_DATA_TABLE_ENTRY"]);
  return tablesCache;
}

self.onmessage = async (e)=>{
  const {type,id,imageBytes,ctlCode,base,size,opts,tablesData}=e.data;
  if(type!=="run") return;
  try{
    const tables=await ensureTables(tablesData);
    const kernel=new NtKernel({tables});
    kernel.bootstrap();
    const drvRec=createDriverObject(kernel,"worker.sys");
    const mapped=mapPe(imageBytes, kernel.mem, BigInt(base), (q)=>kernel.resolveImportProvisioned(q));
    initDriverObjectName(kernel, drvRec, "worker.sys", mapped.base, mapped.imageSize);
    drvRec.image={base:mapped.base, bytes:imageBytes};
    kernel.materializeModuleRange(mapped.base, mapped.imageSize,{fill:0});
    const pe=parsePe(imageBytes);
    kernel.callFunctionSeh(mapped.base+BigInt(pe.entryRva),[drvRec.va,0n], drvRec.image);
    const device=drvRec.deviceList[0] ?? createDeviceObject(kernel, drvRec,{});
    const res=await concolicCampaign(kernel, device, ctlCode, {
      sendIrp:(k,d,s)=>sendIrp(k,d,s),
      imageBase:BigInt(base), imageSize:BigInt(size),
      maxSymBytes: opts.maxSymBytes??32, solverTimeoutMs: opts.solverTimeoutMs??300, maxQueries: opts.maxQueries??4,
      onProgress: (evt)=> self.postMessage({type:"progress", id, evt})
    });
    self.postMessage({type:"done", id, result:{
      ctlCode,
      corpus: res.corpus.map(c=>({hex:[...c.buf].map(b=>b.toString(16).padStart(2,"0")).join("")})),
      queriesDone: res.queriesDone
    }});
  }catch(err){
    self.postMessage({type:"error", id, error: err.message+"\n"+err.stack});
  }
};
