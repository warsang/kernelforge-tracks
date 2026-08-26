/**
 * bugWorker.mjs — Web Worker for Find Bugs (taint + directed fuzz)
 * Runs findBugsCampaign for a single IOCTL in a worker.
 */

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel, createDriverObject, initDriverObjectName, createDeviceObject, sendIrp, mapPe, parsePe } from "@kernelforge/ntsim/src/index.mjs";
import { findBugsCampaign } from "@kernelforge/ntsim-analyzer/src/bug/engine.mjs";

let tablesCache=null;
async function ensureTables(d){
  if(tablesCache) return tablesCache;
  if(d){ tablesCache=new StructTables(d); return tablesCache; }
  tablesCache=await StructTables.loadDir("/tables/windows-10/22h2", ["_EPROCESS","_ETHREAD","_KLDR_DATA_TABLE_ENTRY"]);
  return tablesCache;
}

self.onmessage=async(e)=>{
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
    const res=await findBugsCampaign(kernel, device, ctlCode, {
      sendIrp:(k,d,s)=>sendIrp(k,d,s),
      imageBase:BigInt(base), imageSize:BigInt(size),
      iterations: opts.iterations??64, corpusCap: opts.corpusCap??16,
      driverHash: opts.driverHash,
      onProgress: (evt)=> self.postMessage({type:"progress", id, evt})
    });
    self.postMessage({type:"done", id, result:{
      ctlCode,
      bugs: res.bugDB.all(),
      corpus: res.corpus.length
    }});
  }catch(err){
    self.postMessage({type:"error", id, error: err.message+"\n"+err.stack});
  }
};
