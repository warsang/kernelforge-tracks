/**
 * linux-kernel.mjs — Lightweight Linux kernel emulation for .ko analysis.
 * Design mirrors NtKernel but linux-flavored.
 * Reuses SparseMemory + JsInterpreter + tracer patterns.
 */
import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { JsInterpreter, M64 } from "@kernelforge/ntsim/src/cpu.mjs";
import { installLinuxApi } from "./linux-api.mjs";

const DEFAULT_BASES = {
  thunk: 0xffffffffa0000000n,
  thunkAlias: 0x004100000n,
  slub: 0xffff888000000000n,
  module: 0xffffffffc0000000n,
  stack: 0xffffffffa1000000n,
};
const THUNK_SIZE = 0x100000n;
const STACK_SIZE = 0x4000n;
const LOW_RET_MARKER = 0x0badf00dn; // <2^31 for unicorn hook_add

const POOL_MAGIC = 0x4b46454c52505352n;
const SLUB_GUARD_BYTE = 0xa5;
const SLUB_GUARD_LEN = 16;

export class LinuxKernel {
  constructor(opts={}){
    const raw = opts.cpu?.mem ?? new SparseMemory();
    this.rawMem = raw;
    this.cpu = opts.cpu ?? null;
    this.paging = false;
    this.mem = raw;
    if(!this.cpu) this.cpu = new JsInterpreter(this.mem);
    else this.cpu.mem = raw; // ensure same
    if(this.cpu.regs && !("rip" in this.cpu.regs)){
      const ref=this.cpu;
      Object.defineProperty(ref.regs,"rip",{
        get(){ return ref.rip ?? 0n; },
        set(v){ ref.rip = BigInt.asUintN(64, BigInt(v)); },
        configurable:true,
      });
    }
    const B=opts.bases??{};
    this.bases={
      thunk: B.thunk ?? DEFAULT_BASES.thunk,
      thunkAlias: B.thunkAlias ?? DEFAULT_BASES.thunkAlias,
      slub: B.slub ?? DEFAULT_BASES.slub,
      module: B.module ?? DEFAULT_BASES.module,
      stack: B.stack ?? DEFAULT_BASES.stack,
    };
    this.buildName = opts.buildName ?? "linux-6.6.18";
    this.apiThunks = new Map();
    this.thunkAliasMap = new Map();
    this.nextThunk = this.bases.thunk;
    this.apiImpls = new Map();
    this.apiMeta = new Map();
    this.pristineThunks = new Map();
    this.unmodeledExports = [];
    this.dbgLog = [];
    this.apiTrace = [];
    this.apiTraceLimit = 8192;
    this.exceptionTrace = [];
    this.irqlViolations = [];
    this.traceEvents = [];
    this.traceLimit = 8192;
    this.tracePhase = "run";
    this.traceSeq = 0;
    this.etwLog = [];
    this.onDebugPrint = null;
    this.bugcheck = null;
    this.crash = null;
    this.loadedDrivers = [];
    // heap / slub (alias pool for snapshot compat)
    this.heapConfig = { aslr: !!opts.heap?.aslr, seed: BigInt(opts.heap?.seed ?? 0x9e3779b1n) & 0xffffffffn };
    this._heapPrng = Number(this.heapConfig.seed & 0xffffffffn) || 0x9e3779b1;
    this.nextPool = this.bases.slub;
    this.poolAllocs = []; // slubAllocs alias
    this.slubAllocs = this.poolAllocs;
    this.nextSlub = this.nextPool; // alias
    // per-call stub fuzz policy: name -> {mode:"success"|"err", errCode:-2}
    this.stubPolicy = new Map();
    // generic ops registry (ftrace/kprobe/tracepoint/ebpf/io_uring etc)
    this.opsRegistry = [];
    this.ebpfProgs = new Map(); // fd -> {vm, progType}
    this.ebpfMaps = new Map(); // id -> Map
    this.ebpfLinks = new Map(); // link fd
    this.ioUringRings = new Map(); // fd -> ringInfo
    this.ioUringScheduler = {mode:"fifo", pending:[]};
    this.ftraceHooks = [];
    this.kprobes = [];
    this.tracepoints = [];
    // canonical kernel stack (BUG-2 fix) — materialize and set RSP/RBP
    this.stackBase = this.bases.stack;
    this.stackSize = Number(STACK_SIZE);
    this.materializeModuleRange(this.stackBase, this.stackSize, {fill:0});
    const stackTop = this.stackBase + BigInt(this.stackSize);
    const initStack = (cpu)=>{
      try{
        const cur = cpu.regs.rsp ?? 0n;
        if(cur===0n || cur < 0x1000n || cur > M64-0x1000n){
          cpu.regs.rsp = (stackTop & ~0xFn) - 8n;
          cpu.regs.rbp = 0n;
        }
      }catch{}
    };
    initStack(this.cpu);
    if(this.cpu && this.cpu.js) initStack(this.cpu.js);
    if(this.cpu && this.cpu.uc) initStack(this.cpu.uc);
    // linux specifics
    this.deviceRegistry = []; // char devices
    this.miscDevices = [];
    this.procEntries = [];
    this.netlinkHandlers = new Map();
    this.cdevs = [];
    this.currentCred = { uid: 0, gid: 0, euid: 0 }; // will be tainted sink
    this.credHistory = [];
    this.kallsyms = new Map(); // name -> va for lookups
    // pending workqueues etc
    this.pendingWork = [];
    this.msrIntercepts = new Map();
    this.tracer = { attached:false };

    // Alias for snapshot compat
    // snapshot expects kernel.tickCount etc: provide
    this.tickCount = 0n;
    this.currentIrql = 0;

    installLinuxApi(this);
    // Pre-populate kallsyms for common hooked symbols (generic, not kit-specific)
    for(const n of ["__x64_sys_getdents","__x64_sys_getdents64","__x64_sys_kill","__x64_sys_getuid","__x64_sys_getpgid","__x64_sys_getsid","__x64_sys_sysinfo","__x64_sys_read","__x64_sys_write","__x64_sys_openat","__x64_sys_bpf","__x64_sys_init_module","__x64_sys_finit_module","tcp4_seq_show","tcp6_seq_show","tpacket_rcv","icmp_rcv","sys_call_table","kallsyms_lookup_name"]){
      if(!this.kallsyms.has(n) && !this.apiThunks.has(n)){
        try{ this.defineApi(n, ()=>0n, {ret:"long"}); }catch{}
      }
    }
    this._installCpuHook();
  }
  reinstallHooks(){
    this._installCpuHook();
  }

  _heapNextJitter(){
    let x=this._heapPrng>>>0;
    x ^= (x<<13)>>>0;
    x ^= x>>>17;
    x ^= (x<<5)>>>0;
    this._heapPrng = x>>>0;
    return (x & 0xff)*16;
  }

  allocPool(size, tag="slub"){
    return this.allocSlub(size, tag);
  }
  allocSlub(size, tag="slub"){
    const aligned=(size+15)&~15;
    let hdr=this.nextPool;
    if(this.heapConfig?.aslr){
      hdr+=BigInt(this._heapNextJitter());
    }
    const addr=hdr+16n;
    this.nextPool=hdr+BigInt(aligned)+32n;
    if(this.heapConfig?.aslr) this.nextPool+=16n;
    this.mem.w64(hdr, POOL_MAGIC);
    this.mem.write(addr+BigInt(size), new Uint8Array(SLUB_GUARD_LEN).fill(SLUB_GUARD_BYTE));
    const spanEnd=addr+BigInt(aligned)+32n;
    for(let p=hdr & ~0xfffn; p< spanEnd; p+=0x1000n){
      if(!this.mem.hasPage(p)) this.mem.write(p, new Uint8Array(0x1000));
    }
    this.poolAllocs.push({addr,size,tag,freed:false});
    return addr;
  }
  freePool(addr){
    const e=this.poolAllocs.find(a=>a.addr===BigInt(addr));
    if(!e){ this.dbgLog.push(`[slub] free unknown ${addr.toString(16)}`); return false;}
    if(e.freed){ this.dbgLog.push(`[slub] double free at ${addr.toString(16)}`); return false;}
    e.freed=true; return true;
  }
  verifyGuards(){
    return this.poolAllocs.filter(a=>{
      if(a.freed) return false;
      for(let i=0;i<SLUB_GUARD_LEN;i++) if(this.mem.u8(a.addr+BigInt(a.size)+BigInt(i))!==SLUB_GUARD_BYTE) return true;
      return false;
    });
  }
  materializeModuleRange(base,size,opts){
    const fill=opts?.fill??0;
    const end=base+BigInt(size);
    for(let p=base & ~0xfffn; p< end; p+=0x1000n){
      if(!this.mem.hasPage(p)){
        const chunk = new Uint8Array(0x1000).fill(fill);
        this.mem.write(p, chunk);
      }
    }
  }

  defineApi(name, impl, meta){
    if(!this.apiThunks.has(name)){
      const thunk=this.nextThunk;
      this.nextThunk+=16n;
      this.mem.write(thunk, [0xf4]);
      // alias low mapping for unicorn (<2^31) — same physical byte
      const alias = this.bases.thunkAlias + (thunk - this.bases.thunk);
      this.mem.write(alias, [0xf4]);
      this.apiThunks.set(name, thunk);
      if(!this.thunkAliasMap) this.thunkAliasMap=new Map();
      this.thunkAliasMap.set(thunk, alias);
      this.thunkAliasMap.set(alias, thunk);
      this.pristineThunks.set(name, this.mem.read(thunk,8));
    }
    if(meta) this.apiMeta.set(name,meta);
    this.apiImpls.set(name, impl.bind(this));
    this.kallsyms.set(name, this.apiThunks.get(name));
    return this.apiThunks.get(name);
  }
  _aliasFor(thunk){
    if(!this.thunkAliasMap) return null;
    return this.thunkAliasMap.get(thunk) ?? null;
  }
  provisionUnknownApi(name){
    if(this.apiThunks.has(name)) return this.apiThunks.get(name);
    this.unmodeledExports.push(name);
    // Consult contract table (linux-api-meta) if available, else heuristic
    // Import lazily to avoid cycle; fallback to heuristic
    let meta=null;
    try{
      // dynamic check for known pvoid stubs — keep in sync with linux-api-meta
      const knownPvoid = new Set(["filp_open","kern_path","dentry_open","alloc_file","anon_inode_getfile","prepare_kernel_cred","get_current_cred","kallsyms_lookup_name","class_create","device_create","proc_create","proc_create_data","netlink_kernel_create"]);
      if(knownPvoid.has(name)) meta={ret:"pvoid"};
    }catch{}
    if(meta?.ret==="void"){}
    const isVoid = /^(printk|pr_|mutex_|spin_|kfree|vfree|misc_deregister|unregister_chrdev|proc_remove|cdev_del|__fentry__|__tracepoint|mcount|__traceiter|trace_.*)$/.test(name) || meta?.ret==="void";
    if(isVoid){
      this.dbgLog.push(`[linux] provisioned unmodeled ${name} -> VOID`);
      return this.defineApi(name, ()=>undefined, {ret:"void"});
    }
    // For pvoid stubs, use fuzz-configurable success-by-default (valid pointer) via stubPolicy
    if(meta?.ret==="pvoid"){
      this.dbgLog.push(`[linux] provisioned unmodeled ${name} -> pvoid (success-by-default)`);
      return this.defineApi(name, function(){
        const pol=this.stubPolicy.get(name);
        if(pol?.mode==="err"){
          const code=BigInt(pol.errCode ?? -2);
          return (code & M64); // ERR_PTR
        }
        // success: valid pointer
        return this.allocSlub(64, name);
      }, {ret:"pvoid"});
    }
    this.dbgLog.push(`[linux] provisioned unmodeled ${name} -> 0`);
    return this.defineApi(name, function(){
      const pol=this.stubPolicy.get(name);
      if(pol?.mode==="err") return (-2n & M64);
      return 0n;
    }, {ret:"long"});
  }
  resolveImportProvisioned(qualified){
    const name = qualified.includes("!") ? qualified.split("!").pop() : qualified;
    // strip version suffix?
    const baseName = name.split(".")[0];
    if(this.apiThunks.has(baseName)) return this.apiThunks.get(baseName);
    if(this.apiThunks.has(name)) return this.apiThunks.get(name);
    return this.provisionUnknownApi(name);
  }
  _installCpuHook(){
    const k=this;
    const begin=this.bases.thunk;
    const end=this.bases.thunk+THUNK_SIZE;
    const aliasBegin=this.bases.thunkAlias;
    const aliasEnd=aliasBegin+THUNK_SIZE;
    const handler=(rip)=>{
      let va=BigInt(rip);
      // translate alias low hit to high canonical for lookup
      if(va >= aliasBegin && va < aliasEnd){
        va = begin + (va - aliasBegin);
      } else if(va < begin || va >= end) return null;
      // find which thunk
      for(const [name,thunk] of k.apiThunks){
        if(thunk===va){
          // collect args per System V? Actually kernel APIs are called via System V as well.
          // We'll read args as Windows ABI for sim: rcx,rdx,r8,r9 + stack
          // But Linux kernel internal calls use SysV (rdi,rsi,rdx,rcx,r8,r9). Need to support both.
          // We can read both windows and sysv args and let impl pick via overloading - impl will receive windows order but we translate.
          // Better: read sysv order as primary for linux, then map to impl args as passed.
          // Impl signature expects (a,b,c,...) in call order. We'll provide sysv order.
          // So read rdi,rsi,rdx,rcx,r8,r9
          const cpu=k.cpu;
          const regs=cpu.regs;
          const sysv=[regs.rdi??0n, regs.rsi??0n, regs.rdx??0n, regs.rcx??0n, regs.r8??0n, regs.r9??0n];
          // Also need win order for compatibility? We'll just use sysv. Some impls may expect win order, but our linux-api impls are written for sysv.
          // For generic stub (unknown), we treat as 0.
          // stack args beyond 6
          const stackArgs=[];
          // For JsInterpreter, stack is at regs.rsp after call (ret pushed). Caller push: for sysv, args >6 are on stack at rsp+8 (ret).
          // Our callLinuxFunction pushes ret marker then sets rip. So stack args located at rsp+8.
          // Let's read up to 8 stack slots.
          try {
            const rsp= regs.rsp;
            for(let i=6;i<10;i++){
              const slotAddr = rsp + 8n + BigInt((i-6)*8);
              if(k.mem.canRead(slotAddr,8)) stackArgs.push(k.mem.u64(slotAddr));
              else stackArgs.push(0n);
            }
          } catch{ }
          const allArgs=[...sysv, ...stackArgs].slice(0,10);
          // Call impl with 6 args
          const impl=k.apiImpls.get(name);
          let ret=0n;
          let isVoid=false;
          try{
            if(impl){
              const r=impl(...allArgs);
              ret = r===undefined ? 0n : BigInt(r);
              // check meta void
              const meta=k.apiMeta.get(name);
              if(meta?.ret==="void") isVoid=true;
            }
          } catch(e){
            k.dbgLog.push(`[api] ${name} threw ${e.message}`);
            ret=0n;
          }
          // trace
          if(k.apiTrace.length < k.apiTraceLimit) k.apiTrace.push({name, args: allArgs.slice(0,4), ret, retAddr: 0n});
          k.emitTrace({kind:"api", name, args: allArgs.slice(0,4), ret});
          // emulate ret: pop ret addr, set rip, handle RAX preservation for void
          try {
            // For linux, return in rax
            const cpu=k.cpu;
            // pop ret addr?
            // In our callLinuxFunction we pushed marker; for thunk hook we need to pop it manually.
            // The CPU is stopped at thunk's hlt (0xf4). The hook should unwind.
            // We emulate ret by popping and setting rip to popped value.
            const retAddr = k.mem.u64(cpu.regs.rsp);
            cpu.regs.rsp = (cpu.regs.rsp + 8n) & 0xffffffffffffffffn;
            if(!isVoid) cpu.regs.rax = ret & 0xffffffffffffffffn;
            cpu.rip = retAddr;
            return true; // handled
          } catch(e){
            return true;
          }
        }
      }
      // Check for msr etc? Not thunk
      return null;
    };
    if(typeof this.cpu.addCodeHook==="function"){
      try { this.cpu.addCodeHook(handler, begin, end); } catch{}
      try { this.cpu.addCodeHook(handler, aliasBegin, aliasEnd); } catch{}
    } else {
      this.cpu.onCodeHook=handler;
    }
  }

  emitTrace(evt){
    if(this.traceEvents.length >= this.traceLimit) return;
    this.traceEvents.push({ seq: ++this.traceSeq, phase: this.tracePhase, ...evt });
  }
  debugPrint(line){
    this.dbgLog.push(line);
    this.emitTrace({kind:"printk", text: line});
    if(this.onDebugPrint) try{this.onDebugPrint(line);}catch{}
  }
  dbgPrint(fmtAddr, args){
    const fmt=this.mem.readAnsi(fmtAddr, 512);
    let ai=0;
    const out=fmt.replace(/%(-?\d+)?(?:\.(\d+))?(I(?:32|64)|l{1,2})?([diuxXps])/g, (_m,_w,_p,mod,conv)=>{
      const wide=!!mod;
      const v=args[ai++]??0n;
      switch(conv){
        case "d": return BigInt.asIntN(64,v).toString();
        case "u": return v.toString();
        case "x": case "X": {
          const width=wide?16:8;
          const digits=v.toString(16);
          const padded=digits.padStart(width, conv==="X"?"F":"0");
          return conv==="X"? padded.slice(-width).toUpperCase(): padded.slice(-width);
        }
        case "p": return v===0n ? "0000000000000000" : v.toString(16).padStart(16,"0");
        case "s": return this.mem.readAnsi(v);
        default: return `%${conv}`;
      }
    });
    this.debugPrint(out);
    return out;
  }

  // SysV call wrapper for file_operations — handles both JsInterpreter (stopOnRip) and Unicorn (low hook)
  callLinuxFunction(funcAddr, args=[], shadowSpace=0){
    const cpu=this.cpu;
    const isHybrid = !!(cpu && cpu.js && cpu.uc);
    const isJs = !isHybrid && cpu.constructor?.name==="JsInterpreter";
    // ensure canonical stack
    if(cpu.regs.rsp===0n || cpu.regs.rsp > M64-0x1000n){
      const stackTop=this.stackBase + BigInt(this.stackSize);
      cpu.regs.rsp = (stackTop & ~0xFn) - 8n;
      cpu.regs.rbp = 0n;
    }
    const marker = LOW_RET_MARKER;
    // For unicorn/hybrid we need a code hook at marker; for js we can use stopOnRip
    let hookHandle=null;
    let returned=false;
    const markerHook=(rip)=>{
      if(BigInt(rip)===marker){ returned=true; return true; }
      return null;
    };
    if(isJs){
      // JsInterpreter poll
      cpu.stopOnRip = marker;
    } else {
      // Unicorn/Hybrid — install low hook on both engines if hybrid
      try{
        if(isHybrid){
          cpu.js.addCodeHook(markerHook, marker, marker);
          cpu.uc.addCodeHook(markerHook, marker, marker);
        } else if(typeof cpu.addCodeHook==="function"){
          hookHandle=cpu.addCodeHook(markerHook, marker, marker);
        }
      }catch{}
    }
    // Align and set args SysV
    cpu.regs.rsp = (cpu.regs.rsp & ~0xFn) - 8n;
    const order=["rdi","rsi","rdx","rcx","r8","r9"];
    for(let i=0;i<Math.min(args.length,6);i++) cpu.regs[order[i]]=BigInt(args[i]) & M64;
    if(args.length>6) for(let i=args.length-1;i>=6;i--) cpu.pushVal(BigInt(args[i]));
    cpu.pushVal(marker);
    cpu.rip = BigInt(funcAddr) & M64;
    let reason;
    for(;;){
      reason=cpu.run();
      if(isJs && reason==="returned") break;
      if(!isJs && returned) break;
      if(reason==="breakpoint"){
        if(cpu.lastDebugStop){
          if(isJs) cpu.stopOnRip=null;
          else if(hookHandle && typeof cpu.hook_del==="function") try{cpu.hook_del(hookHandle);}catch{}
          return {status:"debug-stop", code:cpu.lastDebugStop.code, rip:cpu.lastDebugStop.rip};
        }
        if(cpu.rip===marker) break;
        continue;
      }
      if(reason==="error"||reason==="timeout"||reason==="halted"){
        if(isJs) cpu.stopOnRip=null;
        else if(hookHandle && typeof cpu.hook_del==="function") try{cpu.hook_del(hookHandle);}catch{}
        if(reason==="error") return {status:"fault", error:cpu.fault};
        if(reason==="timeout") return {status:"timeout"};
        return {status:reason, rip:cpu.rip};
      }
      // For unicorn, a hook may have set returned but run returned "timeout" chunk; continue
      if(!isJs && returned) break;
    }
    if(isJs) cpu.stopOnRip=null;
    else if(hookHandle && typeof cpu.hook_del==="function") try{cpu.hook_del(hookHandle);}catch{}
    // Hybrid cleanup: remove marker hooks
    if(isHybrid){
      try{ cpu.js.codeHooks = cpu.js.codeHooks.filter(h=>h.fn!==markerHook); }catch{}
      try{ if(typeof cpu.uc.hook_del==="function"){} }catch{}
    }
    return {status:"ok", retval: cpu.regs.rax};
  }

  callFunctionSeh(funcAddr, args, image){
    // Use linux call convention? For init_module, args are none or (void) . But Linux init_module takes (void) not driver object.
    // We'll try SysV call; reuse callLinuxFunction.
    // Provide SEH-like catch for faults (reuse NtKernel logic simplified)
    const res = this.callLinuxFunction(funcAddr, args);
    if(res.status==="fault"){
      // optionally try to dispatch exception? Not needed
      this.exceptionTrace.push({faultRip:`0x${funcAddr.toString(16)}`, handled:false, detail: String(res.error?.message??"fault")});
      // Return fault but not crash
    }
    return res;
  }

  drainDeferred(){ return {dpcs:0, workItems:0, apcs:0}; }
}
