/**
 * Glossary: short definitions for kernel/technical terms used across the
 * course. Pure data + string helpers — no DOM. apps/web turns these into
 * hover tooltips over rendered lesson markdown.
 *
 * @typedef {Object} GlossaryEntry
 * @property {string} key    normalized lookup key (assigned at load)
 * @property {string} term   canonical display name
 * @property {string} [full] expansion of an abbreviation (subtitle)
 * @property {string} def    1-3 sentence definition shown in the tooltip
 * @property {string[]} [aliases] extra matchable surface forms
 */

/**
 * Concept glossary. Keys are `normalizeTermKey()` forms of the term.
 * @type {Record<string, GlossaryEntry>}
 */
export const glossary = {
  // ---------------------------------------------------------- executive core
  ntoskrnl: {
    term: "ntoskrnl.exe",
    full: "Windows NT kernel image",
    def: "The Windows kernel executable — the core of the OS, owning processes, memory, I/O and driver loading. Its structure layouts in these labs come straight from per-build Vergilius tables.",
    aliases: ["ntoskrnl"],
  },
  hal: {
    term: "HAL",
    full: "Hardware Abstraction Layer",
    def: "A kernel-side library (hal.dll) that hides platform differences — interrupt controllers, clocks, buses — behind one interface, sitting beside ntoskrnl. Every hardware interrupt path touches it, which historically made it a favorite hooking target.",
    aliases: ["hal.dll"],
  },
  kpcr: {
    term: "KPCR",
    full: "Kernel Processor Control Region",
    def: "A per-CPU structure holding that core's state: current thread, IDT/GDT pointers, IRQL. On x64 code reaches it via the gs segment register; debuggers read it to answer 'what is this core doing right now?'",
  },
  eprocess: {
    term: "EPROCESS",
    full: "Executive process block",
    def: "The kernel structure describing one process: PID, image name, object handles, and the ActiveProcessLinks list node. Opaque to user mode; walking these blocks is how Task Manager, EDRs and debuggers build every process list.",
  },
  psactiveprocesshead: {
    term: "PsActiveProcessHead",
    def: "The global list head anchoring the circular doubly-linked ring of all _EPROCESS structures. Whatever walks it sees the system's official process list — which is exactly why DKOM hides processes by unlinking from it.",
  },
  activeprocesslinks: {
    term: "ActiveProcessLinks",
    def: "The _LIST_ENTRY field inside every _EPROCESS linking it into the global process ring. Splice a node out by overwriting its neighbors' pointers and a running process vanishes from enumeration while it keeps executing.",
  },
  list_entry: {
    term: "_LIST_ENTRY",
    def: "A pair of pointers, {Flink, Blink}, forming one node of a doubly-linked list. Kernel lists — processes, modules, DPC queues — are chains of these embedded in larger structures.",
  },
  flink: {
    term: "Flink",
    def: "Forward link of a _LIST_ENTRY node (Blink is the backward one). Unlinking means making neighbors point past you: prev->Flink = next; next->Blink = prev.",
    aliases: ["Blink", "Flink/Blink"],
  },
  kthread: {
    term: "KTHREAD",
    def: "The kernel's per-thread control structure — scheduling state, stack, IRQL — embedded in the executive ETHREAD. Cross-referencing threads against the process ring exposes DKOM-hidden processes.",
  },
  dbgprint: {
    term: "DbgPrint",
    def: "The kernel-mode printf; output lands in the debug buffer. This course records every call — recover the trail with !analyze -v.",
  },
  driverentry: {
    term: "DriverEntry",
    def: "The mandatory entry point of every Windows driver, called once at load with the driver object and registry path. Returning STATUS_SUCCESS lets the driver stay resident.",
  },
  zwloaddriver: {
    term: "ZwLoadDriver",
    def: "The documented API that loads a driver through the normal path — service control manager, registry configuration, registered image. Fully legitimate, and fully traceable, which is why manual mapping exists.",
  },
  kldr_data_table_entry: {
    term: "_KLDR_DATA_TABLE_ENTRY",
    def: "The loader's per-module record: base address, size and name of every loaded image, chained on the kernel module list. `lm` enumerates it; manually mapped images deliberately never appear here.",
  },
  pslookupprocessbyprocessid: {
    term: "PsLookupProcessByProcessId",
    def: "Documented kernel API resolving a PID to a referenced PEPROCESS. Module 3's hook suppresses exactly this lookup for one PID — proof of how much software trusts it.",
  },
  pdb: {
    term: "PDB",
    full: "Program Database symbols",
    def: "Microsoft's debug-symbol files mapping names and types to structure offsets. Real tooling resolves _EPROCESS offsets per build from PDBs; ntsim gets the same truth from Vergilius tables instead.",
    aliases: ["PDB symbols"],
  },
  cid: {
    term: "Cid",
    full: "Client ID",
    def: "The kernel's name for a process/thread identifier — the decimal PID shown in !process output.",
  },
  "handle table": {
    term: "handle table",
    def: "Per-process array tracking every open object: processes, files, keys. Hidden processes' handles survive unlinking, so cross-checking handle references against the EPROCESS ring defeats naive DKOM.",
    aliases: ["handle tables"],
  },

  // ---------------------------------------------------------------- memory
  pool: {
    term: "pool",
    full: "Kernel pool",
    def: "The kernel's heap. NonPagedPool stays resident in RAM; PagedPool may swap to disk. Drivers allocate here, and corruption here crashes the whole system — usually far away from the buggy code.",
    aliases: ["kernel pool", "kernel pools"],
  },
  nonpagedpool: {
    term: "NonPagedPool",
    full: "Non-paged pool",
    def: "Kernel memory guaranteed to stay resident — the only kind safe to touch at DISPATCH_LEVEL and above. Driver objects and high-IRQL data must live here.",
    aliases: ["non-paged pool"],
  },
  pagedpool: {
    term: "PagedPool",
    full: "Paged pool",
    def: "Kernel memory the memory manager may page out. Legal only at PASSIVE_LEVEL or APC_LEVEL — touching it at DISPATCH_LEVEL is an instant bugcheck.",
    aliases: ["paged pool"],
  },
  pooltag: {
    term: "pool tag",
    def: "Four characters every pool allocation carries (here 'KfPb') identifying its owner. Pool trackers sum allocations per tag to attribute leaks — which is why malware picks bland tags to blend in.",
    aliases: ["pool tags", "pool-tag"],
  },
  poolguard: {
    term: "pool guard",
    full: "Trailing pool guard bytes",
    def: "Pattern bytes (here 0xA5 repeated) written after an allocation's usable range. If they no longer read back, something overflowed — hard evidence of corruption even before anyone crashed.",
    aliases: ["guard", "guards"],
  },
  specialpool: {
    term: "special pool",
    def: "Driver Verifier mode that gives each qualifying allocation its own pages with guards on both sides — an overrun hits unmapped memory instantly instead of silently corrupting a neighbor.",
  },
  drvverifier: {
    term: "Driver Verifier",
    def: "Built-in Windows stress machinery that subjects drivers to hostile conditions: special pool, IRQL validation, random low-resource simulation. The first tool reached for on pool-corruption reports.",
  },
  bugcheck: {
    term: "bugcheck",
    full: "Bugcheck (BSOD)",
    def: "The kernel's deliberate self-termination when it detects unrecoverable inconsistency — the blue screen. Each carries a numeric code (0x19, 0xC2, 0x50…) naming the invariant that failed.",
    aliases: ["BSOD"],
  },
  irql_not_less_or_equal: {
    term: "IRQL_NOT_LESS_OR_EQUAL",
    def: "Bugcheck 0xA: code touched memory or lowered IRQL in a way illegal for its current interrupt level. Almost always a driver breaking the IRQL rules.",
  },
  bad_pool_header: {
    term: "BAD_POOL_HEADER",
    def: "Bugcheck 0x19: a pool block header was damaged — typically an overflow smashing size or magic fields, or free-list damage.",
  },
  bad_pool_caller: {
    term: "BAD_POOL_CALLER",
    def: "Bugcheck 0xC2: a driver misused the pool API — double free, invalid tag, or freeing memory at the wrong IRQL.",
  },
  page_fault_in_nonpaged_area: {
    term: "PAGE_FAULT_IN_NONPAGED_AREA",
    def: "Bugcheck 0x50: a fault referenced memory that must never page out — the classic landing spot of use-after-free on non-paged pool memory.",
  },
  vad: {
    term: "VAD",
    full: "Virtual Address Descriptor",
    def: "Memory-manager structure describing each user-address-space reservation. Executable memory present in VADs but backed by no module-list image is 'unbacked memory' — a manual-mapping tell.",
  },
  pml4: {
    term: "PML4",
    full: "Page Map Level 4",
    def: "Top level of the x64 four-level page-table hierarchy; its entries point into PDPT tables. The physical address of the active PML4 sits in CR3 — reload CR3 and you swap the entire visible address space.",
  },
  pagetable: {
    term: "page table",
    def: "The hierarchy translating virtual addresses to physical: PML4, PDPT, PD, PT on x64. The TLB caches translations; hypervisors insert a second, nested layer (EPT) beneath all of it.",
    aliases: ["page tables"],
  },
  cr3: {
    term: "CR3",
    def: "CPU register holding the physical base of the current address space's PML4. Every context switch reloads it — one register move decides which memory is 'real'.",
  },
  virtualaddressspace: {
    term: "virtual address space",
    def: "The range of addresses the CPU can dereference, mapped through page tables. On x64 Windows the top half belongs to the kernel, the bottom half to user mode.",
  },
  "canonical address": {
    term: "canonical address",
    def: "x64 rule: in a valid address, bits 63:48 must copy bit 47, splitting space into a low (user) and a high (kernel) half. Everything else faults — the reason kernel pointers look like 0xFFFF….",
    aliases: ["canonical addresses"],
  },
  rva: {
    term: "RVA",
    full: "Relative Virtual Address",
    def: "An offset measured from the image base instead of an absolute address. PE headers and sections are RVA-addressed so the same image works wherever the loader places it.",
  },
  imagebase: {
    term: "ImageBase",
    def: "The preferred load address baked into a PE header. When an image lands somewhere else, relocations patch every absolute address that assumed the preferred base.",
  },
  relocation: {
    term: "relocation",
    def: "Fix-up applied to absolute addresses in compiled code when an image did not land at its preferred ImageBase (DIR64 type on x64). Manual mappers must apply them by hand — skip them and the payload crashes on its first call.",
    aliases: ["relocations"],
  },
  pe: {
    term: "PE",
    full: "Portable Executable (PE32+)",
    def: "The Windows executable format: headers, sections, imports, exports, relocations. 'Manual mapping' is loading a PE into memory by hand, imitating the OS loader.",
    aliases: ["PE32+"],
  },
  iat: {
    term: "IAT",
    full: "Import Address Table",
    def: "Array of function pointers the loader fills with the resolved addresses of imported APIs. Zeroing it parks a manually mapped payload; scanning it shows what code really calls.",
  },
  ssdt: {
    term: "SSDT",
    full: "System Service Dispatch Table",
    def: "The kernel table routing syscall numbers to their implementations. SSDT hooking once dominated rootkits; patch protection pushed technique toward inline hooks.",
    aliases: ["SSDT-style"],
  },

  // ----------------------------------------------------------- hooks/loading
  manualmapping: {
    term: "manual mapping",
    def: "Loading a PE without the OS loader: copy sections, apply relocations, resolve imports, call the entry point yourself. Nothing is registered — no module entry, no notifications — hence its popularity with malware.",
    aliases: ["manually mapped", "manual-map"],
  },
  inlinehook: {
    term: "inline hook",
    def: "Rewriting a function's first instructions to jump into attacker-controlled code, usually with an E9 jmp rel32. The displaced bytes are preserved on a trampoline so the real function stays reachable.",
    aliases: ["jmp rel32"],
  },
  detour: {
    term: "detour",
    def: "An inline redirect patched over a function's prologue — the jump that sends every caller through attacker code first.",
    aliases: ["detoured", "detours"],
  },
  trampoline: {
    term: "trampoline",
    def: "The copied original instructions plus a jump-back stub that an inline hook preserves, letting the hook — or honest callers — still execute the genuine function.",
  },
  prologue: {
    term: "prologue",
    def: "A function's first instructions (stack setup, saved registers). Inline hooks overwrite exactly these bytes, which is why integrity tools compare prologues against known-good copies.",
    aliases: ["prologues"],
  },
  rwx: {
    term: "RWX",
    full: "Read-Write-eXecute memory",
    def: "Memory that is simultaneously writable and executable. Legitimate kernel code avoids it; RWX in kernel space is a strong unbacked-code signal, and HVCI/ACG policies forbid creating it.",
  },
  imagenotify: {
    term: "image-load notification",
    def: "Kernel callback (PsSetLoadImageNotifyRoutine) fired whenever any image loads — core AV/EDR telemetry. Manually mapped code never triggers one.",
  },
  acg: {
    term: "ACG",
    full: "Arbitrary Code Guard",
    def: "Policy that blocks creating writable-and-executable memory. Kernel-side equivalents under HVCI make classic RWX mapping painful, pushing attackers toward signed loaders instead.",
    aliases: ["arbitrary-code-guard", "arbitrary code guard"],
  },

  // ------------------------------------------------------ interrupts/sched
  irql: {
    term: "IRQL",
    full: "Interrupt ReQuest Level",
    def: "Per-CPU interrupt priority from 0 to 31 (software-visible 0-15 on x64). Higher levels mask lower ones, and each level forbids actions: paging and waiting above DISPATCH_LEVEL are fatal. The ladder every Windows driver lives on.",
    aliases: ["interrupt request level", "interrupt request levels"],
  },
  passive_level: {
    term: "PASSIVE_LEVEL",
    def: "IRQL 0 — ordinary thread execution. Everything is allowed: paging, waiting, blocking. Where comfortable code lives.",
  },
  apc_level: {
    term: "APC_LEVEL",
    def: "IRQL 1 — normal APCs are masked. Used for brief synchronization; paging is still allowed.",
  },
  dispatch_level: {
    term: "DISPATCH_LEVEL",
    def: "IRQL 2 — the scheduler/DPC level. No paging, no waiting, no blocking; every cycle spent here is stolen from all threads on the CPU. DPC routines run at this level.",
    aliases: ["DISPATCH"],
  },
  dpc: {
    term: "DPC",
    full: "Deferred Procedure Call",
    def: "Callback queued per-CPU to run at DISPATCH_LEVEL once priority falls back toward 2 — how drivers postpone work out of interrupt context. Pin the CPU above 2 and queued DPCs simply never fire.",
    aliases: [
      "deferred procedure call", "deferred procedure calls", "deferred procedures",
    ],
  },
  isr: {
    term: "ISR",
    full: "Interrupt Service Routine",
    def: "The first handler a driver registers for its device interrupt, running at device IRQL. Kept minimal — real work gets queued to a DPC.",
  },
  apc: {
    term: "APC",
    full: "Asynchronous Procedure Call",
    def: "Callback queued against a thread, delivered at PASSIVE/APC_LEVEL. The mechanism behind I/O completion and alertable waits — and behind userland early-bird injection.",
    aliases: ["APCs"],
  },
  ipi: {
    term: "IPI",
    full: "Inter-Processor Interrupt",
    def: "Interrupt sent from one CPU core to another — forcing TLB shootdowns or raising another core's attention. Sits near the top of the IRQL ladder alongside clock and device levels.",
  },

  // ------------------------------------------------------- tracing / #DB
  trap_flag: {
    term: "trap flag",
    def: "Bit 8 of EFLAGS/RFLAGS. Set it and the CPU executes exactly one instruction, raises a debug exception at the next boundary, then auto-clears the bit — the hardware mechanism behind every debugger's single-step button. Software can read it too, which is why it doubles as an anti-tracing tripwire.",
    aliases: ["TF", "RFLAGS.TF", "EFLAGS.TF"],
  },
  single_stepping: {
    term: "single-stepping",
    def: "Running a program one assembly instruction at a time so registers, memory and control flow can be inspected after every step. Implemented via the trap flag; also how tracers unknowingly announce themselves to protected code.",
    aliases: ["single-step", "single step", "stepping", "trace", "tracing"],
  },
  debug_exception: {
    term: "debug exception",
    def: "CPU event vector 1 (INT 1) raised by hardware single-stepping or hardware breakpoints — EXCEPTION_SINGLE_STEP to Windows code. A tracer intercepts it before the guest ever sees it; anti-trace checks exactly that.",
    aliases: ["INT 1", "#DB", "EXCEPTION_SINGLE_STEP", "STATUS_SINGLE_STEP"],
  },
  pushfq: {
    term: "PUSHFQ",
    def: "Pushes RFLAGS onto the stack as data. Combined with POPFQ it lets software read or rewrite live CPU flags — including arming or detecting the trap flag — without any API call a hook could see.",
    aliases: ["PUSHF", "POPFQ", "POPF"],
  },
  veh: {
    term: "VEH",
    full: "Vectored Exception Handler",
    def: "User-registered exception callback consulted before structured handling, in registration order. Anti-trace uses one to catch self-injected INT 1s; if a debugger swallows those events first, the handler starves and the process knows it is being traced.",
    aliases: [
      "vectored exception handler", "vectored exception handlers",
      "vectored handler", "KiVectoredHandler",
    ],
  },

  // ------------------------------------------------------------- defense
  edr: {
    term: "EDR",
    full: "Endpoint Detection and Response",
    def: "Security agent continuously instrumenting the endpoint — process trees, image loads, memory scans. Much of its telemetry comes from trusting exactly the kernel structures this course teaches you to manipulate.",
    aliases: ["EDRs"],
  },
  rootkit: {
    term: "rootkit",
    def: "Malware whose goal is stealth and persistence by subverting the OS's view of reality — DKOM, inline hooks and filter drivers are its classic toolkit.",
    aliases: ["rootkits"],
  },
  dkom: {
    term: "DKOM",
    full: "Direct Kernel Object Manipulation",
    def: "Attacking kernel data structures directly — unlinking a process from ActiveProcessLinks rather than terminating it. Decades old and still effective wherever defenders trust in-kernel lists blindly.",
    aliases: ["direct kernel object manipulation"],
  },
  hvci: {
    term: "HVCI",
    full: "Hypervisor-protected Code Integrity",
    def: "Memory integrity enforced with the hypervisor: kernel page execution and patching is validated above the OS, locking out unsigned code and making kernel patches detectable.",
  },
  kcfg: {
    term: "kCFG",
    full: "kernel Control Flow Guard",
    def: "Mitigation restricting indirect calls to validated targets, blunting control-flow hijack even when an attacker achieves a write-what-where.",
    aliases: ["XCFG", "control-flow guard", "control flow guard"],
  },
  kpp: {
    term: "KPP",
    full: "Kernel Patch Protection (PatchGuard)",
    def: "Windows mechanism that periodically verifies critical kernel structures and exports against tampering — the reason SSDT/inline patches in protected areas are unstable for attackers.",
    aliases: ["PatchGuard"],
  },
  ept: {
    term: "EPT",
    full: "Extended Page Tables",
    def: "Second-level page translation a hypervisor imposes beneath the guest's own tables. Enables shadow execution views the guest cannot alter, because its page tables no longer have the final say.",
  },
  hypervisor: {
    term: "hypervisor",
    def: "Layer beneath the OS controlling physical memory and CPU virtualization. Security uses: introspection, EPT shadow views, and integrity checks the guest cannot touch.",
  },
  ntstatus: {
    term: "NTSTATUS",
    full: "NT status code",
    def: "Kernel status-code convention: 32-bit values with severity in the high bits and symbolic names like STATUS_SUCCESS or STATUS_INVALID_PARAMETER. The labs expect symbolic names, lowercase.",
    aliases: ["STATUS_INVALID_PARAMETER", "STATUS_SUCCESS"],
  },
  pid: {
    term: "PID",
    full: "Process Identifier",
    def: "Unique decimal ID the kernel assigns each process — the Cid in !process output. Stays stable for the process's lifetime even when image names repeat.",
    aliases: ["process id", "process ids"],
  },
  "write-what-where": {
    term: "write-what-where",
    def: "Exploit primitive offering an arbitrary value written to an arbitrary address. A one-byte pool overflow becomes privilege escalation when the neighboring object's function pointer is the 'where'.",
  },
  uaf: {
    term: "use-after-free",
    def: "Accessing memory after it was freed. In non-paged pool it surfaces as PAGE_FAULT_IN_NONPAGED_AREA — or worse, as controlled reuse for privilege escalation.",
  },
  oob: {
    term: "out-of-bounds write",
    def: "Writing past an allocation's end. In kernel pools it smashes adjacent metadata and guards — today's crash log is tomorrow's exploit primitive.",
    aliases: ["out-of-bounds"],
  },
  overflow: {
    term: "overflow",
    full: "Buffer overflow",
    def: "Writing beyond a buffer's end. Adjacent allocations make kernel overflows cross-object damage: you corrupt someone else's metadata, and the crash lands miles from your bug.",
  },
  lpe: {
    term: "local privilege escalation",
    def: "Turning limited-user code execution into kernel or SYSTEM authority — the usual destination of pool-corruption and write-what-where bugs.",
  },
  antiforensics: {
    term: "anti-forensics",
    def: "Techniques that degrade post-incident reconstruction — for example spinning above DISPATCH_LEVEL so instrumentation callbacks never observe the code.",
  },
  instrcallback: {
    term: "instrumentation callback",
    def: "Kernel notification points (ETW, callback registrations) that security tooling subscribes to. Code executing above certain IRQLs bypasses several of them — IRQL abuse doubles as evasion.",
    aliases: ["instrumentation callbacks"],
  },

  // ------------------------------------------------------------ tooling
  windbg: {
    term: "WinDbg",
    def: "Microsoft's flagship kernel and user debugger. 'kd>' is its command-line persona; this course emulates a faithful subset of it over the ntsim model.",
  },
  kd: {
    term: "kd",
    full: "kernel debugger",
    def: "The command-line kernel debugger that WinDbg wraps — source of the 'kd>' prompt convention and commands like dt, !process and lm.",
  },
  "live-kd": {
    term: "live-kd",
    def: "Inspecting a live machine's kernel state without rebooting into debug mode. Defender tooling uses the same access path as this course's console.",
  },
  x64: {
    term: "x64",
    full: "x86-64 / AMD64",
    def: "The 64-bit architecture Windows targets: canonical addresses, four-level paging, gs-based KPCR access, the Win64 calling convention. Everything in these labs assumes it.",
  },
  rip: {
    term: "RIP",
    full: "instruction pointer",
    def: "Register holding the address of the next instruction to execute. `k` unwinds the stack from it; an inline hook's jmp rel32 redirects RIP through attacker code first.",
  },
  ntsim: {
    term: "ntsim",
    def: "This course's browser-resident emulation of the x64 Windows kernel: sparse memory, a deterministic CPU interpreter, and Vergilius-driven structure tables. Every debugger command operates on it, fully client-side.",
  },
  vergilius: {
    term: "Vergilius",
    full: "Vergilius Project",
    def: "Open repository of Windows kernel structure layouts extracted per build (CC0 licensed). Its tables are ntsim's source of truth — switching builds means swapping table directories.",
    aliases: ["Vergilius project", "Vergilius tables"],
  },
  processexplorer: {
    term: "Process Explorer",
    def: "Sysinternals GUI that enumerates processes through the same APIs and lists you walk raw here — an example of defender tooling built on trust in PsActiveProcessHead.",
  },
  "22h2": {
    term: "22H2",
    full: "Windows 10 22H2 (build 19045)",
    def: "The Windows 10 '2022 Update' whose layout tables drive these labs — for example _EPROCESS.ActiveProcessLinks at offset 0x448.",
  },

  // ---------------------------------------------- roadmap terms (future)
  toctou: {
    term: "TOCTOU",
    full: "Time-Of-Check-Time-Of-Use",
    def: "Race condition where state changes between validation and use — the bug family behind the RACEAC-style BYOVD labs on the roadmap.",
  },
  byovd: {
    term: "BYOVD",
    full: "Bring Your Own Vulnerable Driver",
    def: "Attack pattern that loads a legitimately signed but vulnerable driver as the kernel foothold — sidestepping the signing enforcement that manual mappers fight.",
  },
};

/**
 * Debugger command docs. Matched ONLY against whole inline-code elements
 * (never prose), keyed by the literal command text.
 * @type {Record<string, GlossaryEntry>}
 */
export const commandDocs = {
  lm: {
    term: "lm",
    def: "List loaded modules: base, end, name for each image. Manually mapped code is absent from this list — absence plus executable memory is a tell.",
  },
  dt: {
    term: "dt",
    def: "Dump Type — render a structure's layout from the build tables, optionally overlaid at an address: dt nt!_EPROCESS <addr>.",
  },
  r: {
    term: "r",
    def: "Show the register context of the current processor context.",
  },
  k: {
    term: "k",
    def: "Stack trace — unwind call frames upward from the current RIP.",
  },
  eb: {
    term: "eb",
    def: "Edit bytes — poke byte values straight into memory: eb <addr> 01. The labs' universal repair mechanic: flags, prologues, pool guards.",
  },
  "!process": {
    term: "!process",
    def: "Walk the EPROCESS ring. '!process 0 0' prints one line per process (EPROCESS, Cid, ImageFileName); a PID argument gives a full field walk of that process.",
  },
  "!analyze": {
    term: "!analyze",
    def: "Summarize world state; with -v it includes recent DbgPrint output — how secrets printed by payloads are recovered.",
  },
  "!irql": {
    term: "!irql",
    def: "Show the current IRQL, or force one with '!irql 2' — this lab's repair mechanic for the pinned-CPU scenario.",
  },
  "!dpcs": {
    term: "!dpcs",
    def: "List queued DPCs: routine address, DeferredRoutine, status.",
  },
  "!dpcdrain": {
    term: "!dpcdrain",
    def: "Drop to DISPATCH_LEVEL and run all queued DPCs to completion.",
  },
  "!mmstate": {
    term: "!mmstate",
    def: "Show the manual-map loader state: stubbed config flags and unresolved IAT slots.",
  },
  "!mmrun": {
    term: "!mmrun",
    def: "Re-run the manual map: resolve imports and start the payload.",
  },
  "!hookscan": {
    term: "!hookscan",
    def: "Diff live export bytes against the pristine prologues recorded at boot; name an export to scan just that one.",
  },
  "!hooktest": {
    term: "!hooktest",
    def: "Exercise a modeled API call path to prove behavior changed — run it before and after your repair.",
  },
  "!poolfind": {
    term: "!poolfind",
    def: "Find pool blocks by tag ('!poolfind KfPb'): user address, size, state, and guard health per block.",
  },
  "!poolverify": {
    term: "!poolverify",
    def: "Sweep every trailing pool guard and report corruption precisely.",
  },
};

// ------------------------------------------------------------- key plumbing

/** Normalize any surface form to its glossary lookup key. */
export function normalizeTermKey(raw) {
  let s = String(raw).trim().toLowerCase();
  if (s.startsWith("nt!")) s = s.slice(3);
  while (s.startsWith("_")) s = s.slice(1);
  return s;
}

/** Attach stable keys and validate uniqueness of every surface form. */
function index(entries) {
  const bySurface = new Map();
  const indexed = {};
  for (const [key, entry] of Object.entries(entries)) {
    entry.key = key;
    indexed[key] = entry;
    for (const surface of [entry.term, ...(entry.aliases ?? [])]) {
      const norm = normalizeTermKey(surface);
      if (bySurface.has(norm)) {
        throw new Error(`glossary collision: "${norm}" (${key} vs ${bySurface.get(norm).key})`);
      }
      bySurface.set(norm, entry);
    }
  }
  return { indexed, bySurface };
}

const concepts = index(glossary);
const commands = index(commandDocs);

/**
 * Resolve any raw surface — prose term, `code` span, or debugger command —
 * to its glossary entry. Falls back to stripping a trailing plural "s".
 * @returns {GlossaryEntry|null}
 */
export function findTermEntry(raw) {
  if (raw == null) return null;
  const text = String(raw).trim();
  if (!text) return null;
  const cmd = commands.bySurface.get(text.toLowerCase());
  if (cmd) return cmd;
  const key = normalizeTermKey(text);
  const hit = concepts.indexed[key] ?? concepts.bySurface.get(key);
  if (hit) return hit;
  if (key.endsWith("s")) {
    const base = key.slice(0, -1);
    return concepts.indexed[base] ?? concepts.bySurface.get(base) ?? null;
  }
  return null;
}

/**
 * Regex alternation source matching every concept surface form,
 * longest-first. Debugger commands ("!irql") are intentionally excluded —
 * they only ever match whole code elements, never prose.
 */
export function buildTermPattern() {
  const forms = [];
  for (const entry of Object.values(concepts.indexed)) {
    forms.push(entry.term, ...(entry.aliases ?? []));
  }
  return forms
    .filter((f) => !f.startsWith("!"))
    .sort((a, b) => b.length - a.length)
    .map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|");
}
