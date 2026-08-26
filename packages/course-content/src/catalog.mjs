/**
 * Course catalog v2 — Modules 1-4 of the windows-kernel track.
 *
 * Flag "hashes" are sha256 over NORMALIZED answers (trim + lowercase) and are
 * precomputed constants (browser-safe; no crypto dep at runtime). The
 * plaintext answers live in instructor notes / docs/plan.md; prompts pin the
 * exact expected format so grading is unambiguous.
 *
 * Deterministic addresses verified against the 22h2 table set:
 *   - kftarget.exe _EPROCESS fixed by populateFromDump() at 0xffffc80000001000,
 *     ActiveProcessLinks +0x448 => answer 0xffffc80000001448   (m1.l2.f1)
 *   - irql-dpc world: DeferredRoutine at 0xfffff8055a401400    (m2.l1.f2)
 *   - pool-corrupt world: second KfPb block at 0xfffff90000001200 (m4.l1.f1)
 *   - anti-trace world: kftrace!TraceVeh at 0xfffff8055a800000+0x1400
 *     => answer 0xfffff8055a801400; traced !selftest swallows exactly 4
 *     EXCEPTION_SINGLE_STEP events before TraceVeh sees one    (m5.l1.f1/f2)
 */
import m1l1Body from "./lessons/m1-l1.mjs";
import m1l2Body from "./lessons/m1-l2.mjs";
import m1l3Body from "./lessons/m1-l3.mjs";
import m2l1Body from "./lessons/m2-l1.mjs";
import m3l1Body from "./lessons/m3-l1.mjs";
import m4l1Body from "./lessons/m4-l1.mjs";
import m5l1Body from "./lessons/m5-l1.mjs";

const F = {
  m1l1f1: "5c5ff15e068d0e09659a861ee1c8894f5ab3fb9d239f176d715e3b2a526eb670",
  m1l1f2: "865736a1c30a82dc67aba820360a01b1d9d0da5643234cd07c4d60b06eb530c5",
  // kftarget.exe _EPROCESS is fixed by populateFromDump() at 0xffffc80000001000
  // and ActiveProcessLinks sits at +0x448 (22h2 tables) => 0xffffc80000001448
  m1l2f1: "fb5bee16424f0ead5c88377e236904125c495c6b0ab7cbfff5dc4bfc6de85b0a",
  m1l3f1: "fac4db6ff2799f9496b9274d97f297372527ccfd2ac51d4ebcac83244a11a377",
  m2l1f1: "e629fa6598d732768f7c726b4b621285f9c3b85303900aa912017db7617d8bdb",
  m2l1f2: "eb6ac6d19614930b2043d812fa2f921182d705a123fa25a0960ba32885c1c5ec",
  m2l1f3: "6531630236cc0988185d752ba4774bdaef12e7cc3e9aafef44fac35512c90157",
  m3l1f1: "795c965da66b249e55cd9d0f73b177afea944ec6d076f81092f9657c540db6d3",
  m3l1f2: "c7e616822f366fb1b5e0756af498cc11d2c0862edcb32ca65882f622ff39de1b",
  m3l1f3: "c55edb2e0282de46e56e00d9708090d56690bda1bf2fb2daa061067ba19f60dc",
  m4l1f1: "50bac58f006cecfdbf8bc09893ee32e2bc3eaae6d5b92a6799645cc1463bf031",
  m4l1f2: "e00133bdd1fb36765d3379852981a2b2c7163f1a0cd1b826f82b516d6080d0d0",
  // anti-trace: VEH address, swallowed-int1 count of one traced selftest,
  // bypass secret released once g_AntiTraceEnabled is eb'd to 0
  m5l1f1: "7e42f0651ea88cf8aef7cfcc06130640bd22f4510142ec56ec163cbbaf1f0896",
  m5l1f2: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  m5l1f3: "9c852c785adf33aa647e451ae74e177c62eb37c4637b1a97949a7aa06ae059e7",
};

export const module1 = {
  id: "m1",
  title: "Windows Kernel Fundamentals & Kernel Manual Mapping",
  track: "windows-kernel",
  summary:
    "x64 kernel internals on a real dump-anchored emulated kernel: EPROCESS walking, " +
    "process hiding, then write and manually map your first drivers in ntsim.",
  lessons: [
    {
      id: "m1.l1",
      title: "The x64 kernel landscape",
      body: m1l1Body,
      requires: [],
      labs: [
        {
          id: "m1.l1.lab1",
          kind: "windbg",
          title: "First contact: inspect the live process list",
          brief:
            "Boot ntsim, open the debugger and enumerate processes and loaded modules. " +
            "One module in the list is not part of Windows.",
          scenario: "boot-default",
          flags: [
            {
              id: "m1.l1.f1",
              sha256: F.m1l1f1,
              prompt:
                "Run `lm` in the debugger. One loaded module's name is not a real Windows " +
                "module. Submit that exact file name (including the .sys extension).",
              points: 100,
            },
            {
              id: "m1.l1.f2",
              sha256: F.m1l1f2,
              prompt:
                "Use !process 0 0 to list processes. What is the decimal PID (the Cid) of " +
                "the process named kfsample.exe? Submit just the number.",
              points: 100,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l2",
      title: "EPROCESS walking & process hiding",
      body: m1l2Body,
      requires: ["m1.l1"],
      labs: [
        {
          id: "m1.l2.lab1",
          kind: "compiler",
          title: "Write your first driver: DKOM process hiding",
          brief:
            "Compile a driver that walks PsActiveProcessHead via the real dump-anchored " +
            "EPROCESS list and unlinks a target PID. Load it in ntsim and verify in the debugger.",
          scenario: "dkom-hide",
          starterFiles: [
            { path: "driver/dkomsample.c", content: "" }, // filled by lab runtime
            { path: "driver/ntddk_subset.h", content: "" },
            { path: "Makefile", content: "" },
          ],
          flags: [
            {
              id: "m1.l2.f1",
              sha256: F.m1l2f1,
              prompt:
                "After loading your driver, !process 0 0 no longer shows kftarget.exe. " +
                "What _LIST_ENTRY address did your driver overwrite (from the DbgPrint " +
                "output)? Submit the full hex value with 0x prefix, e.g. 0xffff000000000000.",
              points: 250,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l3",
      title: "Kernel manual mapping",
      body: m1l3Body,
      requires: ["m1.l2"],
      labs: [
        {
          id: "m1.l3.lab1",
          kind: "ntsim",
          title: "Map a PE into kernel space yourself",
          brief:
            "The provided loader driver maps an arbitrary PE you supply — but its import " +
            "resolution is stubbed. Fix the mapping logic so the payload driver resolves its " +
            "imports against nt! and runs.",
          scenario: "manual-map",
          flags: [
            {
              id: "m1.l3.f1",
              sha256: F.m1l3f1,
              prompt:
                "When your mapped payload runs it DbgPrints a secret string (see !analyze -v). " +
                "Submit that secret string exactly.",
              points: 400,
            },
          ],
        },
      ],
    },
  ],
};

export const module2 = {
  id: "m2",
  title: "IRQL & Deferred Procedures",
  track: "windows-kernel",
  summary:
    "The interrupt priority ladder that governs everything a driver may do, and the " +
    "deferred-procedure machinery that breaks when a driver abuses it.",
  lessons: [
    {
      id: "m2.l1",
      title: "IRQL & deferred procedure calls",
      body: m2l1Body,
      requires: ["m1.l3"],
      labs: [
        {
          id: "m2.l1.lab1",
          kind: "windbg",
          title: "Free the pinned processor",
          brief:
            "kfdpc.sys raised the IRQL during init and never lowered it. A DPC is stranded " +
            "in the per-CPU queue. Read the stuck level, record the DPC's routine address, " +
            "repair, drain.",
          scenario: "irql-dpc",
          flags: [
            {
              id: "m2.l1.f1",
              sha256: F.m2l1f1,
              prompt:
                "!irql shows the processor stuck at a level no thread should sit at. " +
                "Submit that IRQL as a decimal number.",
              points: 100,
            },
            {
              id: "m2.l1.f2",
              sha256: F.m2l1f2,
              prompt:
                "!dpcs shows exactly one queued-but-not-drained DPC. Submit its " +
                "DeferredRoutine address as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m2.l1.f3",
              sha256: F.m2l1f3,
              prompt:
                "Repair the level (!irql 2), drain the queue (!dpcdrain), and read the secret " +
                "the deferred routine DbgPrints (!analyze -v). Submit it exactly.",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const module3 = {
  id: "m3",
  title: "Inline Hooks & Control Flow",
  track: "windows-kernel",
  summary:
    "Function prologues rewritten under the kernel's feet: find the detour, understand " +
    "what it suppresses, restore honest control flow.",
  lessons: [
    {
      id: "m3.l1",
      title: "Inline hooks & control flow",
      body: m3l1Body,
      requires: ["m2.l1"],
      labs: [
        {
          id: "m3.l1.lab1",
          kind: "windbg",
          title: "Unhook PsLookupProcessByProcessId",
          brief:
            "kfhook.sys detoured one executive export to make one process invisible to " +
            "lookup. Scan for the detour, identify the hidden PID, repair the prologue, prove it.",
          scenario: "api-hook",
          flags: [
            {
              id: "m3.l1.f1",
              sha256: F.m3l1f1,
              prompt:
                "!hookscan finds exactly one detoured nt! export. Which routine is it? " +
                "Submit the exact export name.",
              points: 150,
            },
            {
              id: "m3.l1.f2",
              sha256: F.m3l1f2,
              prompt:
                "The hook suppresses lookups for exactly one PID (probe with !hooktest). " +
                "Submit that decimal PID.",
              points: 100,
            },
            {
              id: "m3.l1.f3",
              sha256: F.m3l1f3,
              prompt:
                "Restore the original prologue bytes shown by !hookscan (use eb), then run " +
                "!hooktest on the same lookup. Which symbolic NTSTATUS comes back now? " +
                "Submit its name, e.g. STATUS_ACCESS_DENIED style.",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const module4 = {
  id: "m4",
  title: "Pool Internals & Corruption",
  track: "windows-kernel",
  summary:
    "Pool tags, guard patterns and the forensic trail an out-of-bounds write leaves " +
    "before anything crashes.",
  lessons: [
    {
      id: "m4.l1",
      title: "Pool internals & corruption forensics",
      body: m4l1Body,
      requires: ["m3.l1"],
      labs: [
        {
          id: "m4.l1.lab1",
          kind: "windbg",
          title: "Catch the overflow before it crashes",
          brief:
            "kfpooler.sys manages tagged KfPb blocks; an upstream overflow already smashed " +
            "one trailing guard. Find the block, repair the guard, let the integrity pass finish.",
          scenario: "pool-corrupt",
          flags: [
            {
              id: "m4.l1.f1",
              sha256: F.m4l1f1,
              prompt:
                "!poolfind KfPb lists three allocations; exactly one has a corrupted guard. " +
                "Submit that block's user address as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m4.l1.f2",
              sha256: F.m4l1f2,
              prompt:
                "Rewrite the smashed guard bytes shown by !poolfind (eb), confirm with " +
                "!poolverify, and read the checksum secret kfpooler DbgPrints. Submit it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module5 = {
  id: "m5",
  title: "Tracing & Anti-Tracing",
  track: "windows-kernel",
  summary:
    "The trap flag as both scalpel and tripwire: hardware single-stepping, " +
    "pushfq/popfq detection, TF injection into vectored handlers, and the " +
    "mov-ss stall that keeps snapshots honest.",
  lessons: [
    {
      id: "m5.l1",
      title: "Tracing & anti-tracing",
      body: m5l1Body,
      requires: ["m4.l1"],
      labs: [
        {
          id: "m5.l1.lab1",
          kind: "windbg",
          title: "Walk the trap-flag gauntlet",
          brief:
            "kftrace.sys guards a payload secret behind CPU-level tripwires. " +
            "Map them, validate every check under a simulated tracer, then " +
            "neutralize the gate and take the secret.",
          scenario: "anti-trace",
          flags: [
            {
              id: "m5.l1.f1",
              sha256: F.m5l1f1,
              prompt:
                "!traceinfo shows kftrace's registered vectored exception " +
                "handler (kftrace!TraceVeh). Submit its address as full " +
                "16-digit hex with 0x prefix.",
              points: 100,
            },
            {
              id: "m5.l1.f2",
              sha256: F.m5l1f2,
              prompt:
                "Attach the simulated tracer (!trace on) and run !selftest " +
                "exactly once. Every EXCEPTION_SINGLE_STEP the driver raises " +
                "is intercepted before TraceVeh sees one. Submit how many " +
                "events were swallowed by the tracer (decimal number).",
              points: 150,
            },
            {
              id: "m5.l1.f3",
              sha256: F.m5l1f3,
              prompt:
                "Detach (!trace off), clear g_AntiTraceEnabled with eb at the " +
                "address from !traceinfo, rerun !selftest until the verdict " +
                "is CLEAN and the secret DbgPrints. Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

export const catalog = {
  version: 2,
  modules: [module1, module2, module3, module4, module5],
};
