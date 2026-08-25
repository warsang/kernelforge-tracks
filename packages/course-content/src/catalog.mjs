/**
 * Course catalog v3 — Modules 1-4 (windows-kernel track), 5-6 (windows-userland
 * sogen track), 7-9 (linux-kernel v86 track). m10 (reversing/ghidra) joins in
 * the M3 milestone once the static-analysis engine lands.
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
 * Userland worlds (packages/sogen-runtime reference backend):
 *   - sauer-recon: sauerbraten.exe base 0x00400000, entity array at
 *     0x02100040, local player index 3 => VA 0x021000d0, health +0x24
 *   - sauer-hook: cl_sendinput at 0x004532a0, cheat stub at 0x0046f010
 */
import m1l1Body from "./lessons/m1-l1.mjs";
import m1l2Body from "./lessons/m1-l2.mjs";
import m1l3Body from "./lessons/m1-l3.mjs";
import m2l1Body from "./lessons/m2-l1.mjs";
import m3l1Body from "./lessons/m3-l1.mjs";
import m4l1Body from "./lessons/m4-l1.mjs";
import m5l1Body from "./lessons/m5-l1.mjs";
import m6l1Body from "./lessons/m6-l1.mjs";
import m7l1Body from "./lessons/m7-l1.mjs";
import m8l1Body from "./lessons/m8-l1.mjs";
import m9l1Body from "./lessons/m9-l1.mjs";
import m10l1Body from "./lessons/m10-l1.mjs";
import m11l1Body from "./lessons/m11-l1.mjs";
import m12l1Body from "./lessons/m12-l1.mjs";
import m13l1Body from "./lessons/m13-l1.mjs";

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
  // --- windows-userland (sogen reference backend) ---
  m5l1f1: "c60c103663b60f83d7e703e9bc29f715f0f85fbafdfc93c7e8c47974b4234b88", // sauerbraten.exe base
  m5l1f2: "2dca4b7ecfdbb7cf5a40b14d27641e975bb66e4807419161dba0884efd23f729", // local player entity VA
  m5l1f3: "eb21d48944a211681df63be8d6a1a0a7a3724904bfcabda1a9b7e2f0985c3be3", // health field offset
  m6l1f1: "96fb5426e097d4f1ad8791e16d6f7c907d8ee9ba2a00fe0e299ec9857076188a", // detoured fn VA
  m6l1f2: "a38ab0ee07657cb1230654c7d2ea0849234d344222705e21dffc12e09bbd0aea", // E9 stub target VA
  m6l1f3: "578ca15def9a7b2dffd2609b50d154679c28c99cdd4b5d57a16e3384fa995d56", // inputtest secret
  // --- linux-kernel (v86 buildroot track) ---
  m7l1f1: "2747b7c718564ba5f066f0523b03e17f6a496b06851333d2d59ab6d863225848", // __NR_init_module (i386)
  m7l1f2: "4a7f740db3b813bac7d82a7b111cf73eadae8d988d30cb95476130f5a8c3aec5", // /root/.kflag secret
  m8l1f1: "4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8", // __NR_execve (i386)
  m8l1f2: "9c220b3766ff32192d40855481cf872f90cc0e9ecc4cf211f55b8a6efb2a84bc", // kprobe trace secret
  m9l1f1: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", // hidden task count
  m9l1f2: "4c368c365d47c10df5f46f7a56f46bbf2af86534cc884196e2878b34feddd0d2", // villain surrender secret
  // --- reversing (ghidra decompiler pane over the api-hook world) ---
  m10l1f1: "2747b7c718564ba5f066f0523b03e17f6a496b06851333d2d59ab6d863225848", // recovered function count (kfhook.sys grid)
  m10l1f2: "71489c0a57f4a2c1c4fd1dfdd85685d8f09a9ffe3f960f36a30191678e665e3d", // second boundary VA
  m10l1f3: "41571682d793c451794838c436413b18896cb0479575ca5ff59c160c38733537", // E9 detour target VA
  // m11: paging foundations (answers verified deterministic against the 22h2 paged boot)
  m11l1f1: "5ca025c5014c8952a23d1c125b2ee525862b64fdcf484c6dd28d180d73e5f173", // KUSER physical address via !vtop (0x101000)
  m11l1f2: "7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451", // process count in !process 0 0 (7)
  m11l1f3: "e5b564a7a4059dccb9c20cd678603a6f30c5f3db3af9b421e7f87eb37b030337", // KUSER exec class from !pte (nx)
  // m12: SMM vault exfil
  m12l1f1: "c712810a09830eb312aa0fe16773c426021e275ca28c79163e8c7e10dd24ace5", // exfiltrated secret string
  m12l1f2: "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9", // D_OPEN after D_LCK set (0)
  // m13: SMBASE relocation
  m13l1f1: "59559e557dba68f6c1bf096dcbd52ca7f6e5f2bd7ea2d8a058c5cf63204df292", // save-state SMBASE offset (0xfb04)
  m13l1f2: "513c129dfdc2aee92e26719e958855caca7d77c892d76fc576ba8efb946e2831", // planted-stub magic at landing2 (mf2k)
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
  title: "Userland Recon Under an Emulator",
  track: "windows-userland",
  summary:
    "Process-space game hacking inside a sogen-style userspace emulator: module " +
    "enumeration, memory scans, entity hunting in a headless Sauerbraten target.",
  lessons: [
    {
      id: "m5.l1",
      title: "Modules, scans & the local player",
      body: m5l1Body,
      requires: ["m4.l1"],
      labs: [
        {
          id: "m5.l1.lab1",
          kind: "sogen",
          title: "Find the local player entity",
          brief:
            "Boot the emulated Sauerbraten process, enumerate its modules, then use the " +
            "two-scan technique (with !damage as your oracle) to locate your own entity.",
          scenario: "sauer-recon",
          flags: [
            {
              id: "m5.l1.f1",
              sha256: F.m5l1f1,
              prompt:
                "Run lm in the userland console. Submit sauerbraten.exe's image base as " +
                "full 8-digit hex with 0x prefix (e.g. 0x00400000).",
              points: 100,
            },
            {
              id: "m5.l1.f2",
              sha256: F.m5l1f2,
              prompt:
                "Scan for live health values, filter with !damage + re-scan, and find the " +
                "entity whose name is kfgamer. Submit that entity's address as full " +
                "8-digit hex with 0x prefix.",
              points: 250,
            },
            {
              id: "m5.l1.f3",
              sha256: F.m5l1f3,
              prompt:
                "Using x on your entity before/after !damage, work out the health field's " +
                "offset within the entity struct. Submit it as short 0x-prefixed hex " +
                "(e.g. 0x10).",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const module6 = {
  id: "m6",
  title: "Userland Hooks & Input Flow",
  track: "windows-userland",
  summary:
    "The Module-3 detour craft applied in process space: find a cheat's inline " +
    "patch over the engine input path, resolve its trampoline, restore honest flow.",
  lessons: [
    {
      id: "m6.l1",
      title: "Detours over cl_sendinput",
      body: m6l1Body,
      requires: ["m5.l1"],
      labs: [
        {
          id: "m6.l1.lab1",
          kind: "sogen",
          title: "Unhook the input path",
          brief:
            "A cheat stub rewrote the prologue of cl_sendinput to aim-assist every packet. " +
            "hookscan it, resolve the E9 target, repair with eb, prove it with !inputtest.",
          scenario: "sauer-hook",
          flags: [
            {
              id: "m6.l1.f1",
              sha256: F.m6l1f1,
              prompt:
                "hookscan finds exactly one detoured function. Submit its VA as full " +
                "8-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m6.l1.f2",
              sha256: F.m6l1f2,
              prompt:
                "Resolve the detour: target = site + 5 + rel32 (hookscan prints both). " +
                "Submit the cheat stub's VA as full 8-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m6.l1.f3",
              sha256: F.m6l1f3,
              prompt:
                "Restore the original prologue bytes shown by hookscan (eb), confirm " +
                "hookscan is clean, then run !inputtest and submit the secret string " +
                "the honest path prints.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

export const module7 = {
  id: "m7",
  title: "Linux LKM Fundamentals",
  track: "linux-kernel",
  summary:
    "A real i386 Linux kernel booted by v86 inside the browser tab: write, ship " +
    "and load your first loadable kernel modules against a frozen syscall ABI.",
  lessons: [
    {
      id: "m7.l1",
      title: "Hello, kernel module",
      body: m7l1Body,
      requires: ["m6.l1"],
      labs: [
        {
          id: "m7.l1.lab1",
          kind: "linux",
          title: "insmod your first .ko",
          brief:
            "Compile a greeting module in the IDE tab, push it into the buildroot guest, " +
            "insmod it, and read dmesg over serial.",
          scenario: "lkm-hello",
          flags: [
            {
              id: "m7.l1.f1",
              sha256: F.m7l1f1,
              prompt:
                "Linux syscall numbers are a frozen per-arch ABI. Submit init_module's " +
                "decimal syscall number on i386.",
              points: 100,
            },
            {
              id: "m7.l1.f2",
              sha256: F.m7l1f2,
              prompt:
                "Extend your module to read /root/.kflag from kernel space and print it " +
                "with pr_info. Submit the file's secret string exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module8 = {
  id: "m8",
  title: "Syscall Internals & Tracing",
  track: "linux-kernel",
  summary:
    "The int-0x80 choke point, sys_call_table mechanics, and non-invasive " +
    "observation with kprobes — instrumentation without patching.",
  lessons: [
    {
      id: "m8.l1",
      title: "Watch the boundary with kprobes",
      body: m8l1Body,
      requires: ["m7.l1"],
      labs: [
        {
          id: "m8.l1.lab1",
          kind: "linux",
          title: "Probe execve",
          brief:
            "Register a kprobe on the program-execution syscall, trigger it with " +
            "/root/trigger in the guest, and capture your handler's output.",
          scenario: "syscall-trace",
          flags: [
            {
              id: "m8.l1.f1",
              sha256: F.m8l1f1,
              prompt:
                "Your probe must fire when programs start. Submit execve's decimal " +
                "syscall number on i386.",
              points: 100,
            },
            {
              id: "m8.l1.f2",
              sha256: F.m8l1f2,
              prompt:
                "With your kprobe registered and /root/trigger executed, submit the " +
                "secret string your handler prints.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module9 = {
  id: "m9",
  title: "Rootkits & Detection",
  track: "linux-kernel",
  summary:
    "A prebuilt villain rootkit unlinks tasks behind your back; write the " +
    "cross-accounting detector that catches it.",
  lessons: [
    {
      id: "m9.l1",
      title: "Catch the task-unlinking rootkit",
      body: m9l1Body,
      requires: ["m8.l1"],
      labs: [
        {
          id: "m9.l1.lab1",
          kind: "linux",
          title: "Detect what ps cannot see",
          brief:
            "kfvillain.ko hides decoy tasks during boot. Measure the scheduler-list vs " +
            "nr_threads discrepancy, then make the villain confess.",
          scenario: "task-hide",
          flags: [
            {
              id: "m9.l1.f1",
              sha256: F.m9l1f1,
              prompt:
                "Compare nr_threads against /proc-visible tasks with your detector " +
                "module. How many tasks are hidden? Submit the decimal count.",
              points: 200,
            },
            {
              id: "m9.l1.f2",
              sha256: F.m9l1f2,
              prompt:
                "Call the exported kfvillain_reveal() once your count is confirmed; " +
                "the villain prints its surrender secret through your completion path. " +
                "Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};



export const module10 = {
  id: "m10",
  title: "Static Analysis with Ghidra-Grade Tooling",
  track: "reversing",
  summary:
    "Function-boundary recovery and decompilation in the browser: Ghidra's " +
    "native decompiler engine as an analysis pane over live emulated worlds.",
  lessons: [
    {
      id: "m10.l1",
      title: "From bytes to functions to pseudocode",
      body: m10l1Body,
      requires: ["m9.l1"],
      labs: [
        {
          id: "m10.l1.lab1",
          kind: "windbg",
          title: "Recover control flow statically",
          brief:
            "Boot the api-hook world and analyze it without executing anything: " +
            "!funcs recovers kfhook.sys's functions; !hookscan resolves the detour.",
          scenario: "api-hook",
          flags: [
            {
              id: "m10.l1.f1",
              sha256: F.m10l1f1,
              prompt:
                "Run !funcs kfhook.sys. How many functions does the boundary scan " +
                "recover? Submit the decimal count.",
              points: 150,
            },
            {
              id: "m10.l1.f2",
              sha256: F.m10l1f2,
              prompt:
                "Submit the VA where !funcs places the SECOND recovered function, " +
                "as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m10.l1.f3",
              sha256: F.m10l1f3,
              prompt:
                "!hookscan resolves the detoured export's E9 target inside kfhook.sys. " +
                "Submit that target VA as full 16-digit hex with 0x prefix.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

// ---------------------------------------------------------------------------
// m11-m13: SMM / SMRAM track (guest paging + chipset emulation)
// ---------------------------------------------------------------------------

export const module11 = {
  id: "m11",
  title: "x64 Paging & the SMM Landscape",
  track: "smm",
  summary:
    "Boot the platform's first guest-paged kernel: walk real 4-level page " +
    "tables with !vtop/!pte/!cr, meet KUSER_SHARED_DATA's dual mapping, and " +
    "decode a Q35-style chipset whose SMRAM door was never locked.",
  lessons: [
    {
      id: "m11.l1",
      title: "Page tables you can touch, an SMI you can't mask",
      body: m11l1Body,
      requires: ["m10.l1"],
      labs: [
        {
          id: "m11.l1.lab1",
          kind: "windbg",
          title: "Walk the MMU",
          brief:
            "Boot the smm-foundations world. Use !vtop, !pte and !cr to answer " +
            "three questions about how this kernel really maps memory.",
          scenario: "smm-foundations",
          flags: [
            {
              id: "m11.l1.f1",
              sha256: F.m11l1f1,
              prompt:
                "!vtop 0xfffff78000000000 maps the kernel alias of KUSER_SHARED_DATA. " +
                "Submit the physical address it reports (0x-prefixed hex).",
              points: 150,
            },
            {
              id: "m11.l1.f2",
              sha256: F.m11l1f2,
              prompt:
                "How many processes does !process 0 0 show in this world? Submit the decimal count.",
              points: 100,
            },
            {
              id: "m11.l1.f3",
              sha256: F.m11l1f3,
              prompt:
                "!pte 0x7ffe0000 ends with the page's exec class. Is KUSER_SHARED_DATA " +
                "mapped X or NX here? Submit nx or x (lowercase).",
              points: 100,
            },
          ],
        },
      ],
    },
  ],
};

export const module12 = {
  id: "m12",
  title: "Ring-0 → SMM Escalation",
  track: "smm",
  summary:
    "Write the exploit yourself: open the unlocked SMRAM vault from ring 0, " +
    "patch the SMI handler with your own bytes, close the door behind you, " +
    "and make ring -2 exfiltrate its secrets through port 0xB2.",
  lessons: [
    {
      id: "m12.l1",
      title: "Open the vault, patch the handler, steal the secret",
      body: m12l1Body,
      requires: ["m11.l1"],
      labs: [
        {
          id: "m12.l1.lab1",
          kind: "compiler",
          title: "SMI-handler hijack for fun and exfiltration",
          brief:
            "Compile your ring-0 exploit in the IDE, load it into the smm-vault " +
            "world, and let the modeled SMI run YOUR handler below ring 0.",
          scenario: "smm-vault",
          starterFiles: [
            { path: "driver/smm_vault.c", content: "" },
            { path: "driver/ntddk_subset.h", content: "" },
            { path: "Makefile", content: "" },
          ],
          flags: [
            {
              id: "m12.l1.f1",
              sha256: F.m12l1f1,
              prompt:
                "After the SMI fires, the landing page dump shows an ASCII secret. " +
                "Submit it (lowercase, hyphens included).",
              points: 300,
            },
            {
              id: "m12.l1.f2",
              sha256: F.m12l1f2,
              prompt:
                "Finish by setting D_LCK from your driver, then run !smmc: what is " +
                "D_OPEN now? Submit 0 or 1.",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const module13 = {
  id: "m13",
  title: "SMBASE Relocation Persistence",
  track: "smm",
  summary:
    "The capstone: rewrite the save-state's SMBASE field before RSM so the " +
    "next SMI enters code YOU planted — persistence below ring 0, then lock " +
    "the door and prove your own exploit dead.",
  lessons: [
    {
      id: "m13.l1",
      title: "Relocate SMBASE, plant your stub, survive reboot-less forever",
      body: m13l1Body,
      requires: ["m12.l1"],
      labs: [
        {
          id: "m13.l1.lab1",
          kind: "compiler",
          title: "Two SMIs, one relocated CPU",
          brief:
            "Extend your vault exploit: relocate SMBASE via the save state and " +
            "plant a stub at the new base. The lab fires two SMIs; the second one " +
            "is yours.",
          scenario: "smm-reloc",
          starterFiles: [
            { path: "driver/smm_reloc.c", content: "" },
            { path: "driver/ntddk_subset.h", content: "" },
            { path: "Makefile", content: "" },
          ],
          flags: [
            {
              id: "m13.l1.f1",
              sha256: F.m13l1f1,
              prompt:
                "Which save-state offset (SMBASE-relative) holds SMBASE itself? " +
                "Submit as 0x-prefixed lowercase hex — this is the canonical anchor " +
                "from SDM Vol.3 ch.34.",
              points: 200,
            },
            {
              id: "m13.l1.f2",
              sha256: F.m13l1f2,
              prompt:
                "If relocation worked, landing #2 shows a 4-byte magic your stub wrote. " +
                "Submit that magic (lowercase).",
              points: 300,
            },
          ],
        },
      ],
    },
  ],
};

export const catalog = {
  version: 4,
  modules: [module1, module2, module3, module4, module5, module6, module7, module8, module9, module10,
    module11, module12, module13],
};
