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
 * Blog-labs v4 worlds run on LOW-memory bases (unicorn-parity; see
 * apps/web/src/scenarios.js LOW_BASES):
 *   - paging-walk: kftarget real DTB 0x0000000003005000 (decoy owns the
 *     lowest frames), code VA 0x4a1cca43000, PTE alias 0x0000078250e65218
 *   - edr-sensor: kfalcon.sys @ 0x50100000, callback 0x50101000
 *   - ssdt-hook: kfvillain.sys @ 0x5200000, detour target 0x5201000
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
import m14l1Body from "./lessons/m14-l1.mjs";
import m15l1Body from "./lessons/m15-l1.mjs";
import m16l1Body from "./lessons/m16-l1.mjs";

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
  // --- blog labs v4 (windows-kernel: paging / edr-sensor / ssdt) ---
  m11l1f1: "2263d82fc17e3465ea0eb2d2fe69368d8e718bb6b3a62e6aeab2ea243c7ab751", // real DTB (decoy-shuffled world)
  m11l1f2: "fa23c52d20e9bc7c8cf9b23089ffd0c5636e37292d59b3c013af8208274d3855", // code-page PTE alias VA
  m11l1f3: "f58f880c2f1b062881e17ef1e7a2b83228911184225760d88310a8c40f4c157e", // NX-repair secret
  m12l1f1: "daf0604f99e857b8db1f3199cf87664004a3f20a4e4b81e7c75c0617281b42ed", // deny NTSTATUS name
  m12l1f2: "2ba183e0287b7805bdad4926afa8481094ad547d173e20abbc34e8fd7af9d463", // sensor callback VA
  m12l1f3: "0e90786bcce8173a98e2c7054e3ea3df0a7aa8a6a6e10cb7e16c221c36f5b3d5", // telemetry-gap secret
  m13l1f1: "fecde715c8483bcf15534e4dadf2417ac1f2d82425712c7c11768a7bb727b1fb", // hooked service name
  m13l1f2: "a0459593796d340d431d65b318986f7e05bf617252c1137c7370e834c5928590", // detour target VA
  m13l1f3: "21cd32f101408104d43ab2f7cb42103425bdda667d14008899268432a0b0c46c", // clean-table secret
  // --- m14 tbm-ac (sogen usermode AC gauntlet) / m15 linux syscall hook ---
  m14l1f1: "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d", // vector count
  m14l1f2: "01e743f69a7d2bad56da5433c04e57a515e8b4e366c1ac037dde2dda9d184057", // live stats VA
  m14l1f3: "796437c4999a9e5887294d61387e8ba13077a36eaacdddb06e73336605a789c6", // godmode secret
  m15l1f1: "7a61b53701befdae0eeeffaecc73f14e20b537bb0f8b91ad7c2936dc63562b25", // __NR_kill i386
  m15l1f2: "edf12aa731ae4c1c81e79821415e7ff7a222f026c8304dac470f2e75dcf158d2", // detector secret
  m15l1f3: "5922ec30f7a92494220babe4b74d77228b75de3dbdd28d9a76da04695456e58b", // restore secret
  // --- m16 reversing the sensor (kfalcon grid + fixture pseudocode) ---
  m16l1f1: "a68b412c4282555f15546cf6e1fc42893b7e07f271557ceb021821098dd66c1b", // recovered function count
  m16l1f2: "2ba183e0287b7805bdad4926afa8481094ad547d173e20abbc34e8fd7af9d463", // callback VA
  m16l1f3: "a68b412c4282555f15546cf6e1fc42893b7e07f271557ceb021821098dd66c1b", // CreationStatus offset (decimal)
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

export const module11 = {
  id: "m11",
  title: "x64 Virtual Memory & Page Tables",
  track: "windows-kernel",
  summary:
    "Four-level translation on real PML4/PDPT/PD/PT bytes: CR3 walking, " +
    "self-map alias math, hardware PTE bits — and an EAC-style CR3 shuffle.",
  lessons: [
    {
      id: "m11.l1",
      title: "Walk the tables, heal the bit",
      body: m11l1Body,
      requires: ["m10.l1"],
      labs: [
        {
          id: "m11.l1.lab1",
          kind: "windbg",
          title: "From CR3 to a healed NX",
          brief:
            "Boot paging-walk. Identify the real DirectoryTableBase under a " +
            "shuffled decoy, compute the code page's PTE alias by hand, clear " +
            "the smashed NX bit and release the integrity secret.",
          scenario: "paging-walk",
          flags: [
            {
              id: "m11.l1.f1",
              sha256: F.m11l1f1,
              prompt:
                "!cr3 kftarget shows its DTB. The lowest frames are a decoy; " +
                "submit kftarget's REAL DirectoryTableBase as full 16-digit " +
                "hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m11.l1.f2",
              sha256: F.m11l1f2,
              prompt:
                "Split the code VA (!pte prints it) into 9-bit fields and " +
                "compute its PTE self-map alias va(s,pml4,pdpt,pd,pt*8). " +
                "Submit that VA as full 16-digit hex with 0x prefix.",
              points: 200,
            },
            {
              id: "m11.l1.f3",
              sha256: F.m11l1f3,
              prompt:
                "Clear NX (bit 63) on the code-page PTE via eb through the " +
                "alias, then !vtop the code VA. Submit the secret the " +
                "integrity pass prints.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module12 = {
  id: "m12",
  title: "Kernel Callbacks & EDR Sensors",
  track: "windows-kernel",
  summary:
    "Falcon-style process-creation telemetry with real callback machine " +
    "code: enumerate the sensor, read its CreationStatus kill switch, blind it.",
  lessons: [
    {
      id: "m12.l1",
      title: "Inside the mini-Falcon",
      body: m12l1Body,
      requires: ["m11.l1"],
      labs: [
        {
          id: "m12.l1.lab1",
          kind: "windbg",
          title: "Blind the process-create sensor",
          brief:
            "kfalcon.sys blocks kfimplant.exe spawns. Enumerate callbacks, " +
            "trigger the block, locate the name-compare immediates in the " +
            "callback body, patch one byte so the implant slips through.",
          scenario: "edr-sensor",
          flags: [
            {
              id: "m12.l1.f1",
              sha256: F.m12l1f1,
              prompt:
                "!notifytest kfimplant.exe gets blocked. Which symbolic " +
                "NTSTATUS lands in CreationStatus? Submit its name, e.g. " +
                "STATUS_ACCESS_DENIED style.",
              points: 100,
            },
            {
              id: "m12.l1.f2",
              sha256: F.m12l1f2,
              prompt:
                "!notifyroutines lists the registered Ex callback. Submit " +
                "its VA as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m12.l1.f3",
              sha256: F.m12l1f3,
              prompt:
                "Patch one immediate of the name compare (eb) so the " +
                "callback can never match, rerun !notifytest, and submit " +
                "the telemetry-gap secret from !analyze -v.",
              points: 300,
            },
          ],
        },
      ],
    },
  ],
};

export const module13 = {
  id: "m13",
  title: "SSDT & Syscall Hooking",
  track: "windows-kernel",
  summary:
    "A modeled KiServiceTable over real thunks: scan for the inline-detoured " +
    "service, resolve its rel32 target, repair, and re-scan until clean.",
  lessons: [
    {
      id: "m13.l1",
      title: "Clean the service table",
      body: m13l1Body,
      requires: ["m12.l1"],
      labs: [
        {
          id: "m13.l1.lab1",
          kind: "windbg",
          title: "Find and repair the detoured service",
          brief:
            "kfvillain.sys detoured one KiServiceTable entry to hide pid " +
            "666. Scan the table, resolve the E9 target, restore the " +
            "prologue, prove the lookup succeeds.",
          scenario: "ssdt-hook",
          flags: [
            {
              id: "m13.l1.f1",
              sha256: F.m13l1f1,
              prompt:
                "!ssdt marks exactly one HOOKED service. Submit its export " +
                "name exactly (e.g. NtOpenProcess style).",
              points: 100,
            },
            {
              id: "m13.l1.f2",
              sha256: F.m13l1f2,
              prompt:
                "Resolve the detour: target = site + 5 + rel32 (!ssdt " +
                "prints it). Submit the kfvillain.sys VA as full 16-digit " +
                "hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m13.l1.f3",
              sha256: F.m13l1f3,
              prompt:
                "Restore the pristine prologue with eb, re-run !ssdt until " +
                "it reports clean, and submit the secret kfvillain prints " +
                "(see !analyze -v).",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module14 = {
  id: "m14",
  title: "Userland Anti-Cheat Bypass Gauntlet",
  track: "windows-userland",
  summary:
    "A TryBypassMe-style ring-3 gauntlet: blacklists, PEB debugger artifacts, " +
    "XOR-encrypted stats with shadow canaries — reach godmode without a tick.",
  lessons: [
    {
      id: "m14.l1",
      title: "Quiet the five vectors",
      body: m14l1Body,
      requires: ["m13.l1"],
      labs: [
        {
          id: "m14.l1.lab1",
          kind: "sogen",
          title: "Reach godmode cleanly",
          brief:
            "!actrace the vector set, spoof blacklists, clear debug artifacts, " +
            "raise stats through the game API and pass !godmode.",
          scenario: "tbm-ac",
          flags: [
            {
              id: "m14.l1.f1",
              sha256: F.m14l1f1,
              prompt: "!actrace lists how many detection vectors? Submit the decimal count.",
              points: 100,
            },
            {
              id: "m14.l1.f2",
              sha256: F.m14l1f2,
              prompt:
                "The live (encrypted) stats block sits at a fixed VA. Submit it as " +
                "full 8-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m14.l1.f3",
              sha256: F.m14l1f3,
              prompt:
                "With every vector quiet and god-tier stats set via !setstat, " +
                "!godmode prints a secret. Submit it exactly.",
              points: 300,
            },
          ],
        },
      ],
    },
  ],
};

export const module15 = {
  id: "m15",
  title: "Linux Syscall-Table Rootkits",
  track: "linux-kernel",
  summary:
    "kfhooksy.ko rewrote one sys_call_table entry in the v86 guest; write the " +
    "kallsyms cross-checker that catches it and make the villain restore.",
  lessons: [
    {
      id: "m15.l1",
      title: "Cross-check the dispatch table",
      body: m15l1Body,
      requires: ["m14.l1"],
      labs: [
        {
          id: "m15.l1.lab1",
          kind: "linux",
          title: "Catch the hooked syscall",
          brief:
            "Resolve __NR_kill for i386, build a detector module comparing " +
            "sys_call_table entries against kallsyms symbol bounds, then call " +
            "the exported restore path.",
          scenario: "syscall-hook",
          flags: [
            {
              id: "m15.l1.f1",
              sha256: F.m15l1f1,
              prompt:
                "Submit __NR_kill's decimal syscall number on i386 (frozen ABI).",
              points: 100,
            },
            {
              id: "m15.l1.f2",
              sha256: F.m15l1f2,
              prompt:
                "Your detector prints a KFFLAG secret when it finds the entry " +
                "outside core-kernel text. Submit it exactly.",
              points: 250,
            },
            {
              id: "m15.l1.f3",
              sha256: F.m15l1f3,
              prompt:
                "After kfhooksy_restore() re-runs your clean sweep, the villain " +
                "surrenders with a final secret. Submit it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module16 = {
  id: "m16",
  title: "Reversing the Sensor Statically",
  track: "reversing",
  summary:
    "Boundary recovery, rel32 resolution and fixture-shaped pseudocode over " +
    "kfalcon.sys — read the kill switch without executing a single byte.",
  lessons: [
    {
      id: "m16.l1",
      title: "Pseudocode from bytes",
      body: m16l1Body,
      requires: ["m15.l1"],
      labs: [
        {
          id: "m16.l1.lab1",
          kind: "windbg",
          title: "Decompile the CreationStatus store",
          brief:
            "!funcs recovers kfalcon.sys's grid; !pseudocode renders the " +
            "process callback as C. Name the count, the callback, the offset.",
          scenario: "edr-sensor",
          flags: [
            {
              id: "m16.l1.f1",
              sha256: F.m16l1f1,
              prompt:
                "!funcs kfalcon.sys recovers how many functions from the .text " +
                "grid? Submit the decimal count.",
              points: 150,
            },
            {
              id: "m16.l1.f2",
              sha256: F.m16l1f2,
              prompt:
                "Submit the registered process-callback VA (!notifyroutines) as " +
                "full 16-digit hex with 0x prefix.",
              points: 200,
            },
            {
              id: "m16.l1.f3",
              sha256: F.m16l1f3,
              prompt:
                "!pseudocode shows the CreationStatus store at CreateInfo+0x40. " +
                "Submit that field offset in DECIMAL.",
              points: 250,
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
    module11, module12, module13, module14, module15, module16],
};
