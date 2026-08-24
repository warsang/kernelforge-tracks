// Flag hashes below are PRECOMPUTED constants (browser-safe: no env vars at
// runtime). They were generated with sha256Hex/node:crypto and can be
// re-verified with it; plaintexts live only in instructor notes.
// Deterministic addresses verified against the 22h2 table set.
const F = {
  m1l1f1: "c35475b641ba918f21483056fa66919e4e74c0ddfd95566bd1ecb6585b668ee5",
  m1l1f2: "ab391e94ef0403e84deecf24fb047c898707b9bf3ae4277bbebd700f956fb3f6",
  // kftarget.exe _EPROCESS is fixed by populateFromDump() at 0xffffc80000001000
  // and ActiveProcessLinks sits at +0x448 (22h2 tables) => FLAG{0xffffc80000001448}
  m1l2f1: "5fa613ee4f6e78eb7290ac926ec488e35938125c2bd63ca4eca7c07c3352139b",
  m1l3f1: "755e49d01807e882a7a23f553ee908ea9ab7d8111dffd21a9033adb963731b15",
};
export const module1 = {
  id: "m1",
  title: "Windows Kernel Fundamentals & Kernel Manual Mapping",
  track: "windows-kernel",
  summary:
    "x64 kernel internals on a real dump-anchored emulated kernel: EPROCESS walking, " +
    "pool internals, IRQL, then write and manually map your first drivers in ntsim.",
  lessons: [
    {
      id: "m1.l1",
      title: "The x64 kernel landscape",
      body: "./lessons/m1-l1.mdx",
      requires: [],
      labs: [
        {
          id: "m1.l1.lab1",
          kind: "windbg",
          title: "First contact: inspect the live process list",
          brief:
            "Boot ntsim, open the debugger and enumerate all processes. The scenario has " +
            "stashed a flag string in the FullImageName of a suspicious driver entry.",
          scenario: "boot-default",
          flags: [
            {
              id: "m1.l1.f1",
              sha256: F.m1l1f1,
              prompt:
                "Run `lm` in the debugger. One loaded module's name is not a real Windows " +
                "module — submit FLAG{that_module_name}.",
              points: 100,
            },
            {
              id: "m1.l1.f2",
              sha256: F.m1l1f2,
              prompt:
                "Use !process 0 0 to list processes. Submit FLAG{pid_of_the_process_named_" +
                "kfsample} (decimal).",
              points: 100,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l2",
      title: "EPROCESS walking & process hiding",
      body: "./lessons/m1-l2.mdx",
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
                "Submit the address of the _LIST_ENTRY you overwrote (from DbgPrint output), " +
                "as FLAG{0x...}.",
              points: 250,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l3",
      title: "Kernel manual mapping",
      body: "./lessons/m1-l3.mdx",
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
                "When your mapped payload runs it DbgPrints a secret. Capture it with the " +
                "debugger's DbgPrint buffer and submit it.",
              points: 400,
            },
          ],
        },
      ],
    },
  ],
};

export const catalog = {
  version: 1,
  modules: [module1],
};
