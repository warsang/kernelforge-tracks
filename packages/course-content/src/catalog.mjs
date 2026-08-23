import { sha256Hex } from "./sha256.mjs";

// Synchronous on purpose: flags are hashed at module load so the catalog is
// plain static data everywhere (Node and browser). sha256Hex matches
// node:crypto's digest("hex") byte-for-byte.
const sha = sha256Hex;

/**
 * MODULE 1 — Windows Kernel Fundamentals & Manual Mapping (first vertical slice).
 * Flags below are the real ones for the shipped lab; hashes computed at module load.
 */
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
              sha256: sha(process.env.KF_FLAG_M1L1F1 ?? `FLAG{PLACEHOLDER_set_KF_FLAG_M1L1F1}`),
              prompt:
                "Run `lm` in the debugger. One loaded module's name is not a real Windows " +
                "module — submit FLAG{that_module_name}.",
              points: 100,
            },
            {
              id: "m1.l1.f2",
              sha256: sha(process.env.KF_FLAG_M1L1F2 ?? `FLAG{PLACEHOLDER_set_KF_FLAG_M1L1F2}`),
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
              sha256: sha(process.env.KF_FLAG_M1L2F1 ?? `FLAG{PLACEHOLDER_set_KF_FLAG_M1L2F1}`),
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
              sha256: sha(process.env.KF_FLAG_M1L3F1 ?? `FLAG{PLACEHOLDER_set_KF_FLAG_M1L3F1}`),
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
