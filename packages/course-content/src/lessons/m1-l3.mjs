/** Lesson body: m1.l3 — Kernel manual mapping (markdown). */
export default `## Why manual mapping exists

Loading a driver the normal way (\`ZwLoadDriver\`) leaves traces everywhere:
registry keys, a \`_KLDR_DATA_TABLE_ENTRY\`, an image-load notification to
every registered callback. **Manual mapping** skips the loader: read the PE
yourself, copy sections into kernel memory, apply relocations, resolve
imports, call the entry point. What the OS never loaded, the OS does not know
about.

## The four jobs of any mapper

1. **Section copy** — map RVA-addressed sections to their virtual layout.
2. **Relocations** — patch absolute addresses when the image did not land at
   its preferred \`ImageBase\` (\`IMAGE_REL_BASED_DIR64\` on x64).
3. **Import resolution** — walk the import directory, look each name up
   against \`nt!\` exports, and write the resolved function pointers into the
   IAT.
4. **Entry point** — call \`DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)\`.

## The lab

The world ships \`kfloader.sys\`, a mapper whose **step 3 is stubbed**: a
config flag \`g_ResolveImports\` is zeroed, so the payload's IAT stays empty
and its entry point never runs.

Inspect, repair, execute:

\`\`\`
kd> !mmstate          # loader state: stubbed flag + unresolved IAT slots
kd> eb <addr> 01      # set g_ResolveImports = 1 (address shown by !mmstate)
kd> !mmrun            # re-run the map: imports resolve, payload starts
kd> !analyze -v       # read the payload's DbgPrint secret
\`\`\`

When the payload finally runs it calls \`DbgPrint\` with a secret string.
Submit that secret as your answer.

## Custom debugger extensions in this lab

Both commands below are **lab extensions** — they do not exist in real WinDbg;
we added them so the modeled loader is inspectable:

- \`!mmstate [n]\` — dumps the manual-map loader's private state: payload base,
  the decision byte \`g_ResolveImports\`, and every IAT slot with its resolved
  (or zeroed) target. A driver achieves the same by keeping its own mapping
  journal — or by being the EDR that watches for the *symptoms* below.
- \`!mmrun\` — re-runs the modeled map. There is no honest driver equivalent
  of "run someone else's mapper"; what defenders do instead is detect that a
  map *happened*, which is exactly your next sensor's job.

**What a driver does instead** — catch the load event the mapper tried to
skip. Legitimate loads raise callbacks; manually mapped code raises nothing,
which is precisely its fingerprint:

\`\`\`c
// Image-load telemetry: every legit driver/EXE/DLL load passes here.
// Manual-mapped images NEVER do — absence of evidence becomes evidence.
VOID ImageNotifyCb(PUNICODE_STRING imageName, HANDLE pid,
                   PIMAGE_INFO info)
{
    if (info->SystemModeImage) {
        DbgPrint("sensor: kernel image %wZ at %p size=%lx\\n",
                 imageName, info->ImageBase, info->SizeOfImage);
        // production: correlate against a signed allow-list; an executable
        // kernel page range you never saw here is unbacked code
    }
}

NTSTATUS StartImageTelemetry(void)
{
    return PsSetLoadImageNotifyRoutine(ImageNotifyCb);
}
\`\`\`

Pair that callback stream with a periodic scan of executable memory ranges
that no \`lm\` entry covers (you will build this in m1.l4) and the mapper's
payload lights up even though it "was never loaded".

## Reading someone else's mapper

Notice what the debugger shows you about *mechanism* rather than outcome:
which IAT slot maps to which export, where the resolver's decision byte lives.
This is the same reading you would do of a real implant's mapper — and the
same mental model EDR memory scanners use when they hunt for images that are
executable, backed by pool, and absent from the module list.

## Defensive framing

Unbacked executable memory, VAD entries without corresponding module entries
(\`dt nt!_MMVAD_SHORT\` now walks the descriptor: StartingVpn/EndingVpn give
you the range; no matching \`(un)linked\` entry gives you the verdict), and
call stacks that cross from pool into ntoskrnl are the classic tells of
manually mapped code.

Modern Windows adds structural defenses on top of detection:

- **HVCI (hypervisor-protected code integrity)** keeps kernel pages W^X —
  self-modifying loaders and RWX payloads fail allocation outright.
- **Arbitrary code guard / restricted kernel** policies block common
  write-what-where primitives that mappers use to bootstrap.
- **Signed-driver requirements (DSE)** push attackers toward abusing
  legitimately signed but vulnerable drivers (BYOVD) — that is where this
  course's later tracks go.

Detection still matters because policy can be bypassed; the m1.l4 Sentinel
sensor adds the unbacked-executable classifier to your growing EDR.
`;
