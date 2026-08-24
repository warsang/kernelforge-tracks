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
\`\`\`

When the payload finally runs it calls \`DbgPrint\` with a secret string.
Read it from the DbgPrint buffer:

\`\`\`
kd> !analyze -v       # prints recent DbgPrint lines
\`\`\`

Submit that secret as your answer.

## Reading someone else's mapper

Notice what the debugger shows you about *mechanism* rather than outcome:
which IAT slot maps to which export, where the resolver's decision byte lives.
This is the same reading you would do of a real implant's mapper — and the
same mental model EDR memory scanners use when they hunt for images that are
executable, backed by pool, and absent from the module list.

## Defensive framing

Unbacked executable memory, VAD entries without corresponding \`(un)linked\`
module entries, and call stacks that cross from pool into ntoskrnl are the
classic tells of manually mapped code. Modern Windows adds HVCI and
arbitrary-code-guard style policies that make user-style RWX mapping in
kernel painful — which is why attackers increasingly target signed loaders
instead (that is a later module).
`;
