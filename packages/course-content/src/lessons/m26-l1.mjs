/** Lesson body: m26.l1 — fileless & memory-resident execution.
 *  Sources: tmpout v1 netspooky (in-memory LKM), v2 ulexec (SHELF in Chrome),
 *  v3 isra (fd-less Perl exec), v5 TMZ (halfexec/halfshelf/phork trilogy),
 *  v4 gynvael (FixedASLR .o loader). Fixture:
 *  apps/web/public/fixtures/elf/tiny.elf */
export default `## Execution without an executable

The execve family leaves footprints: a path on disk, a new process, audit
records. The tmp.0ut corpus keeps shrinking that footprint until nothing is
left but memory.

### memfd + finit_module: LKMs from thin air

netspooky's in-memory loader (tmp.0ut #1) pulls a \`\.ko\` over a socket and
loads it without touching disk: \`memfd_create("BANG")\` (x86-64 syscall
**319**) yields an anonymous fd, bytes get written into it, and
\`finit_module(fd, ..., flags)\` (**313**) loads the module *from the
descriptor*. The flags are the interesting part: \`MODULE_INIT_IGNORE_MODVERSIONS = 1\`
and \`MODULE_INIT_IGNORE_VERMAGIC = 2\` skip integrity metadata — but only
when the kernel was built with \`CONFIG_MODULE_FORCE_LOAD\`, otherwise you
collect ENOEXEC.

### SHELF: reflective payloads with no execve at all

SHELF (ulexec & \\_Anonymous\\_, tmp.0ut #1; field-tested in Chrome by ulexec,
#2) is a **static PIE with exactly one PT_LOAD** (\`p_offset == 0\`,
\`p_vaddr == 0\`) whose headers are stripped after linking. Deployment maps
the image reflectively — ulexec sprayed WASM pages for RWX space inside a
renderer exploited via CVE-2020-6418, hand-built an auxv
(\`AT_PHDR/AT_PHNUM/AT_ENTRY/AT_RANDOM/...\`) on the stack and jumped to the
entry: **no execve-family call ever happens**, so no process-tree artifact.

TMZ's half-loader trilogy (#5) turns that idea into tooling:

| tool | scope |
|---|---|
| \`halfexec\` | userspace re-execution of ET_EXEC + ET_DYN incl. PT_INTERP handoff, TLS via \`arch_prctl(ARCH_SET_FS)\`, rebuilt auxv |
| \`halfshelf\` | narrow SHELF loader; \`headshelf\` variant rebuilds the image from a stripped blob plus sidecar metadata (\`SHELFBN1\`: magic + 17×u64 + phdr blob); memfd is transport only — "no fexecve, no execveat" |
| \`phork\` | packs it all back: \`[stub][SHELFBN1][payload][SPACK01! footer]\`, self-reads via \`/proc/self/exe\`, RLE+XOR-0xA5 layers |

isra (#3) goes **fd-less** from Perl: mmap/mprotect via raw syscalls
(**9** and **10**), relocations applied by hand, externals resolved through
\`DynaLoader\` — because memfd+fexecve still shows fds under /proc.

### Why the kernel tolerates degenerate headers

dominikr's loader walk (m24) explains h4x.cz's **57-byte ELF**: binfmt_elf
zero-pads its header buffer, never validates \`EI_*\`, and skips unrecognized
phdr types — so a file whose Phdr aliases its own Ehdr (\`e_phoff = 0\`,
\`p_type\` reading back as the magic \`0x464c457f\`) sails through.
Our \`tiny.elf\` fixture reproduces exactly that construction.

## Lab 1 — fifty-seven bytes (hands-on)

Boot the \`elf-tiny\` scenario:

\`\`\`
elf> info      # ehdr extends past EOF: fields decode as zero-padded
elf> phdr      # ONE phdr... whose p_type IS the ELF magic
elf> hex 0 64
elf> note
\`\`\`

Flags: \`e_phoff\`; the nominal \`p_type\` of that aliased phdr (0x-hex);
the file size in decimal.

## Lab 2 — the fileless toolbox (quiz)

Answers live in the syscall table and the articles above.

## Flags

Lab 1: tiny's \`e_phoff\` value; aliased phdr's \`p_type\` as 0x-hex; total
file size (decimal). Lab 2: \`finit_module\`'s x86-64 number; 
\`memfd_create\`'s x86-64 number; which syscall family SHELF avoids entirely.
`;
