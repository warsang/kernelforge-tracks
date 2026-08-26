/** Lesson body: m24.l1 — ELF anatomy & forensics (linux-internals track).
 *  Sources: tmpout v4 deluks (symbols / program headers), v5 dominikr (execve
 *  deep dive), v1 xcellerator (Dead Bytes), v3 g1inko (Weird ELFs),
 *  v5 h4x.cz (57-byte ELF). Fixture: apps/web/public/fixtures/elf/hello.elf */
export default `## The format everything on Linux executes

Every binary you will ever hook, infect or emulate starts with \`\\x7fELF\`.
This module dissects a real x86-64 executable — our [\`hello.elf\`](/fixtures/elf/hello.elf)
fixture — with an in-browser inspector instead of readelf.

### Elf64_Ehdr — the 64-byte contract

\`\`\`
elf> ehdr
  e_type         ET_EXEC (2)        e_machine   EM_X86_64 (0x3e)
  e_entry        0x400100           e_phoff     0x40
  e_shoff        0x2f8              e_phentsize 0x38
  e_phnum        3                  e_shnum     6
\`\`\`

The kernel's loader (\`fs/binfmt_elf.c\`, walked in detail by dominikr,
tmp.0ut #5) checks remarkably little of it: the \`\\x7fELF\` magic as a raw
byte compare, \`e_type ∈ {ET_EXEC, ET_DYN}\`, \`e_machine == EM_X86_64\`,
\`e_phentsize == 0x38\`, and \`0 < e_phnum·e_phentsize ≤ 65536\`.
**EI_CLASS, EI_DATA, EI_VERSION and OSABI are never validated** — xcellerator's
"Dead Bytes" (tmp.0ut #1) catalogues which header bytes are dead weight.
The gap between what \`readelf\` demands and what the kernel accepts IS the
anti-analysis surface the rest of this track lives in.

### Program headers vs section headers

Program headers describe **segments** — what gets mmap'd. Section headers
describe **linker/bookkeeping views** and are optional for execution:

| Phdr | role |
|---|---|
| \`PT_LOAD\` | map \`[p_offset, p_offset+p_filesz)\` at \`p_vaddr\`, zero-fill to \`p_memsz\` |
| \`PT_DYNAMIC\` | pointer to \`.dynamic\` for the runtime linker |
| \`PT_INTERP\` | path of ld.so (\`2 ≤ p_filesz ≤ PATH_MAX\` else ENOENT) |
| \`PT_NOTE\` | ABI metadata — *may be ignored per spec* (remember that) |

The congruence rule \`p_vaddr ≡ p_offset (mod p_align)\` is why segment file
offsets look "aligned" — violate it and your mapping slides by the delta.

### Symbols

An \`Elf64_Sym\` is 24 bytes: \`st_name\` (strtab offset), \`st_info\`
(high nibble = binding LOCAL/GLOBAL/WEAK, low nibble = type OBJECT/FUNC),
\`st_shndx\`, \`st_value\`, \`st_size\`. deluks' two tmp.0ut #4 articles are
the gentle introduction; our fixture ships \`_start\`, \`kf_greet\` and an
OBJECT called \`secret_msg\`.

## Lab 1 — dissect hello.elf (hands-on)

Boot the lab, then drive the inspector:

\`\`\`
elf> info          # loader-view PASS/FAIL lines + anomaly count
elf> phdr          # find the PT_LOAD covering .text
elf> shdr          # .text file offset -> flag 2
elf> sym           # kf_greet's st_value -> flag 3
elf> hex 0x100 32  # watch the mov rax,1/write syscall prologue
elf> note          # anomaly report (clean here — enjoy it while it lasts)
\`\`\`

## Weird ELFs and tiny ones

g1inko (tmp.0ut #3) breaks strict parsers with corrupted SHTs; the System V
ABI itself defines **extended numbering**: when \`e_shnum == 0\` but
\`e_shoff != 0\`, the real count hides in \`shdr[0].sh_size\`; when
\`e_shstrndx == SHN_XINDEX (0xffff)\`, the real index sits in
\`shdr[0].sh_link\`. Our \`weird.elf\` fixture uses both plus a past-EOF
section and a zero-\`entsize\` symtab trap — the inspector survives all four;
many tools do not.

h4x.cz (tmp.0ut #5) builds a **57-byte** ELF: magic-only \`e_ident\`, the
Phdr aliasing the Ehdr at \`e_phoff = 0\` (its \`p_type\` reads back as the
magic dword \`0x464c457f\` — an unrecognized type the kernel's loop simply
skips), trailing fields elided because the kernel zero-pads its 256-byte
\`bprm->buf\`. Module m26 dissects that one hands-on.

## Flags

Lab 1: hello's \`e_entry\` (0x-hex); the **decimal** file offset of the
\`.text\` section; \`kf_greet\`'s \`st_value\` (0x-hex). Lab 2: ELF64's
\`e_phentsize\` (decimal); which \`e_ident\` member records endianness; the
compat-binfmt \`e_phentsize\` (0x-hex).
`;
