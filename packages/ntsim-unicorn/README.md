# @kernelforge/ntsim-unicorn

High-fidelity CPU backend for [ntsim](../ntsim) built on the Unicorn engine
(QEMU TCG) compiled to WebAssembly.

**JsInterpreter remains the default backend for every lab and test.** This
package is opt-in infrastructure: a ~1 MB GPLv2 wasm bundle that only loads
when a scenario explicitly asks for it.

## When to use which backend

| | JsInterpreter (default) | UnicornCpuBackend |
|---|---|---|
| Determinism / grading | pinned semantics, byte-stable forever | tied to vendored binary version |
| ISA coverage | integer subset clang emits for kernel C; unknown opcodes **fail loudly** | full x86-64 (SSE, lock cmpxchg, …) |
| Debug tooling | plain JS state, trivial snapshots/replay | state behind wasm boundary |
| Bundle cost | zero | ~1 MB wasm, lazy-loaded |

Rule of thumb: grade and teach on `js`; use `unicorn` when a scenario needs
instructions the interpreter refuses, or as a differential oracle.

## Known limitation — real kernel VAs

Unicorn ≤ 2.1.x cannot execute or access memory at canonical kernel-half VAs
(bit 63 set): with paging disabled its softmmu masks physical addresses to 52
bits ([upstream #2010](https://github.com/unicorn-engine/unicorn/issues/2010)).
ntsim's default synthetic bases (`0xffff_f800…`) therefore **fault under this
backend**. Two mitigations ship today:

1. Low-memory layouts via `new NtKernel({ cpu, bases: { … } })` — used by the
   differential suite; runs identically on both backends.
2. A guest-paging bootstrap (real PML4 page tables mapping kernel VAs → low
   physical pages, like Windows itself) is designed but not yet landed; see
   `docs/spike-unicorn.md` in the repo history for the validated approach.

## Versioning & provenance

- `vendor/unicorn_x86.cjs` is built from the **exact upstream source** at the
  pinned commit (AlexAltea/unicorn.js, unicorn core 2.1.x), emscripten 3.1.74.
- The npm dist of `@alexaltea/unicorn-js@2.1.4` is **not** used: it is stale
  (missing `_uc_ctl`) *and* marshals address parameters through f64, silently
  corrupting anything above 2^53. All address-bearing calls in this backend go
  through raw `ccall(..., 'i64', ...)` shims instead.
- Rebuild recipe lives in the repo spike notes; bump the vendored file only
  with the differential suite green.

## License

The vendored bundle embeds Unicorn/QEMU, licensed **GPLv2**. Fine for
private/internal course use; distributing the platform publicly triggers GPL
obligations on the combined work.
