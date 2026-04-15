# Triton eBPF Crypto Tracer — bpf/

This directory holds the eBPF C source (`crypto.c`) and its compiled
CO-RE object (`crypto.o`). The object is committed; Go code embeds it
via `//go:embed`.

## Regenerating `crypto.o`

Requires on a Linux host:
- `clang` >= 13
- Kernel headers matching the build target (`linux-headers-$(uname -r)`)
- libbpf headers (`apt install libbpf-dev` on Debian/Ubuntu)

Then from the repo root:

    make ebpf-compile

The `ebpf-compile` target auto-detects the host architecture (via `uname -m`)
and maps it to the `__TARGET_ARCH_*` macro clang expects (`x86`, `arm64`,
`powerpc`, `mips`, `s390`). It also fails fast with an actionable message
if `clang` or libbpf headers are missing, or if the host is not Linux.

The compiled object is intentionally NOT stripped: retaining BTF + debug
info yields much better kernel verifier diagnostics when probe loading
fails, and the size difference is trivial (~10 KB).

## Verification

The runtime `len(cryptoObject) == 0` guard in `program_linux.go` emits a
skipped-finding when `crypto.o` is missing or empty. A CI drift-verification
job (rebuild + diff against committed) is a tracked follow-up but not yet
implemented — contributors editing `crypto.c` MUST manually run
`make ebpf-compile` before committing to keep source and binary in sync.
