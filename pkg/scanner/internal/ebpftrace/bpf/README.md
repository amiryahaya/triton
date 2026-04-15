# Triton eBPF Crypto Tracer — bpf/

This directory holds the eBPF C source (`crypto.c`) and its compiled
CO-RE object (`crypto.o`). The object is committed; Go code embeds it
via `//go:embed`.

## Regenerating `crypto.o`

Requires on a Linux host:
- `clang` >= 13
- `llvm-strip`
- Kernel headers matching the build target (`linux-headers-$(uname -r)`)
- libbpf headers (`apt install libbpf-dev` on Debian/Ubuntu)

Then from the repo root:

    make ebpf-compile

This runs:

    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
          -I pkg/scanner/internal/ebpftrace/bpf \
          -c pkg/scanner/internal/ebpftrace/bpf/crypto.c \
          -o pkg/scanner/internal/ebpftrace/bpf/crypto.o
    llvm-strip -g pkg/scanner/internal/ebpftrace/bpf/crypto.o

## CI verification

The `ebpf-verify` CI job rebuilds `crypto.o` from the committed source
and diffs against the committed object. The job fails if they differ
(ensures committed object matches source).
