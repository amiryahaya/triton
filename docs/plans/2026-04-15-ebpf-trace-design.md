# eBPF Runtime Crypto Tracer — Design

> **Status:** approved scope; ready for implementation plan. First runtime-observation scanner in the project.

## Why

Every scanner shipped so far is *inventory-based*: it finds crypto installed on disk, declared in configs, or embedded in binaries. None of them answer "is this crypto actually being called?". That gap produces a lot of false-positive migration priority: a DEPRECATED `RSA_sign` in libcrypto.so that no running process ever calls is not the same problem as one hit 10K times/second by a production service.

eBPF uprobe+kprobe tracing closes that gap by observing real crypto invocations during a bounded window. Adds a new "actually-used" signal that Triton's later risk-scoring and migration-priority logic can weight against inventory findings.

## Scope

**In scope (PR #1):**

| Surface | How |
|---|---|
| OpenSSL / libcrypto uprobes | `EVP_CipherInit_ex`, `EVP_EncryptInit_ex`, `EVP_DigestInit_ex`, `RSA_generate_key_ex`, `RSA_sign`, `RSA_verify`, `EC_KEY_generate_key`, `ECDSA_sign`, `EVP_PKEY_derive`, `SSL_CTX_new` |
| GnuTLS uprobes | `gnutls_cipher_init`, `gnutls_hash_init`, `gnutls_pubkey_verify_data2` |
| NSS uprobes | `PK11_CipherOp`, `PK11_Digest` |
| Kernel crypto API kprobes | `crypto_alloc_shash`, `crypto_alloc_skcipher`, `crypto_alloc_akcipher`, `crypto_alloc_aead` |
| NID→algorithm resolution | static table generated from `obj_mac.h`; kernel paths read 64-byte ASCII names directly |
| Time-bounded window | default 60s, configurable via `--ebpf-window` flag, validated `[1s, 30m]` |
| Linux-only via build tags | `//go:build linux` on real implementation; stub on macOS/Windows emits single skipped-finding |
| Graceful degradation | non-root / no-BTF / kernel < 5.8 / stripped-libcrypto → emit skipped-finding, never hard-fail |

**Out of scope (deferred PRs):**
- Continuous daemon mode — library boundary in `pkg/scanner/internal/ebpftrace/` designed so a wrapper can hoist the loader+reader into a long-running binary
- Per-PID findings — PR #1 emits one finding per `(binary_path, algo, source)` aggregate
- libsodium / BoringSSL / wolfSSL uprobes — additive (more entries in `symbols.go`)
- XDP / tc TLS fingerprinting — separate PR, parallel to `protocol.go`'s active prober
- Windows eBPF — niche; revisit if needed
- Syscall tracepoints (`getrandom`, `/dev/urandom` reads) — low signal; deliberately excluded

## Architecture

```
Engine dispatches ebpf_trace module (linux only)
   ↓
doctor gate: kernel ≥ 5.8, CAP_BPF|root, /sys/kernel/btf/vmlinux present
   ↓ (on fail: emit skipped-finding, return)
Walk /proc/*/maps → discover loaded libcrypto.so.* / libgnutls.so.* / libnss3.so paths (dedup by inode)
   ↓
Load embedded CO-RE eBPF object (cilium/ebpf, pure Go)
   ↓
Attach uprobes to each discovered library (batched) + kprobes to kernel crypto API
   ↓
Start ring-buffer reader goroutine; collect events into map[key]*aggregate
   ↓ (window expires or ctx cancelled)
Detach all probes, close ring
   ↓
For each aggregate: classify algo via existing pkg/crypto.ClassifyAlgorithm
   ↓
Emit one *model.Finding per (binary_path, algo, source) tuple
```

## Package Layout

```
pkg/scanner/ebpf_trace.go              # Module interface: Name/Category/Scan — dispatches to linux/stub
pkg/scanner/ebpf_trace_linux.go        # //go:build linux — real loader/attacher/reader
pkg/scanner/ebpf_trace_other.go        # //go:build !linux — skipped-finding stub
pkg/scanner/ebpf_trace_test.go         # shared tests (module-interface identity)
pkg/scanner/ebpf_trace_other_test.go   # //go:build !linux — stub behaviour
pkg/scanner/internal/ebpftrace/
  program.go                           # go:embed of bpf/crypto.o; program loader
  attach.go                            # uprobe/kprobe attachment; /proc/*/maps walk + inode dedup
  events.go                            # ring-buffer reader; crypto_event_t decode
  symbols.go                           # registry: libcrypto/gnutls/nss/kernel symbols + NID table
  reader.go                            # coordinator: window + aggregation
  program_test.go
  attach_test.go
  events_test.go
  symbols_test.go
  reader_test.go
  bpf/crypto.c                         # eBPF C source (committed)
  bpf/crypto.o                         # committed pre-compiled CO-RE object (~10KB)
  bpf/vmlinux.h                        # committed minimal vmlinux.h for CO-RE
  bpf/event.h                          # shared uapi (crypto_event_t)
  bpf/README.md                        # regeneration instructions
Makefile                               # new target: ebpf-compile
```

**Boundary:** `ebpftrace/` exposes `Run(ctx, window, opts) ([]Event, error)` — zero `model.Finding` knowledge in the internal package. The scanner module does classification + emission. Symmetric to how `internal/cli/` exposes raw TypeRefs and `dotnet_il.go` classifies.

## Probe Targets

### Uprobes (userspace library calls)

| Library | Symbol | Algorithm source |
|---|---|---|
| libcrypto | `EVP_CipherInit_ex` / `EVP_EncryptInit_ex` | NID from arg 2 |
| libcrypto | `EVP_DigestInit_ex` | NID from arg 2 |
| libcrypto | `RSA_generate_key_ex` / `RSA_sign` / `RSA_verify` | constant RSA |
| libcrypto | `EC_KEY_generate_key` / `ECDSA_sign` | constant ECDSA |
| libcrypto | `EVP_PKEY_derive` | constant KEX |
| libcrypto | `SSL_CTX_new` | constant TLS |
| libgnutls | `gnutls_cipher_init` | algorithm enum arg |
| libgnutls | `gnutls_hash_init` | algorithm enum arg |
| libgnutls | `gnutls_pubkey_verify_data2` | constant verify |
| libnss3 | `PK11_CipherOp` / `PK11_Digest` | mechanism enum arg |

Per-arch ABI: `PT_REGS_PARM2/PARM3` macros from `bpf_tracing.h`. No string reads inside eBPF — only numeric NIDs/enums. Userspace maps them via static table generated once from `obj_mac.h`.

### Kprobes (kernel crypto API)

| Symbol | Extracts |
|---|---|
| `crypto_alloc_shash` | algorithm name (arg 1, via `bpf_probe_read_user_str`, 64-byte cap) |
| `crypto_alloc_skcipher` | same |
| `crypto_alloc_akcipher` | same |
| `crypto_alloc_aead` | same |

Kernel crypto allocator names are short ASCII (`"sha256"`, `"aes-cbc"`, `"md5"`). Safe to read.

## Shared Event Struct

`bpf/event.h` (shared between eBPF C source and userspace Go decoder):

```c
struct crypto_event_t {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    __u8  source;    // 1=uprobe 2=kprobe
    __u8  lib_id;    // 1=libcrypto 2=gnutls 3=nss 4=kernel
    __s32 nid;       // -1 if string-based path
    char  name[64];  // kernel-crypto strings; empty for NID path
    char  comm[16];  // /proc/PID/comm snapshot
};
```

Ring buffer: `BPF_MAP_TYPE_RINGBUF`, 256 KB. Target event rate up to ~10K/sec.

## Finding Shape

```go
Finding{
    Module:   "ebpf_trace",
    Category: int(model.CategoryActiveRuntime),
    Source: model.FindingSource{
        Type:            "process",
        Path:            binaryPath,        // e.g. /usr/lib/x86_64-linux-gnu/libcrypto.so.3
        PID:             firstObservedPID,
        DetectionMethod: "ebpf-uprobe" | "ebpf-kprobe",
        Evidence:        fmt.Sprintf("%d calls over %s from %d pids", count, window, pidCount),
    },
    CryptoAsset: &model.CryptoAsset{
        Algorithm: "AES" | "SHA-256" | ...,  // from NID or kernel string
        Library:   "libcrypto.so.3" | "kernel",
        Language:  "C",
        Function:  functionForFamily(family),
        PQCStatus: string(status),            // via existing ClassifyAlgorithm
    },
    Confidence: 0.98,   // direct observation — highest confidence in the project
}
```

**Dedup:** per-window, one finding per `(binary_path, algo, source)`. Counts + pidCount aggregated into Evidence string.

## Engine Wiring

| Property | Value |
|---|---|
| Module name | `ebpf_trace` |
| Category | `model.CategoryActiveRuntime` |
| Target | `model.TargetProcess` |
| Profile | `comprehensive` only |
| Tier | Pro+ (append to `internal/license/tier.go`) |
| Factory | append to `pkg/scanner/engine.go` `defaultModuleFactories` |
| New CLI flags | `--ebpf-window` (default `60s`), `--ebpf-skip-uprobes` (bool), `--ebpf-skip-kprobes` (bool) |
| Doctor check | new entry: Linux kernel ≥ 5.8 + CAP_BPF|root + `/sys/kernel/btf/vmlinux` |
| Graceful degradation | any prereq failure → single skipped-finding with Evidence = reason; never hard-fails |

## Tests

| Layer | File | What |
|---|---|---|
| Unit — NID table | `ebpftrace/symbols_test.go` | NID→algorithm round-trip for common NIDs |
| Unit — /proc walk | `ebpftrace/attach_test.go` | parse `testdata/fake_maps`; inode dedup |
| Unit — event decode | `ebpftrace/events_test.go` | decode `crypto_event_t` from hex fixtures |
| Unit — reader | `ebpftrace/reader_test.go` | aggregation + window-expiry behaviour with mock event source |
| Module stub | `ebpf_trace_other_test.go` | non-Linux path emits exactly one skipped-finding |
| Integration (build tags `integration linux`) | `test/integration/ebpf_trace_test.go` | spawns `openssl dgst -sha256` inside window; asserts SHA-256 finding appears; skipped if not root or no BTF |

**eBPF program correctness:** the kernel verifier IS the test — if the committed `.o` loads, it's valid. Integration test proves end-to-end wiring. No unit tests inside eBPF C.

**Coverage target:** ≥ 75% on `pkg/scanner/internal/ebpftrace/` (lower than the 80% project target because eBPF attach/detach paths can only be exercised on a real kernel, which CI can't provide without privileged runners).

## Dependency

**New:** `github.com/cilium/ebpf` — pure Go CO-RE loader. Stable, production-proven (Cilium, Pixie, Parca). No `bcc`/`libbpf`/`clang`/`llvm` runtime requirement; builds against glibc only.

## Build Strategy

Committed `bpf/crypto.o` is the source of truth — no eBPF compilation on normal build paths. `make ebpf-compile` target regenerates it (requires `clang` + kernel headers). CI runs a verification job on PRs that touch `bpf/crypto.c`: rebuild the object, diff against committed — fail if they disagree (ensures committed object matches source).

## Risks

- **Stripped libcrypto** — some distros ship stripped `libcrypto.so`. Uprobe attach fails for missing symbols. Mitigation: per-symbol best-effort attach; emit a degraded finding noting "library stripped: N uprobes attached of M requested".
- **Kernel drift** — CO-RE handles field-offset variation; ring-buffer requires kernel ≥ 5.8. Older kernels produce skipped-finding (doctor gate).
- **Committed binary in repo** — small (~10 KB) and verifiable via the CI diff job. Same pattern used by Cilium, Pixie. Not ideal but pragmatic.
- **Observation-window completeness** — 60s default misses nightly cron jobs, bootstrapping crypto. Documented limit. User can extend via `--ebpf-window=30m` for deeper scans.
- **Verifier failures on newer kernels** — kernel changes occasionally break previously-verified programs. Mitigation: CI verification matrix will catch this during follow-up kernel-bump PRs; for PR #1 we target kernel 5.15 (LTS).

## Follow-up PRs

- Continuous daemon mode wrapping `pkg/scanner/internal/ebpftrace/reader.Run`
- Per-PID findings with full process-tree attribution
- libsodium / BoringSSL / wolfSSL uprobe sets
- XDP-based TLS ClientHello fingerprinting (JA3/JA4)
- Windows eBPF via ebpf-for-windows (once ecosystem matures)
- Risk-scoring integration: weight DEPRECATED inventory findings down if no ebpf_trace observation backed them in the same scan

## Estimated Effort

~1.5–2 days subagent-driven. ~9 tasks across 4 phases:

1. Skeleton + non-Linux stub + Module wiring (engine, profile, tier, flags)
2. eBPF C program + committed `.o` + build rule + verifier check
3. Go loader/attacher (program.go, attach.go) + /proc walk
4. Event reader + aggregator + symbols table + reader coordinator
5. Module glue (linux implementation), integration test, docs
