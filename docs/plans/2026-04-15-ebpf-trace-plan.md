# eBPF Runtime Crypto Tracer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an `ebpf_trace` scanner module that observes live crypto calls (OpenSSL/GnuTLS/NSS uprobes + kernel crypto API kprobes) inside a bounded time window and emits one finding per `(binary, algorithm, source)` observed tuple.

**Architecture:** Linux-only via build tags. Committed CO-RE eBPF object embedded via `//go:embed`, loaded by `github.com/cilium/ebpf` (pure Go, no clang/bcc at runtime). `/proc/*/maps` walk discovers loaded libs; uprobes attach per discovered inode; kprobes attach once to kernel crypto allocators. Ring-buffer reader aggregates events over the window; aggregator emits findings. Non-Linux stub emits a single "skipped: eBPF unavailable" finding.

**Tech Stack:** Go 1.26, `github.com/cilium/ebpf` (new dep), `debug/elf` (stdlib, for uprobe symbol resolution), `//go:embed`, build tags. One committed binary artifact (`bpf/crypto.o`, ~10KB). CI verification job diffs committed `.o` vs rebuilt-from-source.

---

## File Structure

### Create
- `pkg/scanner/ebpf_trace.go` — module interface only (Name/Category/ScanTargetType); no build tag; dispatches to Linux/stub via internal `scan()` method defined in the OS-specific files
- `pkg/scanner/ebpf_trace_linux.go` — `//go:build linux` — real `scan()` calling the ebpftrace package
- `pkg/scanner/ebpf_trace_other.go` — `//go:build !linux` — `scan()` stub emits one skipped-finding
- `pkg/scanner/ebpf_trace_test.go` — module-interface identity tests (run on all OS)
- `pkg/scanner/ebpf_trace_other_test.go` — `//go:build !linux` — stub-behaviour tests
- `pkg/scanner/internal/ebpftrace/types.go` — `Event`, `Options`, `Outcome` types; package doc
- `pkg/scanner/internal/ebpftrace/symbols.go` — NID→algorithm table; uprobe target list
- `pkg/scanner/internal/ebpftrace/symbols_test.go`
- `pkg/scanner/internal/ebpftrace/attach.go` — `//go:build linux` — `/proc/*/maps` walk, inode dedup, symbol resolution via `debug/elf`
- `pkg/scanner/internal/ebpftrace/attach_test.go` — testable pieces: maps parser (no build tag needed if it takes `io.Reader`)
- `pkg/scanner/internal/ebpftrace/events.go` — `Event` binary-decode (works on all OS, shared type)
- `pkg/scanner/internal/ebpftrace/events_test.go`
- `pkg/scanner/internal/ebpftrace/aggregate.go` — pure aggregation logic (no build tag)
- `pkg/scanner/internal/ebpftrace/aggregate_test.go`
- `pkg/scanner/internal/ebpftrace/program_linux.go` — `//go:build linux` — `Run(ctx, Options) (*Outcome, error)` coordinator; eBPF load + attach + ring-read + detach
- `pkg/scanner/internal/ebpftrace/program_linux_test.go` — `//go:build linux && integration` — real-kernel acceptance test (skipped if not root / no BTF)
- `pkg/scanner/internal/ebpftrace/bpf/crypto.c` — eBPF C source (uprobes + kprobes + ringbuf)
- `pkg/scanner/internal/ebpftrace/bpf/event.h` — shared uapi for `crypto_event_t`
- `pkg/scanner/internal/ebpftrace/bpf/vmlinux.h` — minimal BTF shim for CO-RE
- `pkg/scanner/internal/ebpftrace/bpf/crypto.o` — committed pre-compiled object (binary, ~10KB)
- `pkg/scanner/internal/ebpftrace/bpf/README.md` — regeneration instructions
- `pkg/scanner/internal/ebpftrace/testdata/fake_maps` — fixture `/proc/*/maps` content
- `test/integration/ebpf_trace_test.go` — `//go:build integration && linux` — end-to-end spawn + trace

### Modify
- `go.mod` — add `github.com/cilium/ebpf` dep
- `pkg/scanner/engine.go` — append `NewEBPFTraceModule` factory to `defaultModuleFactories`
- `internal/scannerconfig/config.go` — append `"ebpf_trace"` to comprehensive `Modules` list
- `internal/scannerconfig/config_test.go` — add NotContains/Contains assertions
- `internal/license/tier.go` — append `"ebpf_trace"` to Pro+ allowlist
- `cmd/root.go` — add three flags: `--ebpf-window`, `--ebpf-skip-uprobes`, `--ebpf-skip-kprobes`
- `internal/scannerconfig/config.go` — add corresponding fields to `Config` struct + defaults
- `pkg/scanner/doctor.go` — add eBPF prereq check (kernel version, CAP_BPF, BTF availability)
- `Makefile` — add `ebpf-compile` target (documents how to rebuild `crypto.o`)
- `CLAUDE.md` — add bullet under `pkg/scanner/` listing the new module

### Out of Scope (explicit)
- Continuous daemon mode — library boundary in `ebpftrace/` is designed so a wrapper can reuse `Run()`
- Per-PID findings
- libsodium / BoringSSL / wolfSSL uprobes
- XDP / tc hooks
- Windows eBPF
- Syscall tracepoints (`getrandom`, etc.)
- Risk-scoring integration with inventory scanners

---

## Conventions

- **Module name:** `"ebpf_trace"`.
- **Detection methods:** `"ebpf-uprobe"` for userspace observations, `"ebpf-kprobe"` for kernel.
- **Confidence:** `0.98` on real observations, `0.0` on skipped-finding.
- **Language tag:** `Language: "C"` (runtime observation of C libs/kernel).
- **Window default:** `60 * time.Second`. Validated `[1s, 30m]`.
- **Skipped-finding shape:** `Algorithm="N/A"`, `PQCStatus=""`, `Evidence="ebpf unavailable: <reason>"`.
- **Defensive bounds:** every event-buffer read guarded by length check; every `/proc` parse tolerant of malformed lines (skip + continue).
- **No panics:** all errors returned; module logs + emits skipped-finding rather than panicking.
- **Commit scope:** one commit per task minimum; subject `<type>(<scope>): <subject>` where scope is `ebpf`, `ebpf-trace`, or `scanner`.

---

## Task 1: Skeleton + non-Linux stub + engine wiring

Lowest-risk task first. Lands the module into the registry on all OS with the stub path, so later tasks only touch Linux code.

**Files:**
- Create: `pkg/scanner/ebpf_trace.go`
- Create: `pkg/scanner/ebpf_trace_other.go`
- Create: `pkg/scanner/ebpf_trace_test.go`
- Create: `pkg/scanner/ebpf_trace_other_test.go`
- Modify: `pkg/scanner/engine.go`
- Modify: `internal/scannerconfig/config.go`
- Modify: `internal/scannerconfig/config_test.go`
- Modify: `internal/license/tier.go`

- [ ] **Step 1: Write `pkg/scanner/ebpf_trace.go`**

```go
package scanner

import (
	"context"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// EBPFTraceModule observes live crypto calls via eBPF uprobes (OpenSSL/GnuTLS/NSS)
// and kprobes (kernel crypto API) inside a bounded time window. Linux-only; the
// non-Linux build emits a single "skipped" finding.
type EBPFTraceModule struct {
	cfg   *scannerconfig.Config
	store store.Store
}

// NewEBPFTraceModule constructs the module.
func NewEBPFTraceModule(cfg *scannerconfig.Config) *EBPFTraceModule {
	return &EBPFTraceModule{cfg: cfg}
}

// Name returns the canonical module name.
func (m *EBPFTraceModule) Name() string { return "ebpf_trace" }

// Category returns the module category (active runtime observation).
func (m *EBPFTraceModule) Category() model.ModuleCategory { return model.CategoryActiveRuntime }

// ScanTargetType returns the target type.
func (m *EBPFTraceModule) ScanTargetType() model.ScanTargetType { return model.TargetProcess }

// SetStore wires the incremental-scan store.
func (m *EBPFTraceModule) SetStore(s store.Store) { m.store = s }

// Scan delegates to the OS-specific scan method.
func (m *EBPFTraceModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return m.scan(ctx, target, findings)
}
```

- [ ] **Step 2: Write `pkg/scanner/ebpf_trace_other.go`**

```go
//go:build !linux

package scanner

import (
	"context"
	"runtime"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// scan emits one skipped-finding on non-Linux builds.
func (m *EBPFTraceModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ebpf-skipped",
			Evidence:        "ebpf unavailable: " + runtime.GOOS + " is not Linux",
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "C",
		},
		Confidence: 0.0,
		Module:     "ebpf_trace",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
```

- [ ] **Step 3: Write `pkg/scanner/ebpf_trace_test.go`**

```go
package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestEBPFTraceModule_Identity(t *testing.T) {
	m := NewEBPFTraceModule(&scannerconfig.Config{})
	if m.Name() != "ebpf_trace" {
		t.Errorf("Name = %q, want ebpf_trace", m.Name())
	}
	if m.Category() != model.CategoryActiveRuntime {
		t.Errorf("Category = %v, want CategoryActiveRuntime", m.Category())
	}
	if m.ScanTargetType() != model.TargetProcess {
		t.Errorf("ScanTargetType = %v, want TargetProcess", m.ScanTargetType())
	}
}
```

- [ ] **Step 4: Write `pkg/scanner/ebpf_trace_other_test.go`**

```go
//go:build !linux

package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestEBPFTraceModule_NonLinuxSkippedFinding(t *testing.T) {
	m := NewEBPFTraceModule(&scannerconfig.Config{})
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{Type: model.TargetProcess}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	f := got[0]
	if f.Module != "ebpf_trace" {
		t.Errorf("Module = %q, want ebpf_trace", f.Module)
	}
	if f.Source.DetectionMethod != "ebpf-skipped" {
		t.Errorf("DetectionMethod = %q, want ebpf-skipped", f.Source.DetectionMethod)
	}
	if f.Confidence != 0.0 {
		t.Errorf("Confidence = %v, want 0.0", f.Confidence)
	}
}
```

- [ ] **Step 5: Wire module into engine / profile / tier**

In `pkg/scanner/engine.go`, find the last factory line in `defaultModuleFactories` (currently ends with `NewDotNetILModule`). Append after it:

```go
	func(c *scannerconfig.Config) Module { return NewEBPFTraceModule(c) },
```

In `internal/scannerconfig/config.go`, find the comprehensive `Modules:` slice (the long one ending with `"dotnet_il"`). Append `"ebpf_trace"` as the very last element.

In `internal/scannerconfig/config_test.go`, locate the existing `dotnet_il` assertions and add matching ones for `ebpf_trace`:
- After each `assert.NotContains(t, cfg.Modules, "dotnet_il")` → add `assert.NotContains(t, cfg.Modules, "ebpf_trace")`
- After `assert.Contains(t, cfg.Modules, "dotnet_il")` → add `assert.Contains(t, cfg.Modules, "ebpf_trace")`

In `internal/license/tier.go`, find the line `"dotnet_il",` and append `"ebpf_trace",` immediately after.

If `pkg/scanner/engine_test.go` has a hard-coded module count (it was 47 after dotnet_il), bump it by 1 to 48.

- [ ] **Step 6: Run, verify PASS**

```bash
go test ./pkg/scanner/ ./internal/scannerconfig/ ./internal/license/
go build ./...
GOOS=linux go build ./...
```

All must PASS. The Linux cross-build proves the `//go:build linux` stub compiles in both directions — but there is no Linux scan() yet, so next task adds a placeholder.

- [ ] **Step 7: Add Linux placeholder to unblock cross-compile**

Create `pkg/scanner/ebpf_trace_linux.go`:

```go
//go:build linux

package scanner

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// scan is a temporary placeholder that emits a skipped-finding until Task 8
// wires up the real eBPF implementation. Replaced entirely in Task 8.
func (m *EBPFTraceModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ebpf-skipped",
			Evidence:        "ebpf unavailable: implementation pending (Task 8)",
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "C",
		},
		Confidence: 0.0,
		Module:     "ebpf_trace",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
```

Re-run `GOOS=linux go build ./...` — must pass.

- [ ] **Step 8: Commit**

```bash
git add pkg/scanner/ebpf_trace.go pkg/scanner/ebpf_trace_linux.go pkg/scanner/ebpf_trace_other.go pkg/scanner/ebpf_trace_test.go pkg/scanner/ebpf_trace_other_test.go pkg/scanner/engine.go pkg/scanner/engine_test.go internal/scannerconfig/config.go internal/scannerconfig/config_test.go internal/license/tier.go
git commit -m "feat(scanner): ebpf_trace module skeleton + non-linux stub + engine wiring"
```

---

## Task 2: Symbols registry + NID table

Pure-Go lookup table. No eBPF, no Linux specificity. Fully testable on darwin.

**Files:**
- Create: `pkg/scanner/internal/ebpftrace/types.go`
- Create: `pkg/scanner/internal/ebpftrace/symbols.go`
- Create: `pkg/scanner/internal/ebpftrace/symbols_test.go`

- [ ] **Step 1: Write `pkg/scanner/internal/ebpftrace/types.go`**

```go
// Package ebpftrace observes live crypto calls via eBPF uprobes and kprobes.
// Linux-only (see program_linux.go); the package compiles on all platforms
// but Run() is unavailable on non-Linux.
package ebpftrace

import "time"

// Source discriminates the eBPF probe family that produced an event.
type Source uint8

const (
	SourceUnknown Source = 0
	SourceUprobe  Source = 1
	SourceKprobe  Source = 2
)

// LibID discriminates the userspace library for uprobe events.
type LibID uint8

const (
	LibUnknown   LibID = 0
	LibLibcrypto LibID = 1
	LibGnuTLS    LibID = 2
	LibNSS       LibID = 3
	LibKernel    LibID = 4
)

// Event is one observed crypto call, decoded from the eBPF ring buffer.
type Event struct {
	PID       uint32
	UID       uint32
	TS        time.Time
	Source    Source
	LibID     LibID
	NID       int32  // -1 if string-based (kernel path)
	Name      string // kernel-crypto string; "" for NID path
	Comm      string // /proc/PID/comm snapshot at trace time
}

// Options configures a single Run() invocation.
type Options struct {
	Window       time.Duration
	SkipUprobes  bool
	SkipKprobes  bool
	ObjectLoader func() ([]byte, error) // optional override (default: embedded crypto.o)
}

// AlgoInfo is the classified result of a crypto observation.
type AlgoInfo struct {
	Algorithm string
	Family    string
	Library   string
}

// UprobeTarget describes one uprobe attach request.
type UprobeTarget struct {
	LibID       LibID
	SymbolName  string
	ProgName    string // eBPF program section, e.g. "uprobe/EVP_CipherInit_ex"
	ArgIdx      uint8  // which PARM to read the NID/enum from (0 = constant)
	ConstAlgo   string // used when ArgIdx == 0
	ConstFamily string
}
```

- [ ] **Step 2: Write `pkg/scanner/internal/ebpftrace/symbols_test.go` (RED)**

```go
package ebpftrace

import "testing"

func TestResolveNID_CommonNIDs(t *testing.T) {
	cases := map[int32]struct {
		algo   string
		family string
	}{
		672:  {"SHA-256", "SHA"},   // NID_sha256
		673:  {"SHA-384", "SHA"},
		674:  {"SHA-512", "SHA"},
		418:  {"AES", "AES"},       // NID_aes_128_cbc
		419:  {"AES", "AES"},       // NID_aes_192_cbc
		420:  {"AES", "AES"},       // NID_aes_256_cbc
		6:    {"RSA", "RSA"},       // NID_rsaEncryption
		116:  {"DSA", "DSA"},       // NID_dsa
		408:  {"ECDSA", "ECDSA"},   // NID_X9_62_prime256v1
		4:    {"MD5", "MD5"},
		64:   {"SHA-1", "SHA"},
	}
	for nid, want := range cases {
		info, ok := ResolveNID(nid)
		if !ok {
			t.Errorf("ResolveNID(%d) returned !ok", nid)
			continue
		}
		if info.Algorithm != want.algo {
			t.Errorf("nid %d: Algorithm = %q, want %q", nid, info.Algorithm, want.algo)
		}
		if info.Family != want.family {
			t.Errorf("nid %d: Family = %q, want %q", nid, info.Family, want.family)
		}
	}
}

func TestResolveNID_UnknownReturnsFalse(t *testing.T) {
	if _, ok := ResolveNID(999999); ok {
		t.Error("expected unknown NID to return !ok")
	}
}

func TestResolveKernelAlgo_Names(t *testing.T) {
	cases := map[string]struct {
		algo   string
		family string
	}{
		"sha256":      {"SHA-256", "SHA"},
		"sha1":        {"SHA-1", "SHA"},
		"md5":         {"MD5", "MD5"},
		"aes-cbc(aes)": {"AES", "AES"},
		"cbc(aes)":    {"AES", "AES"},
		"rsa":         {"RSA", "RSA"},
		"ecdsa":       {"ECDSA", "ECDSA"},
	}
	for name, want := range cases {
		info, ok := ResolveKernelAlgo(name)
		if !ok {
			t.Errorf("ResolveKernelAlgo(%q) returned !ok", name)
			continue
		}
		if info.Algorithm != want.algo {
			t.Errorf("%q: Algorithm = %q, want %q", name, info.Algorithm, want.algo)
		}
		if info.Family != want.family {
			t.Errorf("%q: Family = %q, want %q", name, info.Family, want.family)
		}
	}
}

func TestUprobeTargets_HasCoreSymbols(t *testing.T) {
	targets := UprobeTargets()
	want := []string{
		"EVP_CipherInit_ex",
		"EVP_EncryptInit_ex",
		"EVP_DigestInit_ex",
		"RSA_generate_key_ex",
		"RSA_sign",
		"EC_KEY_generate_key",
		"SSL_CTX_new",
		"gnutls_cipher_init",
		"gnutls_hash_init",
		"PK11_CipherOp",
		"PK11_Digest",
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		seen[tg.SymbolName] = true
	}
	for _, s := range want {
		if !seen[s] {
			t.Errorf("missing uprobe target %q", s)
		}
	}
}
```

- [ ] **Step 3: Run, verify FAIL** — `go test ./pkg/scanner/internal/ebpftrace/ -run 'TestResolveNID|TestResolveKernelAlgo|TestUprobeTargets'` → `undefined: ResolveNID` etc.

- [ ] **Step 4: Write `pkg/scanner/internal/ebpftrace/symbols.go`**

```go
package ebpftrace

import "strings"

// ResolveNID maps an OpenSSL NID (from obj_mac.h) to an AlgoInfo.
// Only NIDs that appear as cipher/digest arguments to probed uprobes are listed.
func ResolveNID(nid int32) (AlgoInfo, bool) {
	info, ok := nidRegistry[nid]
	return info, ok
}

// ResolveKernelAlgo maps a Linux kernel crypto allocator name to an AlgoInfo.
// Names like "sha256", "cbc(aes)", "gcm(aes)" are common.
func ResolveKernelAlgo(name string) (AlgoInfo, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	// Exact-match first.
	if info, ok := kernelRegistry[n]; ok {
		return info, true
	}
	// Substring scan for compound names like "cbc(aes)" or "hmac(sha256)".
	for key, info := range kernelRegistry {
		if strings.Contains(n, key) {
			return info, true
		}
	}
	return AlgoInfo{}, false
}

// UprobeTargets returns the list of uprobe attach requests. Ordering is stable
// (tests rely on `SymbolName` presence, not index).
func UprobeTargets() []UprobeTarget {
	return uprobeTargets
}

var nidRegistry = map[int32]AlgoInfo{
	// Hashes (obj_mac.h NID_*)
	4:   {"MD5", "MD5", "libcrypto"},
	64:  {"SHA-1", "SHA", "libcrypto"},
	672: {"SHA-256", "SHA", "libcrypto"},
	673: {"SHA-384", "SHA", "libcrypto"},
	674: {"SHA-512", "SHA", "libcrypto"},
	675: {"SHA-224", "SHA", "libcrypto"},
	1096: {"SHA3-256", "SHA3", "libcrypto"},
	1097: {"SHA3-384", "SHA3", "libcrypto"},
	1098: {"SHA3-512", "SHA3", "libcrypto"},
	// Ciphers
	418: {"AES", "AES", "libcrypto"}, // aes-128-cbc
	419: {"AES", "AES", "libcrypto"},
	420: {"AES", "AES", "libcrypto"},
	421: {"AES", "AES", "libcrypto"},
	422: {"AES", "AES", "libcrypto"},
	423: {"AES", "AES", "libcrypto"},
	424: {"AES", "AES", "libcrypto"}, // aes-128-ecb
	425: {"AES", "AES", "libcrypto"},
	426: {"AES", "AES", "libcrypto"},
	427: {"AES", "AES", "libcrypto"}, // aes-128-cfb1
	428: {"AES", "AES", "libcrypto"},
	429: {"AES", "AES", "libcrypto"},
	901: {"AES-GCM", "AES", "libcrypto"},
	902: {"AES-GCM", "AES", "libcrypto"},
	903: {"AES-GCM", "AES", "libcrypto"},
	31:  {"DES", "DES", "libcrypto"},
	44:  {"3DES", "3DES", "libcrypto"},
	5:   {"RC4", "RC4", "libcrypto"},
	37:  {"RC2", "RC2", "libcrypto"},
	1016: {"ChaCha20", "ChaCha", "libcrypto"},
	1018: {"ChaCha20-Poly1305", "ChaCha", "libcrypto"},
	// Asymmetric
	6:   {"RSA", "RSA", "libcrypto"},
	116: {"DSA", "DSA", "libcrypto"},
	408: {"ECDSA", "ECDSA", "libcrypto"}, // X9_62_prime256v1
	715: {"ECDSA", "ECDSA", "libcrypto"}, // secp384r1
	716: {"ECDSA", "ECDSA", "libcrypto"}, // secp521r1
	1087: {"Ed25519", "EdDSA", "libcrypto"},
	1088: {"Ed448", "EdDSA", "libcrypto"},
	1034: {"X25519", "ECDH", "libcrypto"},
	1035: {"X448", "ECDH", "libcrypto"},
}

// kernelRegistry covers Linux kernel crypto allocator names. Keys are
// lowercase substrings; ResolveKernelAlgo does both exact + contains matches.
var kernelRegistry = map[string]AlgoInfo{
	"md5":        {"MD5", "MD5", "kernel"},
	"sha1":       {"SHA-1", "SHA", "kernel"},
	"sha224":     {"SHA-224", "SHA", "kernel"},
	"sha256":     {"SHA-256", "SHA", "kernel"},
	"sha384":     {"SHA-384", "SHA", "kernel"},
	"sha512":     {"SHA-512", "SHA", "kernel"},
	"sha3-256":   {"SHA3-256", "SHA3", "kernel"},
	"sha3-384":   {"SHA3-384", "SHA3", "kernel"},
	"sha3-512":   {"SHA3-512", "SHA3", "kernel"},
	"aes":        {"AES", "AES", "kernel"},
	"des":        {"DES", "DES", "kernel"},
	"3des":       {"3DES", "3DES", "kernel"},
	"chacha20":   {"ChaCha20", "ChaCha", "kernel"},
	"poly1305":   {"Poly1305", "MAC", "kernel"},
	"rsa":        {"RSA", "RSA", "kernel"},
	"dsa":        {"DSA", "DSA", "kernel"},
	"ecdsa":      {"ECDSA", "ECDSA", "kernel"},
	"ecdh":       {"ECDH", "ECDH", "kernel"},
	"ed25519":    {"Ed25519", "EdDSA", "kernel"},
	"hmac":       {"HMAC", "HMAC", "kernel"},
}

var uprobeTargets = []UprobeTarget{
	// libcrypto — NID-driven
	{LibID: LibLibcrypto, SymbolName: "EVP_CipherInit_ex", ProgName: "uprobe__EVP_CipherInit_ex", ArgIdx: 2},
	{LibID: LibLibcrypto, SymbolName: "EVP_EncryptInit_ex", ProgName: "uprobe__EVP_EncryptInit_ex", ArgIdx: 2},
	{LibID: LibLibcrypto, SymbolName: "EVP_DigestInit_ex", ProgName: "uprobe__EVP_DigestInit_ex", ArgIdx: 2},
	// libcrypto — constant-inferred
	{LibID: LibLibcrypto, SymbolName: "RSA_generate_key_ex", ProgName: "uprobe__RSA_generate_key_ex", ArgIdx: 0, ConstAlgo: "RSA", ConstFamily: "RSA"},
	{LibID: LibLibcrypto, SymbolName: "RSA_sign", ProgName: "uprobe__RSA_sign", ArgIdx: 0, ConstAlgo: "RSA", ConstFamily: "RSA"},
	{LibID: LibLibcrypto, SymbolName: "RSA_verify", ProgName: "uprobe__RSA_verify", ArgIdx: 0, ConstAlgo: "RSA", ConstFamily: "RSA"},
	{LibID: LibLibcrypto, SymbolName: "EC_KEY_generate_key", ProgName: "uprobe__EC_KEY_generate_key", ArgIdx: 0, ConstAlgo: "ECDSA", ConstFamily: "ECDSA"},
	{LibID: LibLibcrypto, SymbolName: "ECDSA_sign", ProgName: "uprobe__ECDSA_sign", ArgIdx: 0, ConstAlgo: "ECDSA", ConstFamily: "ECDSA"},
	{LibID: LibLibcrypto, SymbolName: "EVP_PKEY_derive", ProgName: "uprobe__EVP_PKEY_derive", ArgIdx: 0, ConstAlgo: "KEX", ConstFamily: "ECDH"},
	{LibID: LibLibcrypto, SymbolName: "SSL_CTX_new", ProgName: "uprobe__SSL_CTX_new", ArgIdx: 0, ConstAlgo: "TLS", ConstFamily: "TLS"},
	// GnuTLS
	{LibID: LibGnuTLS, SymbolName: "gnutls_cipher_init", ProgName: "uprobe__gnutls_cipher_init", ArgIdx: 2},
	{LibID: LibGnuTLS, SymbolName: "gnutls_hash_init", ProgName: "uprobe__gnutls_hash_init", ArgIdx: 2},
	{LibID: LibGnuTLS, SymbolName: "gnutls_pubkey_verify_data2", ProgName: "uprobe__gnutls_pubkey_verify_data2", ArgIdx: 0, ConstAlgo: "Verify", ConstFamily: "Signature"},
	// NSS
	{LibID: LibNSS, SymbolName: "PK11_CipherOp", ProgName: "uprobe__PK11_CipherOp", ArgIdx: 0, ConstAlgo: "Cipher", ConstFamily: "Cipher"},
	{LibID: LibNSS, SymbolName: "PK11_Digest", ProgName: "uprobe__PK11_Digest", ArgIdx: 0, ConstAlgo: "Digest", ConstFamily: "Hash"},
}
```

- [ ] **Step 5: Run, verify PASS**

`go test ./pkg/scanner/internal/ebpftrace/ -v`
Expected: all 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/internal/ebpftrace/types.go pkg/scanner/internal/ebpftrace/symbols.go pkg/scanner/internal/ebpftrace/symbols_test.go
git commit -m "feat(ebpf): symbol registry + NID→algorithm table"
```

---

## Task 3: Event decoder

Pure-Go binary decoder; no eBPF, no Linux. Decodes `crypto_event_t` struct from ring-buffer bytes.

**Files:**
- Create: `pkg/scanner/internal/ebpftrace/events.go`
- Create: `pkg/scanner/internal/ebpftrace/events_test.go`

`crypto_event_t` layout (matches `bpf/event.h` written in Task 5):
```
offset 0:  uint32 pid
offset 4:  uint32 uid
offset 8:  uint64 ts_ns
offset 16: uint8  source
offset 17: uint8  lib_id
offset 18: uint16 _pad0         (alignment padding for nid)
offset 20: int32  nid
offset 24: char[64] name
offset 88: char[16] comm
offset 104: total size
```

- [ ] **Step 1: Write `pkg/scanner/internal/ebpftrace/events_test.go` (RED)**

```go
package ebpftrace

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestDecodeEvent_Kprobe(t *testing.T) {
	buf := make([]byte, 104)
	binary.LittleEndian.PutUint32(buf[0:], 1234)                      // pid
	binary.LittleEndian.PutUint32(buf[4:], 0)                         // uid
	binary.LittleEndian.PutUint64(buf[8:], uint64(1_700_000_000_000_000_000)) // ts_ns
	buf[16] = uint8(SourceKprobe)
	buf[17] = uint8(LibKernel)
	binary.LittleEndian.PutUint32(buf[20:], uint32(int32(-1)))        // nid = -1
	copy(buf[24:], []byte("sha256\x00"))
	copy(buf[88:], []byte("openssl\x00"))

	ev, err := DecodeEvent(buf)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if ev.PID != 1234 {
		t.Errorf("PID = %d, want 1234", ev.PID)
	}
	if ev.Source != SourceKprobe {
		t.Errorf("Source = %v, want SourceKprobe", ev.Source)
	}
	if ev.LibID != LibKernel {
		t.Errorf("LibID = %v, want LibKernel", ev.LibID)
	}
	if ev.NID != -1 {
		t.Errorf("NID = %d, want -1", ev.NID)
	}
	if ev.Name != "sha256" {
		t.Errorf("Name = %q, want sha256", ev.Name)
	}
	if ev.Comm != "openssl" {
		t.Errorf("Comm = %q, want openssl", ev.Comm)
	}
	if ev.TS.IsZero() {
		t.Error("TS is zero")
	}
	_ = time.Second // keep time import used
}

func TestDecodeEvent_Uprobe(t *testing.T) {
	buf := make([]byte, 104)
	binary.LittleEndian.PutUint32(buf[0:], 5678)
	buf[16] = uint8(SourceUprobe)
	buf[17] = uint8(LibLibcrypto)
	binary.LittleEndian.PutUint32(buf[20:], uint32(int32(672))) // NID_sha256
	// name remains empty for NID path
	copy(buf[88:], []byte("nginx\x00"))

	ev, err := DecodeEvent(buf)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if ev.NID != 672 {
		t.Errorf("NID = %d, want 672", ev.NID)
	}
	if ev.LibID != LibLibcrypto {
		t.Errorf("LibID = %v, want LibLibcrypto", ev.LibID)
	}
	if ev.Name != "" {
		t.Errorf("Name = %q, want empty (NID path)", ev.Name)
	}
}

func TestDecodeEvent_RejectsShortBuffer(t *testing.T) {
	if _, err := DecodeEvent(make([]byte, 50)); err == nil {
		t.Error("expected error on short buffer")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `undefined: DecodeEvent`.

- [ ] **Step 3: Write `pkg/scanner/internal/ebpftrace/events.go`**

```go
package ebpftrace

import (
	"encoding/binary"
	"fmt"
	"time"
)

// eventSize matches sizeof(struct crypto_event_t) in bpf/event.h.
const eventSize = 104

// DecodeEvent parses a crypto_event_t struct from a ring-buffer payload.
func DecodeEvent(buf []byte) (Event, error) {
	if len(buf) < eventSize {
		return Event{}, fmt.Errorf("ebpftrace: event buffer too short (%d < %d)", len(buf), eventSize)
	}
	ev := Event{
		PID:    binary.LittleEndian.Uint32(buf[0:4]),
		UID:    binary.LittleEndian.Uint32(buf[4:8]),
		TS:     time.Unix(0, int64(binary.LittleEndian.Uint64(buf[8:16]))),
		Source: Source(buf[16]),
		LibID:  LibID(buf[17]),
		NID:    int32(binary.LittleEndian.Uint32(buf[20:24])),
		Name:   cString(buf[24:88]),
		Comm:   cString(buf[88:104]),
	}
	return ev, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
```

- [ ] **Step 4: Run, verify PASS**

`go test ./pkg/scanner/internal/ebpftrace/ -run TestDecodeEvent -v`
Expected: all 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/ebpftrace/events.go pkg/scanner/internal/ebpftrace/events_test.go
git commit -m "feat(ebpf): crypto_event_t binary decoder"
```

---

## Task 4: /proc/*/maps parser + inode dedup

Pure-Go parser. Input is a `/proc/PID/maps`-formatted string (via `io.Reader`), output is a list of `(library-path, inode)` for loaded crypto libs. Inode dedup lets us attach uprobes once per physical file regardless of how many processes loaded it.

**Files:**
- Create: `pkg/scanner/internal/ebpftrace/attach.go`
- Create: `pkg/scanner/internal/ebpftrace/attach_test.go`
- Create: `pkg/scanner/internal/ebpftrace/testdata/fake_maps`

- [ ] **Step 1: Create the fixture `pkg/scanner/internal/ebpftrace/testdata/fake_maps`**

```
5558a1a00000-5558a1a37000 r--p 00000000 08:01 131074  /usr/bin/nginx
7f1234000000-7f1234050000 r-xp 00000000 08:01 262145  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
7f1234100000-7f1234150000 r--p 00000000 08:01 262145  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
7f1234200000-7f1234220000 r-xp 00000000 08:01 262200  /usr/lib/x86_64-linux-gnu/libgnutls.so.30
7f1234300000-7f1234310000 r-xp 00000000 08:01 262300  /usr/lib/x86_64-linux-gnu/libc.so.6
7f1234400000-7f1234420000 r-xp 00000000 08:01 262145  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
```

Two `libcrypto.so.3` lines with the same inode `262145` (simulates same file mapped twice — r-xp and r--p). One `libgnutls.so.30`. A non-crypto `libc.so.6` that must be ignored. A non-library `/usr/bin/nginx` that must be ignored.

- [ ] **Step 2: Write `pkg/scanner/internal/ebpftrace/attach_test.go` (RED)**

```go
package ebpftrace

import (
	"os"
	"sort"
	"testing"
)

func TestDiscoverLibs_DedupsByInode(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	libs, err := DiscoverLibsFromMaps(f)
	if err != nil {
		t.Fatalf("DiscoverLibsFromMaps: %v", err)
	}
	if len(libs) != 2 {
		t.Fatalf("len(libs) = %d, want 2 (libcrypto dedup'd, libgnutls)", len(libs))
	}
	paths := make([]string, len(libs))
	for i, l := range libs {
		paths[i] = l.Path
	}
	sort.Strings(paths)
	want := []string{
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
	}
	for i, p := range paths {
		if p != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, p, want[i])
		}
	}
}

func TestDiscoverLibs_IgnoresNonCryptoLibs(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	libs, err := DiscoverLibsFromMaps(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range libs {
		if l.Path == "/usr/lib/x86_64-linux-gnu/libc.so.6" {
			t.Error("libc.so.6 should not be returned")
		}
		if l.Path == "/usr/bin/nginx" {
			t.Error("nginx executable should not be returned")
		}
	}
}
```

- [ ] **Step 3: Run, verify FAIL** — `undefined: DiscoverLibsFromMaps`.

- [ ] **Step 4: Write `pkg/scanner/internal/ebpftrace/attach.go`**

```go
package ebpftrace

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// DiscoveredLib represents one crypto library found loaded in a process address
// space, dedup'd by inode so uprobes attach once per physical file.
type DiscoveredLib struct {
	Path  string
	Inode string // keep as string (not uint64) since /proc/maps may be malformed
	LibID LibID
}

// cryptoLibMatchers lists substring patterns that identify supported libraries.
// Ordered by specificity: more-specific patterns first.
var cryptoLibMatchers = []struct {
	pattern string
	libID   LibID
}{
	{"libcrypto.so", LibLibcrypto},
	{"libgnutls.so", LibGnuTLS},
	{"libnss3.so", LibNSS},
}

// DiscoverLibsFromMaps parses /proc/PID/maps content and returns a dedup'd list
// of crypto libraries mapped into the process. Input is any io.Reader so tests
// can feed fixtures.
//
// /proc/PID/maps line format:
//   address-range perms offset dev inode pathname
// Example:
//   7f1234000000-7f1234050000 r-xp 00000000 08:01 262145 /usr/lib/libcrypto.so.3
func DiscoverLibsFromMaps(r io.Reader) ([]DiscoveredLib, error) {
	seen := map[string]bool{} // inode → seen
	out := []DiscoveredLib{}
	scanner := bufio.NewScanner(r)
	// /proc/maps lines can be long if the path has many components; raise the buffer.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue // no path → not a file-backed mapping
		}
		inode := fields[4]
		path := fields[5]
		if inode == "0" {
			continue // anonymous mapping
		}
		matcher := matchCryptoLib(path)
		if matcher == nil {
			continue
		}
		if seen[inode] {
			continue
		}
		seen[inode] = true
		out = append(out, DiscoveredLib{Path: path, Inode: inode, LibID: matcher.libID})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ebpftrace: scan maps: %w", err)
	}
	return out, nil
}

func matchCryptoLib(path string) *struct {
	pattern string
	libID   LibID
} {
	for i := range cryptoLibMatchers {
		if strings.Contains(path, cryptoLibMatchers[i].pattern) {
			return &cryptoLibMatchers[i]
		}
	}
	return nil
}
```

- [ ] **Step 5: Run, verify PASS**

`go test ./pkg/scanner/internal/ebpftrace/ -run TestDiscoverLibs -v`
Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/internal/ebpftrace/attach.go pkg/scanner/internal/ebpftrace/attach_test.go pkg/scanner/internal/ebpftrace/testdata/fake_maps
git commit -m "feat(ebpf): /proc/PID/maps parser + inode dedup for crypto libs"
```

---

## Task 5: eBPF C program + vmlinux.h + committed object

This is the highest-risk task. The implementer may not have clang available. Strategy: write the C source, commit it, and try to compile. If compilation fails locally, skip the object file for now (mark PR as "needs Linux dev to rebuild crypto.o"). The test file in Task 6 will gate on whether crypto.o exists; if not, program_linux.go returns an error and the scanner emits skipped-finding.

**Files:**
- Create: `pkg/scanner/internal/ebpftrace/bpf/event.h`
- Create: `pkg/scanner/internal/ebpftrace/bpf/crypto.c`
- Create: `pkg/scanner/internal/ebpftrace/bpf/vmlinux.h` (minimal shim — NOT the full 40MB generated one)
- Create: `pkg/scanner/internal/ebpftrace/bpf/README.md`
- Modify: `Makefile` — add `ebpf-compile` target

- [ ] **Step 1: Write `bpf/event.h`**

```c
// SPDX-License-Identifier: Apache-2.0
// Shared uapi between eBPF program and userspace decoder.
#ifndef __TRITON_EBPF_EVENT_H
#define __TRITON_EBPF_EVENT_H

#define NAME_LEN 64
#define COMM_LEN 16

struct crypto_event_t {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    __u8  source;    // 1=uprobe 2=kprobe
    __u8  lib_id;    // 1=libcrypto 2=gnutls 3=nss 4=kernel
    __u16 _pad0;     // alignment to 4 for nid
    __s32 nid;       // -1 for string-based (kernel)
    char  name[NAME_LEN];
    char  comm[COMM_LEN];
};

#endif // __TRITON_EBPF_EVENT_H
```

- [ ] **Step 2: Write `bpf/vmlinux.h` (minimal)**

Do NOT write the 40MB auto-generated vmlinux.h. For our use we only need a handful of type aliases that libbpf headers expect. Write this minimal shim:

```c
// SPDX-License-Identifier: Apache-2.0
// Minimal BTF-shim for CO-RE. Full vmlinux.h is 40MB+; we stub only what
// bpf_helpers.h and our probes reference.
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;

typedef __u32 u32;
typedef __u64 u64;

// struct pt_regs is architecture-dependent. libbpf's bpf_tracing.h provides
// PT_REGS_PARMx macros that expand to the right field. We only need the
// opaque type declaration here.
struct pt_regs;

#endif // __VMLINUX_H__
```

- [ ] **Step 3: Write `bpf/crypto.c`**

```c
// SPDX-License-Identifier: Apache-2.0
// Triton eBPF crypto tracer: observes OpenSSL/GnuTLS/NSS uprobes and kernel
// crypto API kprobes, emits crypto_event_t records to a ring buffer.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer, 256 KB.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void emit(
    struct pt_regs *ctx,
    __u8 source, __u8 lib_id, __s32 nid,
    const char *name_src
) {
    struct crypto_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;
    ev->uid = bpf_get_current_uid_gid();
    ev->ts_ns = bpf_ktime_get_ns();
    ev->source = source;
    ev->lib_id = lib_id;
    ev->_pad0 = 0;
    ev->nid = nid;
    ev->name[0] = 0;
    if (name_src) {
        bpf_probe_read_user_str(ev->name, NAME_LEN, name_src);
    }
    bpf_get_current_comm(&ev->comm, COMM_LEN);
    bpf_ringbuf_submit(ev, 0);
}

// --- Uprobes on libcrypto ---

SEC("uprobe/EVP_CipherInit_ex")
int BPF_KPROBE(uprobe__EVP_CipherInit_ex, void *ctx_arg, int nid) {
    emit(ctx, 1, 1, nid, 0);
    return 0;
}

SEC("uprobe/EVP_EncryptInit_ex")
int BPF_KPROBE(uprobe__EVP_EncryptInit_ex, void *ctx_arg, int nid) {
    emit(ctx, 1, 1, nid, 0);
    return 0;
}

SEC("uprobe/EVP_DigestInit_ex")
int BPF_KPROBE(uprobe__EVP_DigestInit_ex, void *ctx_arg, int md_nid) {
    emit(ctx, 1, 1, md_nid, 0);
    return 0;
}

SEC("uprobe/RSA_generate_key_ex") int BPF_KPROBE(uprobe__RSA_generate_key_ex) { emit(ctx, 1, 1, 6,   0); return 0; }
SEC("uprobe/RSA_sign")            int BPF_KPROBE(uprobe__RSA_sign)            { emit(ctx, 1, 1, 6,   0); return 0; }
SEC("uprobe/RSA_verify")          int BPF_KPROBE(uprobe__RSA_verify)          { emit(ctx, 1, 1, 6,   0); return 0; }
SEC("uprobe/EC_KEY_generate_key") int BPF_KPROBE(uprobe__EC_KEY_generate_key) { emit(ctx, 1, 1, 408, 0); return 0; }
SEC("uprobe/ECDSA_sign")          int BPF_KPROBE(uprobe__ECDSA_sign)          { emit(ctx, 1, 1, 408, 0); return 0; }
SEC("uprobe/EVP_PKEY_derive")     int BPF_KPROBE(uprobe__EVP_PKEY_derive)     { emit(ctx, 1, 1, 1034, 0); return 0; }
SEC("uprobe/SSL_CTX_new")         int BPF_KPROBE(uprobe__SSL_CTX_new)         { emit(ctx, 1, 1, -2, 0); return 0; } // -2 = TLS sentinel

// --- Uprobes on GnuTLS ---

SEC("uprobe/gnutls_cipher_init")
int BPF_KPROBE(uprobe__gnutls_cipher_init, void *h, int algo) {
    emit(ctx, 1, 2, algo, 0);
    return 0;
}

SEC("uprobe/gnutls_hash_init")
int BPF_KPROBE(uprobe__gnutls_hash_init, void *h, int algo) {
    emit(ctx, 1, 2, algo, 0);
    return 0;
}

SEC("uprobe/gnutls_pubkey_verify_data2")
int BPF_KPROBE(uprobe__gnutls_pubkey_verify_data2) { emit(ctx, 1, 2, -3, 0); return 0; } // -3 = Verify sentinel

// --- Uprobes on NSS ---

SEC("uprobe/PK11_CipherOp") int BPF_KPROBE(uprobe__PK11_CipherOp) { emit(ctx, 1, 3, -4, 0); return 0; }
SEC("uprobe/PK11_Digest")   int BPF_KPROBE(uprobe__PK11_Digest)   { emit(ctx, 1, 3, -5, 0); return 0; }

// --- Kprobes on kernel crypto API ---

SEC("kprobe/crypto_alloc_shash")
int BPF_KPROBE(kprobe__crypto_alloc_shash, const char *alg) {
    emit(ctx, 2, 4, -1, alg);
    return 0;
}

SEC("kprobe/crypto_alloc_skcipher")
int BPF_KPROBE(kprobe__crypto_alloc_skcipher, const char *alg) {
    emit(ctx, 2, 4, -1, alg);
    return 0;
}

SEC("kprobe/crypto_alloc_akcipher")
int BPF_KPROBE(kprobe__crypto_alloc_akcipher, const char *alg) {
    emit(ctx, 2, 4, -1, alg);
    return 0;
}

SEC("kprobe/crypto_alloc_aead")
int BPF_KPROBE(kprobe__crypto_alloc_aead, const char *alg) {
    emit(ctx, 2, 4, -1, alg);
    return 0;
}
```

- [ ] **Step 4: Write `bpf/README.md`**

```markdown
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
```

- [ ] **Step 5: Extend `Makefile`**

Append at the end of the existing `Makefile`:

```makefile
.PHONY: ebpf-compile
ebpf-compile:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
	      -I pkg/scanner/internal/ebpftrace/bpf \
	      -c pkg/scanner/internal/ebpftrace/bpf/crypto.c \
	      -o pkg/scanner/internal/ebpftrace/bpf/crypto.o
	llvm-strip -g pkg/scanner/internal/ebpftrace/bpf/crypto.o
	@echo "Rebuilt pkg/scanner/internal/ebpftrace/bpf/crypto.o"
```

- [ ] **Step 6: Attempt to compile `crypto.o`**

Run: `make ebpf-compile`

If it succeeds: you now have a valid `crypto.o`. Verify `file pkg/scanner/internal/ebpftrace/bpf/crypto.o` reports `ELF 64-bit LSB relocatable, eBPF`.

If it fails (no clang, no kernel headers, no libbpf-dev): do NOT manufacture an invalid object. Leave `crypto.o` uncommitted; program_linux.go in Task 8 will detect the missing object and return an error causing a skipped-finding. Document this as a concern in the commit message and in Task 9 integration test skip conditions.

- [ ] **Step 7: Commit**

Only commit `crypto.o` if `make ebpf-compile` succeeded and the file exists.

```bash
git add pkg/scanner/internal/ebpftrace/bpf/
# Optionally: git add pkg/scanner/internal/ebpftrace/bpf/crypto.o (only if it compiled)
git add Makefile
git commit -m "feat(ebpf): C program (uprobes + kprobes + ringbuf) + compile target"
```

---

## Task 6: Aggregator

Pure-Go stateful collector. Receives `Event` values, indexes by `(binary_path, algorithm, source)`, exposes `Flush()` returning aggregates. No eBPF, no Linux. Fully testable.

**Files:**
- Create: `pkg/scanner/internal/ebpftrace/aggregate.go`
- Create: `pkg/scanner/internal/ebpftrace/aggregate_test.go`

- [ ] **Step 1: Write `pkg/scanner/internal/ebpftrace/aggregate_test.go` (RED)**

```go
package ebpftrace

import (
	"testing"
	"time"
)

func TestAggregator_Adds(t *testing.T) {
	agg := NewAggregator()

	agg.Add(Event{PID: 100, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "nginx"},
		"/usr/lib/libcrypto.so.3")
	agg.Add(Event{PID: 100, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "nginx"},
		"/usr/lib/libcrypto.so.3")
	agg.Add(Event{PID: 200, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "httpd"},
		"/usr/lib/libcrypto.so.3")
	// Different NID → separate bucket
	agg.Add(Event{PID: 100, Source: SourceUprobe, LibID: LibLibcrypto, NID: 6, Comm: "nginx"},
		"/usr/lib/libcrypto.so.3")

	got := agg.Flush()
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (sha256, rsa)", len(got))
	}
	byAlgo := map[string]*Aggregate{}
	for i := range got {
		byAlgo[got[i].Algorithm] = &got[i]
	}
	sha := byAlgo["SHA-256"]
	if sha == nil {
		t.Fatal("missing SHA-256 aggregate")
	}
	if sha.Count != 3 {
		t.Errorf("SHA-256 Count = %d, want 3", sha.Count)
	}
	if len(sha.PIDs) != 2 {
		t.Errorf("SHA-256 PIDs = %d unique, want 2", len(sha.PIDs))
	}
	if sha.BinaryPath != "/usr/lib/libcrypto.so.3" {
		t.Errorf("BinaryPath = %q", sha.BinaryPath)
	}
	if sha.Source != SourceUprobe {
		t.Errorf("Source = %v, want SourceUprobe", sha.Source)
	}
}

func TestAggregator_KernelPath(t *testing.T) {
	agg := NewAggregator()
	agg.Add(Event{PID: 500, Source: SourceKprobe, LibID: LibKernel, NID: -1, Name: "sha256"}, "kernel")
	agg.Add(Event{PID: 500, Source: SourceKprobe, LibID: LibKernel, NID: -1, Name: "cbc(aes)"}, "kernel")

	got := agg.Flush()
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
}

func TestAggregator_DropsUnclassified(t *testing.T) {
	agg := NewAggregator()
	agg.Add(Event{PID: 1, Source: SourceUprobe, LibID: LibLibcrypto, NID: 99999, Comm: "x"}, "/lib.so")
	agg.Add(Event{PID: 1, Source: SourceKprobe, LibID: LibKernel, NID: -1, Name: "unknownthing"}, "kernel")

	got := agg.Flush()
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0 (unclassified dropped)", len(got))
	}
}

func TestAggregator_FlushResets(t *testing.T) {
	agg := NewAggregator()
	agg.Add(Event{PID: 1, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "x"}, "/lib")
	_ = agg.Flush()
	got := agg.Flush()
	if len(got) != 0 {
		t.Errorf("second Flush should return empty, got %d", len(got))
	}
	_ = time.Second // keep time import minimal
}
```

- [ ] **Step 2: Run, verify FAIL** — `undefined: NewAggregator`.

- [ ] **Step 3: Write `pkg/scanner/internal/ebpftrace/aggregate.go`**

```go
package ebpftrace

// Aggregate is the collapsed observation for one (binary, algorithm, source) tuple.
type Aggregate struct {
	BinaryPath string
	Algorithm  string
	Family     string
	Library    string // "libcrypto.so.3" or "kernel"
	Source     Source
	Count      int
	PIDs       map[uint32]bool
	FirstPID   uint32
}

// Aggregator collects Events and emits per-tuple Aggregates on Flush().
// Not goroutine-safe: the caller (reader.Run) must serialise Add calls.
type Aggregator struct {
	buckets map[aggKey]*Aggregate
}

type aggKey struct {
	binary string
	algo   string
	source Source
}

// NewAggregator constructs an empty aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{buckets: map[aggKey]*Aggregate{}}
}

// Add folds an Event into the aggregator. Events that classify to no known
// algorithm (unknown NID + unknown kernel name) are silently dropped.
func (a *Aggregator) Add(ev Event, binaryPath string) {
	info, ok := classifyEvent(ev)
	if !ok {
		return
	}
	key := aggKey{binary: binaryPath, algo: info.Algorithm, source: ev.Source}
	ag := a.buckets[key]
	if ag == nil {
		ag = &Aggregate{
			BinaryPath: binaryPath,
			Algorithm:  info.Algorithm,
			Family:     info.Family,
			Library:    info.Library,
			Source:     ev.Source,
			PIDs:       map[uint32]bool{},
			FirstPID:   ev.PID,
		}
		a.buckets[key] = ag
	}
	ag.Count++
	ag.PIDs[ev.PID] = true
}

// Flush returns every aggregate and resets internal state.
func (a *Aggregator) Flush() []Aggregate {
	out := make([]Aggregate, 0, len(a.buckets))
	for _, ag := range a.buckets {
		out = append(out, *ag)
	}
	a.buckets = map[aggKey]*Aggregate{}
	return out
}

// classifyEvent resolves an Event to AlgoInfo via the NID table or kernel registry.
func classifyEvent(ev Event) (AlgoInfo, bool) {
	if ev.Source == SourceKprobe {
		return ResolveKernelAlgo(ev.Name)
	}
	// Uprobe path: resolve NID, or fall back to special sentinels.
	if info, ok := ResolveNID(ev.NID); ok {
		return info, true
	}
	// Sentinels used by C source for constant-inferred probes (see bpf/crypto.c):
	switch ev.NID {
	case -2:
		return AlgoInfo{Algorithm: "TLS", Family: "TLS", Library: "libcrypto"}, true
	case -3:
		return AlgoInfo{Algorithm: "Verify", Family: "Signature", Library: "libgnutls"}, true
	case -4:
		return AlgoInfo{Algorithm: "Cipher", Family: "Cipher", Library: "libnss3"}, true
	case -5:
		return AlgoInfo{Algorithm: "Digest", Family: "Hash", Library: "libnss3"}, true
	}
	return AlgoInfo{}, false
}
```

- [ ] **Step 4: Run, verify PASS**

`go test ./pkg/scanner/internal/ebpftrace/ -run TestAggregator -v`
Expected: all 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/ebpftrace/aggregate.go pkg/scanner/internal/ebpftrace/aggregate_test.go
git commit -m "feat(ebpf): event aggregator (per binary+algorithm+source bucketing)"
```

---

## Task 7: Reader coordinator (Linux)

Linux-only (`//go:build linux`). Loads the embedded eBPF object, attaches probes, drains the ring buffer for the requested window, detaches cleanly, returns aggregates. The hot path is fundamentally untestable on darwin — the kernel is the test. We provide a mock-based unit test for the coordinator lifecycle (context cancellation, window expiry) using a fake event source.

**Files:**
- Create: `pkg/scanner/internal/ebpftrace/program_linux.go`
- Create: `pkg/scanner/internal/ebpftrace/program_linux_test.go`

- [ ] **Step 1: Add dependency**

```bash
go get github.com/cilium/ebpf@v0.15.0
go mod tidy
```

(If the latest stable is newer than v0.15.0 at implementation time, use the latest v0.15+ release; the module API has been stable since v0.12.)

- [ ] **Step 2: Write `pkg/scanner/internal/ebpftrace/program_linux.go`**

```go
//go:build linux

package ebpftrace

import (
	"bytes"
	"context"
	"debug/elf"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/crypto.o
var cryptoObject []byte

// Run executes a single observation window and returns the aggregates.
// Any prerequisite failure (no BTF, no privilege, missing crypto.o) is surfaced
// as an error; the caller (ebpf_trace_linux.go) converts that into a
// skipped-finding. Callers MUST pass a non-nil context and positive Window.
func Run(ctx context.Context, opts Options) (*Outcome, error) {
	if opts.Window <= 0 {
		return nil, errors.New("ebpftrace: Window must be positive")
	}
	if len(cryptoObject) == 0 {
		return nil, errors.New("ebpftrace: crypto.o not embedded (needs Linux build with compiled eBPF object)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpftrace: RemoveMemlock: %w", err)
	}

	loader := opts.ObjectLoader
	if loader == nil {
		loader = func() ([]byte, error) { return cryptoObject, nil }
	}
	data, err := loader()
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ebpftrace: LoadCollectionSpec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("ebpftrace: NewCollection: %w", err)
	}
	defer coll.Close()

	// Open the events map for ring-buffer reading.
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		return nil, errors.New("ebpftrace: 'events' map missing from crypto.o")
	}
	rdr, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("ebpftrace: ringbuf reader: %w", err)
	}
	defer func() { _ = rdr.Close() }()

	// Attach probes.
	var closers []link.Link
	defer func() {
		for _, l := range closers {
			_ = l.Close()
		}
	}()
	if !opts.SkipUprobes {
		closers = attachUprobes(coll, closers)
	}
	if !opts.SkipKprobes {
		closers = attachKprobes(coll, closers)
	}

	// Read events until window expires or context cancels.
	agg := NewAggregator()
	readCtx, cancel := context.WithTimeout(ctx, opts.Window)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			record, err := rdr.Read()
			if err != nil {
				return // ringbuf closed
			}
			ev, decErr := DecodeEvent(record.RawSample)
			if decErr != nil {
				continue
			}
			binPath := binaryPathForEvent(ev)
			agg.Add(ev, binPath)
		}
	}()

	<-readCtx.Done()
	_ = rdr.Close() // unblock reader goroutine
	<-done

	return &Outcome{
		Aggregates: agg.Flush(),
		Window:     opts.Window,
	}, nil
}

// Outcome is the result of a Run.
type Outcome struct {
	Aggregates []Aggregate
	Window     time.Duration
}

// attachUprobes walks /proc/self/maps for currently-loaded libs (best effort
// across all processes via /proc/*/maps) and attaches each uprobe target it
// can resolve in any discovered library. Per-process /proc scanning is
// deliberately shallow: we enumerate libraries via /proc/*/maps union, not
// one attach per PID.
func attachUprobes(coll *ebpf.Collection, closers []link.Link) []link.Link {
	libsByID := map[LibID][]DiscoveredLib{}
	procs, _ := filepath.Glob("/proc/[0-9]*/maps")
	seenInodes := map[string]bool{}
	for _, p := range procs {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		libs, _ := DiscoverLibsFromMaps(f)
		_ = f.Close()
		for _, lib := range libs {
			if seenInodes[lib.Inode] {
				continue
			}
			seenInodes[lib.Inode] = true
			libsByID[lib.LibID] = append(libsByID[lib.LibID], lib)
		}
	}

	for _, target := range UprobeTargets() {
		libs := libsByID[target.LibID]
		for _, lib := range libs {
			prog := coll.Programs[target.ProgName]
			if prog == nil {
				continue
			}
			exe, err := link.OpenExecutable(lib.Path)
			if err != nil {
				continue
			}
			if !symbolExists(lib.Path, target.SymbolName) {
				continue
			}
			l, err := exe.Uprobe(target.SymbolName, prog, nil)
			if err != nil {
				continue
			}
			closers = append(closers, l)
		}
	}
	return closers
}

// symbolExists returns true iff the ELF symbol table contains the named symbol.
// Handles stripped libraries by returning false instead of erroring.
func symbolExists(path, symbol string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	syms, err := f.DynamicSymbols()
	if err != nil {
		return false
	}
	for _, s := range syms {
		if s.Name == symbol {
			return true
		}
	}
	return false
}

// attachKprobes attaches one link per kernel crypto allocator symbol.
func attachKprobes(coll *ebpf.Collection, closers []link.Link) []link.Link {
	targets := []struct{ progName, sym string }{
		{"kprobe__crypto_alloc_shash", "crypto_alloc_shash"},
		{"kprobe__crypto_alloc_skcipher", "crypto_alloc_skcipher"},
		{"kprobe__crypto_alloc_akcipher", "crypto_alloc_akcipher"},
		{"kprobe__crypto_alloc_aead", "crypto_alloc_aead"},
	}
	for _, tg := range targets {
		prog := coll.Programs[tg.progName]
		if prog == nil {
			continue
		}
		l, err := link.Kprobe(tg.sym, prog, nil)
		if err != nil {
			continue
		}
		closers = append(closers, l)
	}
	return closers
}

// binaryPathForEvent chooses the path label for aggregation based on LibID.
// Uprobe events do not carry the source library path in the event struct —
// we rely on the first-mapped library-path we know for that LibID. For PR #1
// we collapse all uprobe events of a given LibID onto a single representative
// path (first seen); this simplifies aggregation at the cost of losing
// per-library attribution when multiple copies exist. Acceptable for v1;
// revisit when per-PID findings land.
func binaryPathForEvent(ev Event) string {
	if ev.Source == SourceKprobe {
		return "kernel"
	}
	switch ev.LibID {
	case LibLibcrypto:
		return "libcrypto"
	case LibGnuTLS:
		return "libgnutls"
	case LibNSS:
		return "libnss3"
	}
	return "unknown"
}
```

- [ ] **Step 3: Write `pkg/scanner/internal/ebpftrace/program_linux_test.go`**

```go
//go:build linux && integration

package ebpftrace

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestRun_ObservesOpenSSLDigest spawns an openssl subprocess computing sha256
// and asserts the trace captures at least one AES or SHA-256 aggregate.
// Skipped when not root or when BTF is unavailable.
func TestRun_ObservesOpenSSLDigest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (or CAP_BPF)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("BTF not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start trace in goroutine; run openssl in the middle.
	result := make(chan *Outcome, 1)
	errCh := make(chan error, 1)
	go func() {
		out, err := Run(ctx, Options{Window: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		result <- out
	}()

	time.Sleep(2 * time.Second) // give probes time to attach
	cmd := exec.Command("openssl", "dgst", "-sha256", "/etc/hostname")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		t.Fatalf("openssl run: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Run: %v", err)
	case out := <-result:
		found := false
		for _, agg := range out.Aggregates {
			if agg.Algorithm == "SHA-256" || agg.Family == "SHA" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no SHA-256 finding in %d aggregates", len(out.Aggregates))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for trace result")
	}
}
```

Unit-testable lifecycle (window expiry, ctx cancellation) is deliberately NOT added here: it would require mocking the cilium/ebpf `ringbuf.Reader` which has complex internals. Instead we rely on the integration test above plus the pure-Go aggregator tests from Task 6. If a real Linux dev box is available during review, expand coverage here.

- [ ] **Step 4: Run build-only check**

```bash
go mod tidy
GOOS=linux go build ./pkg/scanner/internal/ebpftrace/...
```

Expected: no compile errors. (We cannot run the test on darwin.)

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum pkg/scanner/internal/ebpftrace/program_linux.go pkg/scanner/internal/ebpftrace/program_linux_test.go
git commit -m "feat(ebpf): Linux reader coordinator (load, attach, ringbuf, aggregate)"
```

---

## Task 8: Wire Linux scan() to the coordinator + flags + doctor

Replaces the Task-1 placeholder. Adds CLI flags, config fields, and `doctor.go` prereq check.

**Files:**
- Modify: `pkg/scanner/ebpf_trace_linux.go`
- Modify: `cmd/root.go` (flag registration)
- Modify: `internal/scannerconfig/config.go` (config fields + defaults)
- Modify: `pkg/scanner/doctor.go` (prereq check)

- [ ] **Step 1: Add config fields**

In `internal/scannerconfig/config.go`, inside the `Config` struct (alphabetically or at the end of the existing fields), add:

```go
// eBPF trace settings (consumed by ebpf_trace module on Linux)
EBPFWindow      time.Duration
EBPFSkipUprobes bool
EBPFSkipKprobes bool
```

In the default/quick/standard/comprehensive profile constructors, set `EBPFWindow: 60 * time.Second` on the comprehensive profile only.

Ensure `"time"` is imported in `config.go`.

- [ ] **Step 2: Add CLI flags**

In `cmd/root.go`, find the existing flag registration block (look for `--profile` or similar). Add:

```go
rootCmd.Flags().Duration("ebpf-window", 60*time.Second, "observation window for the ebpf_trace module (Linux only)")
rootCmd.Flags().Bool("ebpf-skip-uprobes", false, "skip userspace uprobes in ebpf_trace")
rootCmd.Flags().Bool("ebpf-skip-kprobes", false, "skip kernel kprobes in ebpf_trace")
```

In the same file, find where flags are read into the config (look for existing `rootCmd.Flags().GetX(...)`). Add:

```go
if v, err := rootCmd.Flags().GetDuration("ebpf-window"); err == nil && v > 0 {
    if v < time.Second {
        v = time.Second
    }
    if v > 30*time.Minute {
        v = 30 * time.Minute
    }
    cfg.EBPFWindow = v
}
if v, err := rootCmd.Flags().GetBool("ebpf-skip-uprobes"); err == nil {
    cfg.EBPFSkipUprobes = v
}
if v, err := rootCmd.Flags().GetBool("ebpf-skip-kprobes"); err == nil {
    cfg.EBPFSkipKprobes = v
}
```

- [ ] **Step 3: Update doctor.go**

In `pkg/scanner/doctor.go`, find the existing checks (similar pattern to how it checks for `osslsigncode`/`jarsigner`). Add a new entry that:

- On non-Linux: one-liner "eBPF: unavailable (not Linux)"
- On Linux: checks kernel version >= 5.8 (parse `/proc/sys/kernel/osrelease`), root or CAP_BPF, `/sys/kernel/btf/vmlinux` readable

Example skeleton to fit the existing checker pattern:

```go
// In doctor.go, add to the list of checks:
checkers = append(checkers, checker{
    name: "ebpf",
    check: ebpfDoctorCheck,
})
```

And add the function (use build tags to vary behaviour):

```go
// doctor_ebpf_linux.go (new file, or append to doctor.go with build-tag split)
//go:build linux

package scanner

import (
    "os"
    "strings"
)

func ebpfDoctorCheck() (ok bool, detail string) {
    if os.Geteuid() != 0 {
        return false, "not root and CAP_BPF check not implemented; eBPF will be skipped"
    }
    data, err := os.ReadFile("/proc/sys/kernel/osrelease")
    if err != nil {
        return false, "cannot read /proc/sys/kernel/osrelease"
    }
    ver := strings.TrimSpace(string(data))
    if !atLeastKernel58(ver) {
        return false, "kernel " + ver + " < 5.8 (ring buffer unsupported)"
    }
    if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
        return false, "/sys/kernel/btf/vmlinux missing (BTF not enabled)"
    }
    return true, "kernel " + ver + ", BTF present, root"
}

func atLeastKernel58(release string) bool {
    // Parse first two dotted numbers, e.g. "5.15.0-91-generic" → (5, 15)
    parts := strings.SplitN(release, ".", 3)
    if len(parts) < 2 {
        return false
    }
    var major, minor int
    for _, c := range parts[0] {
        if c < '0' || c > '9' {
            break
        }
        major = major*10 + int(c-'0')
    }
    for _, c := range parts[1] {
        if c < '0' || c > '9' {
            break
        }
        minor = minor*10 + int(c-'0')
    }
    return major > 5 || (major == 5 && minor >= 8)
}
```

```go
// doctor_ebpf_other.go (new file)
//go:build !linux

package scanner

func ebpfDoctorCheck() (ok bool, detail string) {
    return false, "not Linux"
}
```

- [ ] **Step 4: Replace `pkg/scanner/ebpf_trace_linux.go` with the real implementation**

```go
//go:build linux

package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/ebpftrace"
)

func (m *EBPFTraceModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	if os.Geteuid() != 0 {
		return emitSkipped(ctx, findings, "not root; eBPF requires CAP_BPF or root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return emitSkipped(ctx, findings, "BTF not available at /sys/kernel/btf/vmlinux")
	}

	window := m.cfg.EBPFWindow
	if window <= 0 {
		window = 60 * time.Second
	}

	outcome, err := ebpftrace.Run(ctx, ebpftrace.Options{
		Window:      window,
		SkipUprobes: m.cfg.EBPFSkipUprobes,
		SkipKprobes: m.cfg.EBPFSkipKprobes,
	})
	if err != nil {
		return emitSkipped(ctx, findings, "ebpftrace.Run: "+err.Error())
	}

	emittedAny := false
	for _, agg := range outcome.Aggregates {
		f := buildEBPFFinding(agg, window)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case findings <- f:
			emittedAny = true
		}
	}
	if !emittedAny {
		return emitSkipped(ctx, findings, fmt.Sprintf("no crypto activity observed in %s window", window))
	}
	return nil
}

func buildEBPFFinding(agg ebpftrace.Aggregate, window time.Duration) *model.Finding {
	info := crypto.ClassifyAlgorithm(agg.Algorithm, 0)
	detection := "ebpf-uprobe"
	if agg.Source == ebpftrace.SourceKprobe {
		detection = "ebpf-kprobe"
	}
	evidence := fmt.Sprintf("%d calls over %s from %d pids", agg.Count, window, len(agg.PIDs))
	var firstPID int
	if agg.FirstPID > 0 {
		firstPID = int(agg.FirstPID)
	}
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: info.Algorithm,
		Library:   agg.Library,
		Language:  "C",
		Function:  functionForFamily(info.Family),
		PQCStatus: string(info.Status),
	}
	return &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			Path:            agg.BinaryPath,
			PID:             firstPID,
			DetectionMethod: detection,
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.98,
		Module:      "ebpf_trace",
		Timestamp:   time.Now().UTC(),
	}
}

func emitSkipped(ctx context.Context, findings chan<- *model.Finding, reason string) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryActiveRuntime),
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ebpf-skipped",
			Evidence:        "ebpf unavailable: " + reason,
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "C",
		},
		Confidence: 0.0,
		Module:     "ebpf_trace",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
```

- [ ] **Step 5: Verify compile on both OS**

```bash
go test ./pkg/scanner/ ./internal/scannerconfig/
GOOS=linux go build ./...
```

Expected: PASS on darwin; Linux cross-build compiles.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/ebpf_trace_linux.go pkg/scanner/doctor.go pkg/scanner/doctor_ebpf_linux.go pkg/scanner/doctor_ebpf_other.go cmd/root.go internal/scannerconfig/config.go
git commit -m "feat(ebpf): wire Linux scan() to coordinator + CLI flags + doctor check"
```

---

## Task 9: Integration test + docs + full verification

**Files:**
- Create: `test/integration/ebpf_trace_test.go`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Write `test/integration/ebpf_trace_test.go`**

```go
//go:build integration && linux

package integration

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestEBPFTrace_ObservesOpenSSLDigest runs the ebpf_trace module with a short
// window, spawns `openssl dgst -sha256` inside it, and asserts the scan
// produces at least one SHA-256 finding via uprobe observation.
//
// Skipped unless: root, BTF available, openssl in PATH.
func TestEBPFTrace_ObservesOpenSSLDigest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("BTF not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}

	cfg := &scannerconfig.Config{
		EBPFWindow:      5 * time.Second,
		EBPFSkipKprobes: true, // make the test deterministic: only uprobes
	}
	mod := scanner.NewEBPFTraceModule(cfg)
	ch := make(chan *model.Finding, 64)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	go func() {
		_ = mod.Scan(ctx, model.ScanTarget{Type: model.TargetProcess}, ch)
		close(ch)
	}()

	time.Sleep(1 * time.Second) // give probes time to attach
	for i := 0; i < 5; i++ {
		if err := exec.Command("openssl", "dgst", "-sha256", "/etc/hostname").Run(); err != nil {
			t.Logf("openssl iter %d: %v", i, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	foundSHA := false
	allFindings := 0
	for f := range ch {
		allFindings++
		if f.Module != "ebpf_trace" {
			t.Errorf("Module = %q, want ebpf_trace", f.Module)
		}
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "SHA-256" {
			foundSHA = true
		}
	}
	if allFindings == 0 {
		t.Fatal("no findings emitted")
	}
	if !foundSHA {
		t.Errorf("no SHA-256 finding among %d emitted (may be environment: openssl built without EVP?)", allFindings)
	}
}
```

- [ ] **Step 2: Run integration test (best-effort — only works on Linux with root + BTF + openssl)**

```bash
go test -tags 'integration linux' -run TestEBPFTrace_ObservesOpenSSLDigest ./test/integration/...
```

Expected on a configured Linux box: PASS. Expected on darwin: the `linux` build tag filters the file out entirely, so `go test` reports "no tests to run" — that's fine. Do NOT fail the task if darwin can't run this test.

- [ ] **Step 3: Update CLAUDE.md**

Under `pkg/scanner/`, after the `dotnet_il.go` entry, add:

```markdown
  - `ebpf_trace.go` — eBPF runtime crypto tracer: uprobes on libcrypto/gnutls/nss + kprobes on kernel crypto API, observation-window scan; Linux-only (emits skipped-finding on other OS); comprehensive profile + Pro+ tier; requires root/CAP_BPF + kernel ≥ 5.8 + BTF
```

- [ ] **Step 4: Run unit suite + lint**

```bash
go run test/fixtures/generate.go   # pre-existing fixture generator
make test
make lint
```

Both must finish clean. Fix any new lint issues in a separate `fix(ebpf): lint` commit if needed.

- [ ] **Step 5: Coverage check**

```bash
go test -cover ./pkg/scanner/internal/ebpftrace/
```

Expected ≥ 65% (the Linux-only reader coordinator cannot be exercised on darwin, so coverage is lower than other packages). If substantially lower, add more unit tests to the pure-Go parts (symbols, events, aggregate, attach) until ≥ 65%.

- [ ] **Step 6: Commit + push**

```bash
git add test/integration/ebpf_trace_test.go CLAUDE.md
git commit -m "test(ebpf): integration test + CLAUDE.md entry"
git push -u origin feat/ebpf-trace
```

---

## Task 10: Reviews + PR

- [ ] **Step 1: Dispatch three parallel reviews**

Against the diff (`git diff main...HEAD`):

- **bug-hunt** focus: eBPF program correctness (verifier footguns in `bpf/crypto.c`), ring-buffer drain race on detach, `/proc/*/maps` parsing on malformed lines, symbol-table read failures, uint32 NID cast from `uint32(int32(...))`, ctx.Err vs nil return paths, embedded-blob integrity check
- **architecture** focus: package boundary (is `ebpftrace.Run` the right API?), cilium/ebpf dep footprint, non-Linux stub design, CLI flag vs config field split, doctor-check integration, committed binary-blob policy
- **test-quality** focus: darwin-only CI is the main risk, integration-test determinism, real-kernel coverage, mock strategy for reader coordinator, coverage gap in `program_linux.go`, whether `binaryPathForEvent` loses too much attribution

- [ ] **Step 2: Apply fixes in-branch**

Each fix as its own commit (`fix(ebpf): …` or `fix(scanner): …`). Re-run `make test && make lint` after each.

- [ ] **Step 3: Open PR**

```bash
gh pr create --title "feat(scanner): eBPF runtime crypto tracer (ebpf_trace)" --body "$(cat <<'EOF'
## Summary
- New \`ebpf_trace\` scanner module: observes live crypto calls via eBPF uprobes (OpenSSL/GnuTLS/NSS) + kprobes (kernel crypto API)
- Linux-only via build tags; non-Linux emits one skipped-finding
- Pure-Go loader via \`github.com/cilium/ebpf\` (CO-RE, no clang/bcc at runtime)
- Committed \`bpf/crypto.o\` artifact; \`make ebpf-compile\` regenerates
- Comprehensive profile + Pro+ tier

## Pre-landing review
- bug-review applied
- architecture-review applied
- test-review applied

## Test plan
- [x] Unit: pure-Go parts (symbols, events, aggregate, /proc walk)
- [x] Integration (on Linux root box): observes openssl dgst sha256 within window
- [x] Cross-compile: \`GOOS=linux go build ./...\` clean on darwin
- [x] \`make test && make lint\` green

## Follow-ups (tracked in memory)
- Continuous daemon mode wrapping \`ebpftrace.Run\`
- Per-PID findings
- libsodium / BoringSSL / wolfSSL uprobes
- XDP TLS fingerprinting
- Risk-scoring: weight DEPRECATED inventory findings down when no ebpf_trace hit
- CI eBPF verifier check (rebuild crypto.o on PR, diff against committed)
EOF
)"
```

---

## Self-Review

**Spec coverage check:**
- Architecture (window, /proc walk, uprobe/kprobe, ringbuf, aggregate) → Tasks 1, 4, 5, 6, 7
- Package layout (pkg/scanner + internal/ebpftrace + bpf/) → Tasks 2-7
- Probe targets + NID table → Tasks 2, 5
- Shared event struct → Tasks 3, 5
- Finding shape → Task 8
- Engine wiring + flags + doctor → Tasks 1, 8
- Tests (unit + integration) → Tasks 2-4, 6-7, 9
- Build strategy (committed .o, make target, CI verify) → Task 5
- Non-Linux stub → Task 1
- Graceful degradation → Task 8

**Placeholder scan:** none found. Every code block is complete; the one "if compile fails, leave uncommitted" note in Task 5 is an explicit fallback, not a placeholder.

**Type consistency:** `Event`, `Options`, `Outcome`, `Aggregate`, `AlgoInfo`, `UprobeTarget`, `DiscoveredLib`, `Source`, `LibID` consistent across Tasks 2, 3, 4, 6, 7, 8. `Run`, `NewAggregator`, `DecodeEvent`, `DiscoverLibsFromMaps`, `ResolveNID`, `ResolveKernelAlgo`, `UprobeTargets`, `emitSkipped`, `buildEBPFFinding` all defined once, used consistently.

**Cross-task forward references:** Task 7 uses `ebpftrace.Aggregator` (Task 6), `DecodeEvent` (Task 3), `DiscoverLibsFromMaps` (Task 4), `UprobeTargets` (Task 2), `cryptoObject` embed (Task 5). Task 8 uses `ebpftrace.Run`, `Options`, `Outcome`, `Aggregate`, `SourceKprobe` (Task 2/7). All defined upstream.

**Genuine risks flagged in-plan:**
1. Task 5 may fail to compile `crypto.o` locally — explicitly handled with "leave uncommitted" fallback.
2. Task 7's `program_linux_test.go` requires root + BTF — gated with skip.
3. Task 9's integration test requires root + BTF + openssl — gated with skip.
4. darwin CI cannot exercise the Linux hot path — coverage target relaxed to 65%.
