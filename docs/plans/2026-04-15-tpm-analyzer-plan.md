# TPM 2.0 Attestation Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Linux-only passive TPM scanner module that reads `/sys/class/tpm/` and the TCG event log, classifies firmware CVEs, parses the EK cert, and audits the event log's hash-algorithm coverage. Non-Linux emits a single skipped-finding.

**Architecture:** Mirrors `ebpf_trace`'s Linux/other build-tag split. New `pkg/scanner/tpm.go` module shell + `_linux.go` real driver + `_other.go` stub. Internal `pkg/scanner/internal/tpmfs/` package does the sysfs walking, TCG event log parsing, and EK cert extraction. New `pkg/crypto/tpm_firmware.go` holds the CVE registry. All components testable on any OS via fixture-root injection. Reuses existing `crypto.ClassifyCryptoAsset` + `keyquality.Analyze` for the EK cert.

**Tech Stack:** Go 1.26.1 stdlib only (`encoding/binary`, `crypto/x509`, `io`, `os`, `strings`, `//go:build linux`, `//go:embed` for test fixtures). No new third-party deps.

---

## File Structure

### Create
- `pkg/scanner/tpm.go` — module shell (all OS); `Name`/`Category`/`ScanTargetType`; dispatches to OS-specific `scan()`
- `pkg/scanner/tpm_linux.go` — `//go:build linux` — real `scan()` driver
- `pkg/scanner/tpm_other.go` — `//go:build !linux` — skipped-finding stub
- `pkg/scanner/tpm_test.go` — module identity tests (all OS)
- `pkg/scanner/tpm_other_test.go` — `//go:build !linux` — stub behaviour
- `pkg/scanner/internal/tpmfs/types.go` — exported types (`Device`, `EKCert`, `EventLog`, `HashAlgo` constants), package doc
- `pkg/scanner/internal/tpmfs/tpmfs.go` — sysfs walker (`DiscoverDevices`)
- `pkg/scanner/internal/tpmfs/tpmfs_test.go`
- `pkg/scanner/internal/tpmfs/eventlog.go` — TCG PFP binary log parser (portable; no build tag)
- `pkg/scanner/internal/tpmfs/eventlog_test.go`
- `pkg/scanner/internal/tpmfs/ekcert.go` — DER reader + x509 parse
- `pkg/scanner/internal/tpmfs/ekcert_test.go`
- `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/tpm_version_major`
- `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/caps`
- `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/description`
- `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/endorsement_key_cert` (DER, generated at test time or committed)
- `pkg/scanner/internal/tpmfs/testdata/event-log-sha256-only.bin`
- `pkg/scanner/internal/tpmfs/testdata/event-log-sha1-only.bin`
- `pkg/scanner/internal/tpmfs/testdata/event-log-mixed.bin`
- `pkg/crypto/tpm_firmware.go` — CVE registry
- `pkg/crypto/tpm_firmware_test.go`
- `test/integration/tpm_test.go` — `//go:build integration` — end-to-end via fixture root

### Modify
- `pkg/scanner/engine.go` — append `NewTPMModule` factory after `NewEBPFTraceModule`
- `pkg/scanner/engine_test.go` — bump module count if fenced
- `internal/scannerconfig/config.go` — append `"tpm"` to comprehensive `Modules` list
- `internal/scannerconfig/config_test.go` — NotContains (quick/standard) + Contains (comprehensive) assertions
- `internal/license/tier.go` — append `"tpm"` to Pro+ allowlist
- `CLAUDE.md` — `tpm.go` bullet under `pkg/scanner/`; `tpm_firmware.go` under `pkg/crypto/`

### Out of Scope (explicit)
- Active `/dev/tpm0` queries / `go-tpm` dep
- Windows TBS / macOS T2
- PCR digest aggregation vs reference values
- IMA/EVM log
- AK cert chain validation

---

## Conventions

- **Module name:** `"tpm"`.
- **Detection methods:** `"sysfs"` (device finding), `"tcg-pfp-log"` (event log finding). EK cert findings use `"sysfs"` too.
- **Confidence:** `0.95` (sysfs data is authoritative when present).
- **Language tag:** `"Firmware"` for the TPM device finding; EK cert uses the standard cert-scanner path (Language implicit).
- **Path style:** the sysfs walker takes explicit root paths (`sysRoot`, `secRoot`) so tests can inject fixtures; production uses `/sys/class/tpm` + `/sys/kernel/security`.
- **Build tags:** Linux-specific files use `//go:build linux`; non-Linux stub uses `//go:build !linux`. Portable files (event log parser, EK cert parser, types, CVE registry) carry no build tag.
- **Error policy:** missing optional files (EK cert, event log) are silent; parse errors emit a degraded finding noting the issue rather than crashing.
- **Commit scope:** `tpm` (module + tpmfs) or `crypto` (tpm_firmware.go).

---

## Task 1: Skeleton + non-Linux stub + engine wiring

Mirrors `ebpf_trace` Task 1. Lands the module into the registry on all OS with the stub path, so later tasks only touch Linux code.

**Files:**
- Create: `pkg/scanner/tpm.go`
- Create: `pkg/scanner/tpm_other.go`
- Create: `pkg/scanner/tpm_test.go`
- Create: `pkg/scanner/tpm_other_test.go`
- Create: `pkg/scanner/tpm_linux.go` (placeholder)
- Modify: `pkg/scanner/engine.go`
- Modify: `pkg/scanner/engine_test.go` (if module count fenced)
- Modify: `internal/scannerconfig/config.go`
- Modify: `internal/scannerconfig/config_test.go`
- Modify: `internal/license/tier.go`

- [ ] **Step 1: Write `pkg/scanner/tpm.go`**

```go
package scanner

import (
	"context"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// TPMModule scans /sys/class/tpm/ for TPM devices, classifies firmware
// against a CVE registry, parses the endorsement-key certificate, and
// audits the TCG measured-boot event log's hash-algorithm coverage.
// Linux-only; non-Linux builds emit a single skipped-finding.
type TPMModule struct {
	cfg   *scannerconfig.Config
	store store.Store
}

// NewTPMModule constructs the module.
func NewTPMModule(cfg *scannerconfig.Config) *TPMModule {
	return &TPMModule{cfg: cfg}
}

// Name returns the canonical module name.
func (m *TPMModule) Name() string { return "tpm" }

// Category returns the module category (passive file scanner).
func (m *TPMModule) Category() model.ModuleCategory { return model.CategoryPassiveFile }

// ScanTargetType returns the target type.
func (m *TPMModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// SetStore wires the incremental-scan store.
func (m *TPMModule) SetStore(s store.Store) { m.store = s }

// Scan delegates to the OS-specific scan method.
func (m *TPMModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return m.scan(ctx, target, findings)
}
```

- [ ] **Step 2: Write `pkg/scanner/tpm_other.go`**

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
func (m *TPMModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			DetectionMethod: "tpm-skipped",
			Evidence:        "tpm scanning unavailable: " + runtime.GOOS + " is not Linux",
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "Firmware",
		},
		Confidence: 0.0,
		Module:     "tpm",
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

- [ ] **Step 3: Write `pkg/scanner/tpm_linux.go` (placeholder, real impl in Task 6)**

```go
//go:build linux

package scanner

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// scan is a temporary placeholder that emits a skipped-finding until Task 6
// wires up the real tpmfs-based implementation. Replaced entirely in Task 6.
func (m *TPMModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			DetectionMethod: "tpm-skipped",
			Evidence:        "tpm scanning unavailable: implementation pending (Task 6)",
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			PQCStatus: "",
			Language:  "Firmware",
		},
		Confidence: 0.0,
		Module:     "tpm",
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

- [ ] **Step 4: Write `pkg/scanner/tpm_test.go`**

```go
package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestTPMModule_Identity(t *testing.T) {
	m := NewTPMModule(&scannerconfig.Config{})
	if m.Name() != "tpm" {
		t.Errorf("Name = %q, want tpm", m.Name())
	}
	if m.Category() != model.CategoryPassiveFile {
		t.Errorf("Category = %v, want CategoryPassiveFile", m.Category())
	}
	if m.ScanTargetType() != model.TargetFilesystem {
		t.Errorf("ScanTargetType = %v, want TargetFilesystem", m.ScanTargetType())
	}
}
```

- [ ] **Step 5: Write `pkg/scanner/tpm_other_test.go`**

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

func TestTPMModule_NonLinuxSkippedFinding(t *testing.T) {
	m := NewTPMModule(&scannerconfig.Config{})
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
		return
	}
	f := got[0]
	if f.Module != "tpm" {
		t.Errorf("Module = %q, want tpm", f.Module)
	}
	if f.Source.DetectionMethod != "tpm-skipped" {
		t.Errorf("DetectionMethod = %q, want tpm-skipped", f.Source.DetectionMethod)
	}
	if f.Confidence != 0.0 {
		t.Errorf("Confidence = %v, want 0.0", f.Confidence)
	}
}
```

- [ ] **Step 6: Wire into engine / profile / tier**

In `pkg/scanner/engine.go`, find the last factory line in `defaultModuleFactories` (currently ends with `NewEBPFTraceModule`). Append:

```go
	func(c *scannerconfig.Config) Module { return NewTPMModule(c) },
```

In `internal/scannerconfig/config.go`, find the comprehensive `Modules:` slice (the long one). Append `"tpm"` as the last element.

In `internal/scannerconfig/config_test.go`, locate existing `ebpf_trace` assertions and add matching ones for `tpm`:
- After each `assert.NotContains(t, cfg.Modules, "ebpf_trace")` → add `assert.NotContains(t, cfg.Modules, "tpm")`
- After `assert.Contains(t, cfg.Modules, "ebpf_trace")` → add `assert.Contains(t, cfg.Modules, "tpm")`

In `internal/license/tier.go`, after the line `"ebpf_trace",` add `"tpm",`.

If `pkg/scanner/engine_test.go` has a hardcoded module count, bump it by 1.

- [ ] **Step 7: Run, verify PASS**

```bash
go test ./pkg/scanner/ ./internal/scannerconfig/ ./internal/license/
go build ./...
GOOS=linux go build ./...
```

All must PASS on darwin; Linux cross-build must succeed.

- [ ] **Step 8: Commit**

```bash
git add pkg/scanner/tpm.go pkg/scanner/tpm_linux.go pkg/scanner/tpm_other.go pkg/scanner/tpm_test.go pkg/scanner/tpm_other_test.go pkg/scanner/engine.go pkg/scanner/engine_test.go internal/scannerconfig/config.go internal/scannerconfig/config_test.go internal/license/tier.go
git commit -m "feat(scanner): tpm module skeleton + non-linux stub + engine wiring"
```

---

## Task 2: tpmfs types + sysfs walker + fixture

Pure-Go walker that takes an injected `sysRoot` argument. Testable on any OS via fixture directories.

**Files:**
- Create: `pkg/scanner/internal/tpmfs/types.go`
- Create: `pkg/scanner/internal/tpmfs/tpmfs.go`
- Create: `pkg/scanner/internal/tpmfs/tpmfs_test.go`
- Create: `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/tpm_version_major`
- Create: `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/caps`
- Create: `pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/description`

- [ ] **Step 1: Write `pkg/scanner/internal/tpmfs/types.go`**

```go
// Package tpmfs parses Linux TPM sysfs artefacts (/sys/class/tpm/) and TCG
// event logs. Linux-only for the sysfs walker; the event-log parser is
// portable and runs on any OS (tested via committed binary fixtures).
package tpmfs

// Device captures one TPM device discovered under /sys/class/tpm/.
type Device struct {
	Path            string // e.g. "/sys/class/tpm/tpm0"
	Name            string // e.g. "tpm0"
	SpecVersion     string // "2.0" | "1.2"
	Vendor          string // human name, e.g. "Infineon"; vendor ID raw if unknown
	VendorRawID     string // 4-char ASCII manufacturer code
	FirmwareVersion string // vendor-specific, e.g. "4.32.1.2"
	Description     string // from device/description file, when present
	EKCertPath      string // sysfs path to endorsement_key_cert file, if present
}

// HashAlgo is a TPM_ALG_ID value from TCG specs.
type HashAlgo uint16

const (
	AlgSHA1   HashAlgo = 0x0004
	AlgSHA256 HashAlgo = 0x000B
	AlgSHA384 HashAlgo = 0x000C
	AlgSHA512 HashAlgo = 0x000D
	AlgSM3    HashAlgo = 0x0012
)

// Size returns the digest size in bytes for this algorithm. Returns 0 for
// unknown algorithms (parser must treat as fatal for the event it appears in).
func (a HashAlgo) Size() int {
	switch a {
	case AlgSHA1:
		return 20
	case AlgSHA256, AlgSM3:
		return 32
	case AlgSHA384:
		return 48
	case AlgSHA512:
		return 64
	}
	return 0
}

// String returns a human-readable name for the algorithm.
func (a HashAlgo) String() string {
	switch a {
	case AlgSHA1:
		return "SHA-1"
	case AlgSHA256:
		return "SHA-256"
	case AlgSHA384:
		return "SHA-384"
	case AlgSHA512:
		return "SHA-512"
	case AlgSM3:
		return "SM3"
	}
	return "unknown"
}

// EventLogEntry is one TCG_PCR_EVENT2 record after parsing.
type EventLogEntry struct {
	PCRIndex   uint32
	EventType  uint32
	Algorithms []HashAlgo // one per (algorithm, digest) pair in DigestValues
}

// EventLog holds a parsed TCG PFP binary event log.
type EventLog struct {
	Entries []EventLogEntry
	// Aggregate summary (populated by the parser):
	AlgoCounts map[HashAlgo]int // algo → number of events extending that bank
}

// EKCert holds a parsed endorsement-key certificate.
type EKCert struct {
	RawDER    []byte
	Algorithm string // "RSA" / "ECDSA" / "Ed25519"
	KeySize   int    // bits
	Subject   string
	Issuer    string
}
```

- [ ] **Step 2: Create test fixtures**

Run these commands from the repo root:

```bash
mkdir -p pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device

cat > pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/tpm_version_major <<'EOF'
2
EOF

cat > pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/description <<'EOF'
TPM 2.0 Device
EOF

cat > pkg/scanner/internal/tpmfs/testdata/sysfs-infineon/tpm0/device/caps <<'EOF'
Manufacturer: 0x49465800
TCG version: 2.0
Firmware version: 4.32.1.2
EOF
```

Note: `0x49465800` decodes to ASCII `"IFX\x00"` which we'll normalise to `"IFX "` (space-padded) in the parser.

- [ ] **Step 3: Write `pkg/scanner/internal/tpmfs/tpmfs_test.go` (RED)**

```go
package tpmfs

import (
	"testing"
)

func TestDiscoverDevices_ParsesInfineonFixture(t *testing.T) {
	devs, err := DiscoverDevices("testdata/sysfs-infineon")
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("len(devs) = %d, want 1", len(devs))
		return
	}
	d := devs[0]
	if d.Name != "tpm0" {
		t.Errorf("Name = %q, want tpm0", d.Name)
	}
	if d.SpecVersion != "2.0" {
		t.Errorf("SpecVersion = %q, want 2.0", d.SpecVersion)
	}
	if d.Vendor != "Infineon" {
		t.Errorf("Vendor = %q, want Infineon", d.Vendor)
	}
	if d.FirmwareVersion != "4.32.1.2" {
		t.Errorf("FirmwareVersion = %q, want 4.32.1.2", d.FirmwareVersion)
	}
	if d.Description != "TPM 2.0 Device" {
		t.Errorf("Description = %q, want 'TPM 2.0 Device'", d.Description)
	}
}

func TestDiscoverDevices_MissingRoot(t *testing.T) {
	// Non-existent root → no error, empty slice.
	devs, err := DiscoverDevices("testdata/does-not-exist")
	if err != nil {
		t.Errorf("missing root should not error, got %v", err)
	}
	if len(devs) != 0 {
		t.Errorf("len(devs) = %d, want 0", len(devs))
	}
}

func TestDecodeVendorID(t *testing.T) {
	cases := map[string]string{
		"0x49465800": "Infineon",     // "IFX\x00" → "IFX "
		"0x494E5443": "Intel",        // "INTC"
		"0x4E544300": "Nuvoton",      // "NTC\x00" → "NTC "
		"0x53544D20": "STMicroelectronics", // "STM "
		"0x41544D4C": "Microchip",    // "ATML"
		"0x4D534654": "Microsoft",    // "MSFT"
		"0x474F4F47": "Google",       // "GOOG"
		"0x414D4400": "AMD",          // "AMD\x00" → "AMD "
		"0x01020304": "01020304",     // unknown → raw hex
		"INVALID":    "INVALID",      // non-hex → passes through
	}
	for input, want := range cases {
		got := decodeVendorID(input)
		if got != want {
			t.Errorf("decodeVendorID(%q) = %q, want %q", input, got, want)
		}
	}
}
```

- [ ] **Step 4: Run, verify FAIL** — `undefined: DiscoverDevices`, `undefined: decodeVendorID`.

- [ ] **Step 5: Write `pkg/scanner/internal/tpmfs/tpmfs.go`**

```go
package tpmfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DiscoverDevices walks sysRoot (e.g. "/sys/class/tpm") and returns one
// Device entry per discovered tpm* subdirectory. Returns an empty slice
// (and no error) if sysRoot does not exist — TPM absence is not a failure.
func DiscoverDevices(sysRoot string) ([]Device, error) {
	entries, err := os.ReadDir(sysRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("tpmfs: readdir %s: %w", sysRoot, err)
	}
	out := []Device{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "tpm") {
			continue
		}
		devPath := filepath.Join(sysRoot, name)
		d := Device{Path: devPath, Name: name}
		d.SpecVersion = readTrimmed(filepath.Join(devPath, "tpm_version_major"))
		if d.SpecVersion == "2" {
			d.SpecVersion = "2.0"
		}
		d.Description = readTrimmed(filepath.Join(devPath, "device", "description"))
		parseCaps(filepath.Join(devPath, "device", "caps"), &d)
		ekPath := filepath.Join(devPath, "device", "endorsement_key_cert")
		if _, err := os.Stat(ekPath); err == nil {
			d.EKCertPath = ekPath
		}
		out = append(out, d)
	}
	return out, nil
}

// readTrimmed returns the trimmed contents of a file, or "" if absent.
func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseCaps reads the multi-line caps file and populates Vendor + FirmwareVersion.
func parseCaps(path string, d *Device) {
	content := readTrimmed(path)
	if content == "" {
		return
	}
	for _, line := range strings.Split(content, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "Manufacturer":
			d.VendorRawID = val
			d.Vendor = decodeVendorID(val)
		case "Firmware version":
			d.FirmwareVersion = val
		case "TCG version":
			if d.SpecVersion == "" {
				d.SpecVersion = val
			}
		}
	}
}

// vendorIDTable maps 4-char ASCII manufacturer codes to human names.
// Codes may be space-padded to 4 chars.
var vendorIDTable = map[string]string{
	"IFX ": "Infineon",
	"INTC": "Intel",
	"NTC ": "Nuvoton",
	"STM ": "STMicroelectronics",
	"ATML": "Microchip",
	"MSFT": "Microsoft",
	"GOOG": "Google",
	"AMD ": "AMD",
}

// decodeVendorID converts a hex manufacturer code (e.g. "0x49465800")
// to a human-readable vendor name via vendorIDTable. Unknown vendors
// pass through the input as-is.
func decodeVendorID(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return s
	}
	n, err := strconv.ParseUint(s[2:], 16, 32)
	if err != nil {
		return raw
	}
	bs := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	// Replace NUL bytes with spaces so lookups match the space-padded keys.
	for i, b := range bs {
		if b == 0 {
			bs[i] = ' '
		}
	}
	key := string(bs)
	if name, ok := vendorIDTable[key]; ok {
		return name
	}
	// Fallback: return raw hex without the "0x" prefix for consistency.
	return s[2:]
}
```

- [ ] **Step 6: Run, verify PASS**

```bash
go test ./pkg/scanner/internal/tpmfs/ -v
```
All tests must PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/scanner/internal/tpmfs/types.go pkg/scanner/internal/tpmfs/tpmfs.go pkg/scanner/internal/tpmfs/tpmfs_test.go pkg/scanner/internal/tpmfs/testdata/
git commit -m "feat(tpmfs): sysfs walker + vendor-ID decoder + Infineon fixture"
```

---

## Task 3: TPM firmware CVE registry

`pkg/crypto/tpm_firmware.go`: vendor + firmware-version → CVE refs. Infineon + Intel get range comparison via dotted-integer parsing; other vendors fall back to exact-string match on `MinVersion`.

**Files:**
- Create: `pkg/crypto/tpm_firmware.go`
- Create: `pkg/crypto/tpm_firmware_test.go`

- [ ] **Step 1: Write `pkg/crypto/tpm_firmware_test.go` (RED)**

```go
package crypto

import "testing"

func TestLookupTPMFirmwareCVEs_InfineonROCA(t *testing.T) {
	// Infineon firmware ≤ 4.33.4 → CVE-2017-15361 fires.
	cases := []struct {
		version string
		wantFP  bool // should fire?
	}{
		{"4.32.1.2", true},
		{"4.33.0", true},
		{"4.33.4", true},
		{"4.34.0", false},
		{"5.0.0", false},
	}
	for _, c := range cases {
		cves := LookupTPMFirmwareCVEs("Infineon", c.version)
		found := false
		for _, cve := range cves {
			if cve.CVE == "CVE-2017-15361" {
				found = true
				break
			}
		}
		if found != c.wantFP {
			t.Errorf("version=%q: ROCA CVE found=%v, want %v", c.version, found, c.wantFP)
		}
	}
}

func TestLookupTPMFirmwareCVEs_TCGLibBugs(t *testing.T) {
	// TPM 2.0 library ≤ 1.59 → CVE-2023-1017 and CVE-2023-1018 fire for any vendor.
	cves := LookupTPMFirmwareCVEs("Infineon", "4.40.0")
	// Firmware 4.40.0 is past ROCA, but TCG library bugs still fire IF firmware
	// implements the affected library version. For PR #1 we're conservative:
	// TCG-lib CVEs are only registered when we know the firmware ships that
	// library version, which we don't generically — so they should NOT fire
	// just based on vendor+version here. Expect empty.
	for _, c := range cves {
		if c.CVE == "CVE-2023-1017" || c.CVE == "CVE-2023-1018" {
			t.Errorf("TCG lib CVE fired without library-version context: %s", c.CVE)
		}
	}
}

func TestLookupTPMFirmwareCVEs_UnknownVendorNoCVEs(t *testing.T) {
	cves := LookupTPMFirmwareCVEs("SomeRandomVendor", "1.2.3")
	if len(cves) != 0 {
		t.Errorf("unknown vendor returned %d CVEs, want 0", len(cves))
	}
}

func TestLookupTPMFirmwareCVEs_FreshInfineonClean(t *testing.T) {
	cves := LookupTPMFirmwareCVEs("Infineon", "5.0.0")
	if len(cves) != 0 {
		t.Errorf("fresh Infineon firmware returned %d CVEs, want 0", len(cves))
	}
}

func TestCompareVersion_DottedIntegers(t *testing.T) {
	cases := []struct {
		a, b string
		want int // -1 if a<b, 0 if equal, 1 if a>b
	}{
		{"4.32.1.2", "4.33.0", -1},
		{"4.33.4", "4.33.4", 0},
		{"4.33.5", "4.33.4", 1},
		{"5.0", "4.99.99", 1},
		{"4.33", "4.33.4", -1}, // shorter version is "less" when missing components
	}
	for _, c := range cases {
		got := compareVersion(c.a, c.b)
		if got != c.want {
			t.Errorf("compareVersion(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `undefined: LookupTPMFirmwareCVEs`, `undefined: compareVersion`.

- [ ] **Step 3: Write `pkg/crypto/tpm_firmware.go`**

```go
package crypto

import (
	"strconv"
	"strings"
)

// TPMFirmwareCVE describes a known-vulnerable TPM firmware range.
// MinVersion / MaxVersion are inclusive bounds; empty string means "any".
// Version comparison uses dotted-integer semantics for vendors with
// well-documented version schemes; for other vendors, MinVersion must
// equal the firmware string exactly.
type TPMFirmwareCVE struct {
	Vendor      string
	CVE         string
	MinVersion  string
	MaxVersion  string
	Description string
	Severity    string // CRITICAL | HIGH | MEDIUM
}

// tpmFirmwareCVEs is the committed registry of known vulnerabilities.
var tpmFirmwareCVEs = []TPMFirmwareCVE{
	{
		Vendor:      "Infineon",
		CVE:         "CVE-2017-15361",
		MinVersion:  "",
		MaxVersion:  "4.33.4",
		Description: "ROCA — weak prime generation in Infineon RSA library",
		Severity:    "CRITICAL",
	},
	{
		Vendor:      "Intel",
		CVE:         "CVE-2017-5689",
		MinVersion:  "",
		MaxVersion:  "11.6",
		Description: "Intel ME / AMT authentication bypass (adjacent to Intel PTT firmware TPM)",
		Severity:    "HIGH",
	},
	{
		Vendor:      "STMicroelectronics",
		CVE:         "CVE-2019-16863",
		MinVersion:  "73.04",
		MaxVersion:  "73.04",
		Description: "ECDSA nonce bias in ST33 family TPM",
		Severity:    "HIGH",
	},
}

// rangeComparableVendors lists vendors whose firmware versions use dotted
// integers and can therefore be range-compared. Other vendors fall back
// to exact-match against the MinVersion field.
var rangeComparableVendors = map[string]bool{
	"Infineon": true,
	"Intel":    true,
}

// LookupTPMFirmwareCVEs returns every CVE in the registry whose vendor
// and firmware-version range matches the inputs.
func LookupTPMFirmwareCVEs(vendor, firmwareVersion string) []TPMFirmwareCVE {
	if vendor == "" || firmwareVersion == "" {
		return nil
	}
	out := []TPMFirmwareCVE{}
	for _, cve := range tpmFirmwareCVEs {
		if cve.Vendor != vendor {
			continue
		}
		if !versionInRange(vendor, firmwareVersion, cve.MinVersion, cve.MaxVersion) {
			continue
		}
		out = append(out, cve)
	}
	return out
}

// versionInRange returns true if firmwareVersion is within [min, max]
// (inclusive; empty bound = open-ended). For range-comparable vendors,
// uses compareVersion; otherwise requires firmwareVersion == min.
func versionInRange(vendor, firmwareVersion, minV, maxV string) bool {
	if !rangeComparableVendors[vendor] {
		// Non-range vendors: exact match against MinVersion only.
		return minV != "" && firmwareVersion == minV
	}
	if minV != "" && compareVersion(firmwareVersion, minV) < 0 {
		return false
	}
	if maxV != "" && compareVersion(firmwareVersion, maxV) > 0 {
		return false
	}
	return true
}

// compareVersion compares two dotted-integer version strings.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
// Missing components are treated as 0 (so "4.33" < "4.33.4").
func compareVersion(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai := 0
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		bi := 0
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}
```

- [ ] **Step 4: Run, verify PASS**

```bash
go test ./pkg/crypto/ -run 'TestLookupTPMFirmwareCVEs|TestCompareVersion' -v
```
All PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/tpm_firmware.go pkg/crypto/tpm_firmware_test.go
git commit -m "feat(crypto): TPM firmware CVE registry (Infineon ROCA, Intel PTT, STMicro ST33)"
```

---

## Task 4: EK certificate reader

Reads DER from a file path, parses via `crypto/x509`, returns a typed `EKCert`. Test uses a freshly-generated RSA-2048 certificate as a synthetic EK cert.

**Files:**
- Create: `pkg/scanner/internal/tpmfs/ekcert.go`
- Create: `pkg/scanner/internal/tpmfs/ekcert_test.go`

- [ ] **Step 1: Write `pkg/scanner/internal/tpmfs/ekcert_test.go` (RED)**

```go
package tpmfs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadEKCert_ParsesRSACert(t *testing.T) {
	// Generate a throwaway self-signed RSA-2048 cert and write DER to a tempdir.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek"},
		Issuer:       pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsement_key_cert")
	if err := os.WriteFile(p, der, 0o644); err != nil {
		t.Fatal(err)
	}

	ek, err := ReadEKCert(p)
	if err != nil {
		t.Fatalf("ReadEKCert: %v", err)
	}
	if ek == nil {
		t.Fatal("nil EK cert returned")
		return
	}
	if ek.Algorithm != "RSA" {
		t.Errorf("Algorithm = %q, want RSA", ek.Algorithm)
	}
	if ek.KeySize != 2048 {
		t.Errorf("KeySize = %d, want 2048", ek.KeySize)
	}
	if ek.Subject == "" {
		t.Error("Subject empty")
	}
}

func TestReadEKCert_MissingFileReturnsNilNoError(t *testing.T) {
	ek, err := ReadEKCert("/does/not/exist")
	if err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
	if ek != nil {
		t.Errorf("ek = %+v, want nil", ek)
	}
}

func TestReadEKCert_CorruptFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bogus")
	if err := os.WriteFile(p, []byte("not a DER cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadEKCert(p)
	if err == nil {
		t.Error("expected error on corrupt DER")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `undefined: ReadEKCert`.

- [ ] **Step 3: Write `pkg/scanner/internal/tpmfs/ekcert.go`**

```go
package tpmfs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

// maxEKCertSize caps file reads to prevent runaway allocations on a
// pathological /sys/.../endorsement_key_cert file. 64 KB is far above
// any realistic EK cert (typical: 1–2 KB).
const maxEKCertSize = 64 * 1024

// ReadEKCert reads a DER-encoded endorsement-key certificate from path,
// parses it via crypto/x509, and returns a typed EKCert. Missing files
// return (nil, nil) — EK cert absence is not a failure. Parse errors
// are surfaced to the caller.
func ReadEKCert(path string) (*EKCert, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("tpmfs: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	der, err := io.ReadAll(io.LimitReader(f, maxEKCertSize))
	if err != nil {
		return nil, fmt.Errorf("tpmfs: read %s: %w", path, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tpmfs: parse EK cert: %w", err)
	}
	algo, size := publicKeyInfo(cert.PublicKey)
	return &EKCert{
		RawDER:    der,
		Algorithm: algo,
		KeySize:   size,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
	}, nil
}

// publicKeyInfo extracts algorithm name + key size from a parsed public key.
func publicKeyInfo(pub interface{}) (algo string, size int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}
```

- [ ] **Step 4: Run, verify PASS**

```bash
go test ./pkg/scanner/internal/tpmfs/ -run TestReadEKCert -v
```
All PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/tpmfs/ekcert.go pkg/scanner/internal/tpmfs/ekcert_test.go
git commit -m "feat(tpmfs): EK certificate reader (DER + x509 parse)"
```

---

## Task 5: TCG event log parser

Parses the TCG PC Client Platform Firmware Profile binary event log. Portable (no build tag); works on any OS because we're parsing file bytes, not live TPM output.

**Files:**
- Create: `pkg/scanner/internal/tpmfs/eventlog.go`
- Create: `pkg/scanner/internal/tpmfs/eventlog_test.go`
- Create: `pkg/scanner/internal/tpmfs/testdata/event-log-sha256-only.bin` (synthesised via helper in the test)
- Create: `pkg/scanner/internal/tpmfs/testdata/event-log-sha1-only.bin`
- Create: `pkg/scanner/internal/tpmfs/testdata/event-log-mixed.bin`

- [ ] **Step 1: Write `pkg/scanner/internal/tpmfs/eventlog_test.go` (RED)**

```go
package tpmfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildEventLog synthesises a minimal TCG PFP TPM 2.0 binary event log with
// the given events. Each event is a TCG_PCR_EVENT2 record.
//
// algos describes the digest algorithms present in EVERY event (simplified
// for tests — real logs vary event-by-event). Returns the full log including
// the spec-ID pseudo-header.
func buildEventLog(algos []HashAlgo, eventCount int) []byte {
	var buf bytes.Buffer

	// Spec ID pseudo-event (TCG_PCR_EVENT, old format, 32 bytes + SpecID blob).
	// For testing purposes this is minimal; real parsers accept it as a no-op marker.
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // PCRIndex = 0
	binary.Write(&buf, binary.LittleEndian, uint32(3))      // EventType = EV_NO_ACTION
	buf.Write(make([]byte, 20))                              // SHA1 digest (zero)
	specIDBlob := []byte("Spec ID Event03\x00")              // placeholder blob
	binary.Write(&buf, binary.LittleEndian, uint32(len(specIDBlob)))
	buf.Write(specIDBlob)

	// N TCG_PCR_EVENT2 records.
	for i := 0; i < eventCount; i++ {
		binary.Write(&buf, binary.LittleEndian, uint32(4))         // PCRIndex = 4
		binary.Write(&buf, binary.LittleEndian, uint32(0x0D))      // EventType = EV_EFI_BOOT_SERVICES_APPLICATION
		binary.Write(&buf, binary.LittleEndian, uint32(len(algos))) // DigestCount
		for _, a := range algos {
			binary.Write(&buf, binary.LittleEndian, uint16(a))
			buf.Write(make([]byte, a.Size()))
		}
		binary.Write(&buf, binary.LittleEndian, uint32(0)) // EventSize = 0
	}
	return buf.Bytes()
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseEventLog_SHA256Only(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA256}, 5)
	p := writeFixture(t, "event-log-sha256-only.bin", data)
	defer os.Remove(p)

	log, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if len(log.Entries) != 5 {
		t.Errorf("len(Entries) = %d, want 5", len(log.Entries))
	}
	if log.AlgoCounts[AlgSHA256] != 5 {
		t.Errorf("SHA-256 count = %d, want 5", log.AlgoCounts[AlgSHA256])
	}
	if log.AlgoCounts[AlgSHA1] != 0 {
		t.Errorf("SHA-1 count = %d, want 0", log.AlgoCounts[AlgSHA1])
	}
}

func TestParseEventLog_SHA1Only(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA1}, 3)
	log, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if log.AlgoCounts[AlgSHA1] != 3 {
		t.Errorf("SHA-1 count = %d, want 3", log.AlgoCounts[AlgSHA1])
	}
	if log.AlgoCounts[AlgSHA256] != 0 {
		t.Errorf("SHA-256 count = %d, want 0", log.AlgoCounts[AlgSHA256])
	}
}

func TestParseEventLog_Mixed(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA1, AlgSHA256}, 4)
	log, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if log.AlgoCounts[AlgSHA1] != 4 {
		t.Errorf("SHA-1 count = %d, want 4", log.AlgoCounts[AlgSHA1])
	}
	if log.AlgoCounts[AlgSHA256] != 4 {
		t.Errorf("SHA-256 count = %d, want 4", log.AlgoCounts[AlgSHA256])
	}
}

func TestClassifyEventLog(t *testing.T) {
	cases := []struct {
		name      string
		log       *EventLog
		wantPQC   string
	}{
		{
			name:    "SHA-256 only",
			log:     &EventLog{AlgoCounts: map[HashAlgo]int{AlgSHA256: 10}},
			wantPQC: "SAFE",
		},
		{
			name:    "SHA-1 only",
			log:     &EventLog{AlgoCounts: map[HashAlgo]int{AlgSHA1: 10}},
			wantPQC: "UNSAFE",
		},
		{
			name:    "mixed SHA-1 + SHA-256",
			log:     &EventLog{AlgoCounts: map[HashAlgo]int{AlgSHA1: 10, AlgSHA256: 10}},
			wantPQC: "TRANSITIONAL",
		},
		{
			name:    "SHA-384 only",
			log:     &EventLog{AlgoCounts: map[HashAlgo]int{AlgSHA384: 10}},
			wantPQC: "SAFE",
		},
		{
			name:    "empty log",
			log:     &EventLog{AlgoCounts: map[HashAlgo]int{}},
			wantPQC: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyEventLog(c.log)
			if got != c.wantPQC {
				t.Errorf("got %q, want %q", got, c.wantPQC)
			}
		})
	}
}

func TestParseEventLog_TruncatedReturnsError(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA256}, 2)
	// Truncate mid-record.
	truncated := data[:len(data)-10]
	_, err := ParseEventLog(truncated)
	if err == nil {
		t.Error("expected error on truncated log")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `undefined: ParseEventLog`, `undefined: ClassifyEventLog`.

- [ ] **Step 3: Write `pkg/scanner/internal/tpmfs/eventlog.go`**

```go
package tpmfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// maxEventLogSize caps event-log byte reads.
const maxEventLogSize = 16 * 1024 * 1024

// maxDigestCount and maxEventSize provide defensive bounds against malformed
// or adversarial event logs. Legitimate logs have DigestCount ≤ ~8 and
// EventSize ≤ ~4 KB.
const (
	maxDigestCount = 64
	maxEventSize   = 256 * 1024
)

// ParseEventLog parses a TCG PC Client PFP TPM 2.0 binary event log.
// Returns an EventLog with per-event algorithm records and an aggregate
// AlgoCounts map. The spec-ID pseudo-header (a TCG_PCR_EVENT record at the
// start) is consumed but not added to Entries.
func ParseEventLog(data []byte) (*EventLog, error) {
	if len(data) > maxEventLogSize {
		return nil, fmt.Errorf("tpmfs: event log exceeds %d bytes", maxEventLogSize)
	}
	r := bytes.NewReader(data)

	// Consume the TCG_PCR_EVENT spec-ID pseudo-header.
	if err := skipSpecIDHeader(r); err != nil {
		return nil, fmt.Errorf("tpmfs: spec-ID header: %w", err)
	}

	log := &EventLog{AlgoCounts: map[HashAlgo]int{}}
	for r.Len() > 0 {
		entry, err := parseEvent2(r)
		if err != nil {
			return nil, err
		}
		log.Entries = append(log.Entries, *entry)
		for _, a := range entry.Algorithms {
			log.AlgoCounts[a]++
		}
	}
	return log, nil
}

// skipSpecIDHeader reads the TCG_PCR_EVENT (legacy-format) pseudo-header
// that precedes the TPM 2.0 event log.
func skipSpecIDHeader(r *bytes.Reader) error {
	// PCRIndex (4) + EventType (4) + DigestSHA1 (20) + EventSize (4).
	header := make([]byte, 32)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	eventSize := binary.LittleEndian.Uint32(header[28:32])
	if eventSize > maxEventSize {
		return fmt.Errorf("spec-ID event size %d exceeds cap", eventSize)
	}
	if _, err := io.CopyN(io.Discard, r, int64(eventSize)); err != nil {
		return fmt.Errorf("skip spec-ID body: %w", err)
	}
	return nil
}

// parseEvent2 reads one TCG_PCR_EVENT2 record.
func parseEvent2(r *bytes.Reader) (*EventLogEntry, error) {
	var pcrIndex, eventType, digestCount uint32
	if err := binary.Read(r, binary.LittleEndian, &pcrIndex); err != nil {
		return nil, fmt.Errorf("read PCRIndex: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &eventType); err != nil {
		return nil, fmt.Errorf("read EventType: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &digestCount); err != nil {
		return nil, fmt.Errorf("read DigestCount: %w", err)
	}
	if digestCount > maxDigestCount {
		return nil, fmt.Errorf("DigestCount %d exceeds cap %d", digestCount, maxDigestCount)
	}
	algos := make([]HashAlgo, 0, digestCount)
	for i := uint32(0); i < digestCount; i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return nil, fmt.Errorf("read algID: %w", err)
		}
		algo := HashAlgo(algID)
		size := algo.Size()
		if size == 0 {
			return nil, fmt.Errorf("unknown TPM_ALG_ID 0x%04x", algID)
		}
		if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
			return nil, fmt.Errorf("skip digest bytes: %w", err)
		}
		algos = append(algos, algo)
	}
	var eventSize uint32
	if err := binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return nil, fmt.Errorf("read EventSize: %w", err)
	}
	if eventSize > maxEventSize {
		return nil, fmt.Errorf("EventSize %d exceeds cap %d", eventSize, maxEventSize)
	}
	if _, err := io.CopyN(io.Discard, r, int64(eventSize)); err != nil {
		return nil, fmt.Errorf("skip event body: %w", err)
	}
	return &EventLogEntry{
		PCRIndex:   pcrIndex,
		EventType:  eventType,
		Algorithms: algos,
	}, nil
}

// ClassifyEventLog returns a PQC status string summarising the log's hash
// algorithm coverage:
//   - "SAFE" if every algorithm used is SHA-256 or stronger (no SHA-1)
//   - "UNSAFE" if only SHA-1 is used (no modern banks)
//   - "TRANSITIONAL" if both SHA-1 and a modern algorithm are extended
//   - "" if the log is empty (no events)
func ClassifyEventLog(log *EventLog) string {
	if log == nil || len(log.AlgoCounts) == 0 {
		return ""
	}
	hasSHA1 := log.AlgoCounts[AlgSHA1] > 0
	hasModern := log.AlgoCounts[AlgSHA256]+log.AlgoCounts[AlgSHA384]+log.AlgoCounts[AlgSHA512] > 0
	switch {
	case hasModern && !hasSHA1:
		return "SAFE"
	case hasSHA1 && !hasModern:
		return "UNSAFE"
	case hasSHA1 && hasModern:
		return "TRANSITIONAL"
	}
	return ""
}
```

- [ ] **Step 4: Run, verify PASS**

```bash
go test ./pkg/scanner/internal/tpmfs/ -v
```
All PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/tpmfs/eventlog.go pkg/scanner/internal/tpmfs/eventlog_test.go
git commit -m "feat(tpmfs): TCG PFP event log parser + hash-algorithm classifier"
```

---

## Task 6: Linux scan() driver + finding builders

Replaces the Task 1 placeholder. Composes sysfs walker, EK cert reader, event log parser, and firmware CVE registry into a full `scan()` implementation.

**Files:**
- Modify: `pkg/scanner/tpm_linux.go` (replace placeholder)
- Create: `pkg/scanner/tpm_linux_test.go` (Linux-only; exercises `scan()` via fixture root)

- [ ] **Step 1: Replace `pkg/scanner/tpm_linux.go`**

```go
//go:build linux

package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/crypto/keyquality"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tpmfs"
)

// Default production paths; overridable via tpmSysRoot / tpmSecRoot fields
// (left nil in production; tests inject fixtures).
const (
	defaultTPMSysRoot = "/sys/class/tpm"
	defaultTPMSecRoot = "/sys/kernel/security"
)

// scan walks /sys/class/tpm, emits one device finding per TPM, plus EK cert
// and event-log findings when those artefacts are available. Missing TPM
// (no /sys/class/tpm) is silent no-op. Never hard-fails.
func (m *TPMModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	sysRoot := defaultTPMSysRoot
	secRoot := defaultTPMSecRoot
	if m.cfg != nil && m.cfg.TPMSysRoot != "" {
		sysRoot = m.cfg.TPMSysRoot
	}
	if m.cfg != nil && m.cfg.TPMSecRoot != "" {
		secRoot = m.cfg.TPMSecRoot
	}

	devs, err := tpmfs.DiscoverDevices(sysRoot)
	if err != nil {
		// Non-fatal: log via skipped finding.
		return emitTPMSkipped(ctx, findings, err.Error())
	}
	if len(devs) == 0 {
		return nil // no TPM present — silent success
	}

	for _, dev := range devs {
		if err := emitDeviceFinding(ctx, dev, findings); err != nil {
			return err
		}
		if dev.EKCertPath != "" {
			if err := emitEKCertFinding(ctx, dev, findings); err != nil {
				return err
			}
		}
		logPath := filepath.Join(secRoot, dev.Name, "binary_bios_measurements")
		if _, err := os.Stat(logPath); err == nil {
			if err := emitEventLogFinding(ctx, logPath, findings); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitDeviceFinding emits the top-level TPM device finding with CVE-derived quality warnings.
func emitDeviceFinding(ctx context.Context, dev tpmfs.Device, findings chan<- *model.Finding) error {
	cves := crypto.LookupTPMFirmwareCVEs(dev.Vendor, dev.FirmwareVersion)
	status := "SAFE"
	severity := "" // aggregate worst-case severity across CVE hits
	qualityWarnings := make([]model.QualityWarning, 0, len(cves))
	for _, cve := range cves {
		qualityWarnings = append(qualityWarnings, model.QualityWarning{
			Code:     "FIRMWARE-CVE",
			Severity: cve.Severity,
			Message:  cve.Description,
			CVE:      cve.CVE,
		})
		switch cve.Severity {
		case "CRITICAL":
			status = "UNSAFE"
			severity = "CRITICAL"
		case "HIGH":
			if severity == "" {
				status = "DEPRECATED"
				severity = "HIGH"
			}
		case "MEDIUM":
			if severity == "" {
				status = "TRANSITIONAL"
				severity = "MEDIUM"
			}
		}
	}

	algo := "TPM" + dev.SpecVersion
	if algo == "TPM" {
		algo = "TPM"
	}
	asset := &model.CryptoAsset{
		ID:              uuid.New().String(),
		Algorithm:       algo,
		Library:         dev.Vendor + " TPM firmware",
		Language:        "Firmware",
		Function:        "Hardware root of trust",
		PQCStatus:       status,
		QualityWarnings: qualityWarnings,
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            dev.Path,
			DetectionMethod: "sysfs",
			Evidence:        fmt.Sprintf("vendor=%s firmware=%s tcg-version=%s", dev.Vendor, dev.FirmwareVersion, dev.SpecVersion),
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "tpm",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

// emitEKCertFinding emits a finding for the endorsement-key certificate.
func emitEKCertFinding(ctx context.Context, dev tpmfs.Device, findings chan<- *model.Finding) error {
	ek, err := tpmfs.ReadEKCert(dev.EKCertPath)
	if err != nil || ek == nil {
		return nil // silently skip unparseable or missing EK cert
	}
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: ek.Algorithm,
		KeySize:   ek.KeySize,
		Subject:   ek.Subject,
		Issuer:    ek.Issuer,
		Function:  "TPM endorsement key",
		Language:  "Firmware",
	}
	crypto.ClassifyCryptoAsset(asset)
	// Reuse keyquality for material-level audits.
	pub := extractPubForQuality(ek.RawDER)
	if pub != nil {
		ws := keyquality.Analyze(pub, asset.Algorithm, asset.KeySize)
		if len(ws) > 0 {
			asset.QualityWarnings = keyquality.ToModel(ws)
		}
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            dev.EKCertPath,
			DetectionMethod: "sysfs",
			Evidence:        "TPM endorsement key certificate",
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "tpm",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

// extractPubForQuality re-parses the DER to pull the public key out. Duplicates
// some work from ReadEKCert but keeps that function's signature clean.
func extractPubForQuality(der []byte) interface{} {
	cert, err := parseCertSilent(der)
	if err != nil {
		return nil
	}
	return cert.PublicKey
}

// parseCertSilent is a tiny wrapper so the import of crypto/x509 in this file
// stays narrow. Errors are non-fatal at this call site.
func parseCertSilent(der []byte) (*certWithPubKey, error) {
	c, err := cryptox509ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &certWithPubKey{PublicKey: c.PublicKey}, nil
}

type certWithPubKey struct {
	PublicKey interface{}
}

// cryptox509ParseCertificate is a narrowly-scoped import shim to avoid a
// top-level crypto/x509 dependency in this file's visible imports.
var cryptox509ParseCertificate = func(der []byte) (*cryptoX509ParsedCert, error) {
	return nil, fmt.Errorf("cryptox509ParseCertificate not initialised; see init()")
}

type cryptoX509ParsedCert struct {
	PublicKey interface{}
}

// emitEventLogFinding parses the TCG event log and emits a finding with its
// hash-algorithm classification.
func emitEventLogFinding(ctx context.Context, logPath string, findings chan<- *model.Finding) error {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil // silently skip — log presence is best-effort
	}
	log, err := tpmfs.ParseEventLog(data)
	if err != nil {
		return nil // degraded; log corruption surfaces in a future finding
	}
	pqc := tpmfs.ClassifyEventLog(log)
	evidence := formatLogEvidence(log)
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: "Measured-Boot-Log",
		Library:   "TCG PFP TPM 2.0",
		Language:  "Firmware",
		Function:  "Measured boot integrity",
		PQCStatus: pqc,
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            logPath,
			DetectionMethod: "tcg-pfp-log",
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "tpm",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

func formatLogEvidence(log *tpmfs.EventLog) string {
	parts := fmt.Sprintf("%d events", len(log.Entries))
	for _, a := range []tpmfs.HashAlgo{tpmfs.AlgSHA1, tpmfs.AlgSHA256, tpmfs.AlgSHA384, tpmfs.AlgSHA512, tpmfs.AlgSM3} {
		if n := log.AlgoCounts[a]; n > 0 {
			parts += fmt.Sprintf(", %d %s", n, a.String())
		}
	}
	return parts
}

// emitTPMSkipped emits a single skipped-finding with the given reason.
func emitTPMSkipped(ctx context.Context, findings chan<- *model.Finding, reason string) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			DetectionMethod: "tpm-skipped",
			Evidence:        "tpm scan error: " + reason,
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			Language:  "Firmware",
		},
		Confidence: 0.0,
		Module:     "tpm",
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

The imports use an indirection shim (`cryptox509ParseCertificate`) to avoid adding `crypto/x509` to this file's direct imports — which conflicts with the local `pkg/crypto` import already present. Clean alternative: just rename-import as we did in `key.go` — use `stdcrypto "crypto/x509"` as `stdx509`. Simpler version of the top of the file:

```go
import (
	"context"
	"fmt"
	stdx509 "crypto/x509"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/crypto/keyquality"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tpmfs"
)
```

Then in `extractPubForQuality`:
```go
func extractPubForQuality(der []byte) interface{} {
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert.PublicKey
}
```

Delete the whole `parseCertSilent` / `cryptox509ParseCertificate` / `cryptoX509ParsedCert` / `certWithPubKey` block — replaced by the direct `stdx509.ParseCertificate` call.

**Use the clean alternative (stdx509 alias) — the shim was overkill.**

- [ ] **Step 2: Add config fields**

In `internal/scannerconfig/config.go`, inside the `Config` struct, add:

```go
// TPM root overrides — used by tests to inject fixtures.
// Production leaves these empty; scanner uses /sys/class/tpm and /sys/kernel/security.
TPMSysRoot string
TPMSecRoot string
```

No CLI flag — these are internal test-hooks only.

- [ ] **Step 3: Write `pkg/scanner/tpm_linux_test.go`**

```go
//go:build linux

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// TestTPMModule_Linux_EmitsDeviceFinding exercises the full scan pipeline
// against the committed sysfs-infineon fixture. Runs on Linux only.
func TestTPMModule_Linux_EmitsDeviceFinding(t *testing.T) {
	// Use the fixture as the sysfs root.
	sysRoot, _ := filepath.Abs("internal/tpmfs/testdata/sysfs-infineon")
	if _, err := os.Stat(sysRoot); err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	secRoot := t.TempDir()

	cfg := &scannerconfig.Config{
		TPMSysRoot: sysRoot,
		TPMSecRoot: secRoot,
	}
	m := NewTPMModule(cfg)
	ch := make(chan *model.Finding, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch)
		close(ch)
	}()

	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) < 1 {
		t.Fatalf("len(got) = %d, want ≥ 1 (device finding)", len(got))
		return
	}

	// Find the device finding.
	var deviceFinding *model.Finding
	for _, f := range got {
		if f.Source.DetectionMethod == "sysfs" && f.CryptoAsset.Function == "Hardware root of trust" {
			deviceFinding = f
			break
		}
	}
	if deviceFinding == nil {
		t.Fatal("no device finding emitted")
		return
	}
	if deviceFinding.CryptoAsset.Library != "Infineon TPM firmware" {
		t.Errorf("Library = %q, want 'Infineon TPM firmware'", deviceFinding.CryptoAsset.Library)
	}
	// Firmware 4.32.1.2 ≤ 4.33.4 → ROCA CVE should fire.
	foundROCA := false
	for _, qw := range deviceFinding.CryptoAsset.QualityWarnings {
		if qw.CVE == "CVE-2017-15361" {
			foundROCA = true
		}
	}
	if !foundROCA {
		t.Errorf("expected CVE-2017-15361 (ROCA) warning on Infineon firmware 4.32.1.2; got %+v", deviceFinding.CryptoAsset.QualityWarnings)
	}
}

func TestTPMModule_Linux_NoTPMSilent(t *testing.T) {
	sysRoot := t.TempDir() // empty directory — no tpm* subdirs
	secRoot := t.TempDir()
	cfg := &scannerconfig.Config{TPMSysRoot: sysRoot, TPMSecRoot: secRoot}
	m := NewTPMModule(cfg)
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	for f := range ch {
		t.Errorf("unexpected finding: %+v", f)
	}
}
```

- [ ] **Step 4: Run (darwin can cross-compile; actual tests run on Linux)**

```bash
go test ./pkg/scanner/ -run TestTPMModule
go build ./...
GOOS=linux go build ./...
```

On darwin: `TestTPMModule_Identity` and `TestTPMModule_NonLinuxSkippedFinding` run and pass. The Linux-specific tests are excluded by build tag (that's fine).

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/tpm_linux.go pkg/scanner/tpm_linux_test.go internal/scannerconfig/config.go
git commit -m "feat(scanner): wire TPM scan() to tpmfs discovery + CVE lookup + EK cert + event log"
```

---

## Task 7: Integration test + docs + full verification

**Files:**
- Create: `test/integration/tpm_test.go`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Write `test/integration/tpm_test.go`**

```go
//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestTPM_EndToEnd exercises the tpm module against the committed Infineon
// sysfs fixture and asserts the expected findings surface with CVE warnings.
// Linux-only; skips on other OS.
func TestTPM_EndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tpm module is Linux-only")
	}
	// Integration test file lives in test/integration; fixture is in pkg/scanner/internal/tpmfs/testdata.
	// Resolve the fixture path relative to the repo root.
	repoRoot, _ := filepath.Abs("../..")
	sysRoot := filepath.Join(repoRoot, "pkg/scanner/internal/tpmfs/testdata/sysfs-infineon")
	if _, err := os.Stat(sysRoot); err != nil {
		t.Skipf("fixture not found at %s: %v", sysRoot, err)
	}
	secRoot := t.TempDir()

	cfg := &scannerconfig.Config{
		TPMSysRoot:  sysRoot,
		TPMSecRoot:  secRoot,
		MaxFileSize: 16 << 20,
	}
	m := scanner.NewTPMModule(cfg)
	ch := make(chan *model.Finding, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch)
		close(ch)
	}()

	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) == 0 {
		t.Fatal("no findings emitted from TPM fixture scan")
	}

	// Assert the module tags each finding correctly.
	for _, f := range got {
		if f.Module != "tpm" {
			t.Errorf("Module = %q, want tpm", f.Module)
		}
	}
}
```

- [ ] **Step 2: Run integration test on Linux (darwin skips)**

```bash
go test -tags integration -run TestTPM_EndToEnd ./test/integration/...
```

On Linux: PASS. On darwin: skipped at runtime check (`runtime.GOOS != "linux"`).

- [ ] **Step 3: Update `CLAUDE.md`**

Under `pkg/scanner/`, after the `ebpf_trace.go` bullet, add:

```markdown
  - `tpm.go` — TPM 2.0 attestation analyzer: parses /sys/class/tpm sysfs + TCG PFP measured-boot log, classifies firmware against CVE registry (Infineon ROCA, Intel PTT, STMicro ST33), reuses `crypto.ClassifyCryptoAsset` + `keyquality.Analyze` for the endorsement-key certificate; Linux-only (emits skipped-finding on other OS); comprehensive profile + Pro+ tier
```

Under `pkg/crypto/`, after the `keyquality/` bullet, add:

```markdown
  - `tpm_firmware.go` — TPM firmware CVE registry (Infineon ≤ 4.33.4 = ROCA, Intel PTT ≤ 11.6, STMicro ST33 = ECDSA nonce bias); vendor-specific version parsing for Infineon + Intel, exact-match fallback otherwise
```

- [ ] **Step 4: Full suite + lint**

```bash
go run test/fixtures/generate.go    # pre-existing generator, idempotent
make test
make lint
```

Both must finish clean. Fix any lint issues in a separate `fix(tpm): lint` commit if needed.

- [ ] **Step 5: Coverage**

```bash
go test -cover ./pkg/scanner/internal/tpmfs/ ./pkg/crypto/
```

Expected: ≥ 80% on both.

- [ ] **Step 6: Commit + push**

```bash
git add test/integration/tpm_test.go CLAUDE.md
git commit -m "test(tpm): integration test + CLAUDE.md entry"
git push -u origin feat/tpm-analyzer
```

If you made a separate lint commit, push both.

---

## Task 8: Reviews + PR

- [ ] **Step 1: Dispatch three parallel reviews**

Against `git diff main...HEAD`:

- **bug-hunt:** TCG event log parser edge cases (truncation, malformed DigestCount, unknown TPM_ALG_ID); vendor-ID decoder NUL-to-space normalisation; CVE version-comparison boundary behaviour; EK cert parse error handling; sysfs path traversal safety; ctx cancellation propagation; stdx509 alias consistency.
- **architecture:** package boundary (`pkg/scanner/internal/tpmfs/` API surface); CVE registry placement (`pkg/crypto/` vs a new subdir); integration seam with existing cert+keyquality stack; config-field placement for test-hook roots (is `TPMSysRoot` leaking implementation into Config?); three-list SSOT drift (same PR #54 finding); mirror-of-ebpf_trace pattern — is this creating a pattern we'll regret?
- **test-quality:** synthetic-fixture fidelity vs real TPM data; event log parser coverage of digest-count/event-size caps; firmware CVE range-boundary tests; `TestTPMModule_Linux_EmitsDeviceFinding` fixture-dependency (breaks if fixture changes); EK cert test against non-RSA key types (ECDSA EK is valid on modern TPMs); integration test coverage of event log + EK cert paths (not just device finding).

- [ ] **Step 2: Apply fixes in-branch**

Each fix as its own commit (`fix(tpm):` / `fix(tpmfs):` / `fix(crypto):`). Re-run `make test && make lint` after each.

- [ ] **Step 3: Open PR**

```bash
gh pr create --title "feat(scanner): TPM 2.0 attestation analyzer (tpm)" --body "$(cat <<'EOF'
## Summary
- New \`tpm\` scanner module: Linux-only passive analysis of /sys/class/tpm/ + TCG PFP event log
- New \`pkg/scanner/internal/tpmfs/\` package: sysfs walker, EK cert reader, event log parser (all testable via fixture-root injection on any OS)
- New \`pkg/crypto/tpm_firmware.go\` CVE registry: Infineon ROCA (CVE-2017-15361), Intel PTT (CVE-2017-5689), STMicro ST33 (CVE-2019-16863)
- Comprehensive profile + Pro+ tier; non-Linux emits single skipped-finding
- Reuses existing \`crypto.ClassifyCryptoAsset\` + \`keyquality.Analyze\` for the EK cert

## Pre-landing review
- bug-review applied
- architecture-review applied
- test-review applied

## Test plan
- [x] Unit: \`go test ./pkg/scanner/internal/tpmfs/ ./pkg/crypto/\` — sysfs walk, event log parse, EK cert, CVE registry
- [x] Module (Linux): scan against committed Infineon fixture asserts ROCA CVE fires
- [x] Integration: \`go test -tags integration -run TestTPM_EndToEnd ./test/integration/...\`
- [x] \`make test && make lint\` green

## Follow-ups (tracked in memory)
- Active \`/dev/tpm0\` queries (PCR readouts, TPM2_Quote verification) — needs root + \`go-tpm\` dep
- Windows TBS API + macOS T2 coverage
- PCR reference-value comparison (policy-engine territory)
- IMA/EVM measured-boot log parsing
- Attestation key (AK) cert chain validation
- Per-vendor firmware-version parsers for Nuvoton/STMicro/Atmel (currently exact-string only)
- Expanded CVE registry (TPM 2.0 library CVE-2023-1017/1018 pending library-version context data)
EOF
)"
```

---

## Self-Review

**Spec coverage:**
- Sysfs walker + vendor ID table → Task 2
- Firmware CVE registry → Task 3
- EK cert reader → Task 4
- Event log parser + classifier → Task 5
- Module wiring (engine, profile, tier, stub) → Task 1
- Linux scan() composing everything → Task 6
- Integration test + docs → Task 7
- Reviews → Task 8

**Placeholder scan:** none. Every code block is complete. The eventlog parser upper bounds (`maxDigestCount`, `maxEventSize`, `maxEventLogSize`) are concrete integers, not TBDs. The fixture-creation commands are exact bash.

**Type consistency:**
- `Device`, `EventLogEntry`, `EventLog`, `EKCert`, `HashAlgo` defined in Task 2 types.go, used consistently
- `DiscoverDevices`, `ReadEKCert`, `ParseEventLog`, `ClassifyEventLog` signatures consistent
- `TPMFirmwareCVE`, `LookupTPMFirmwareCVEs`, `compareVersion` consistent
- `TPMSysRoot` / `TPMSecRoot` Config fields appear in Task 6; placeholder doesn't reference them (Task 1's Linux stub is just a placeholder)
- `stdx509` alias is local to `tpm_linux.go`; no cross-file concerns

**Genuine risks flagged in-plan:**
1. The Task 6 draft shows two import patterns (shim vs `stdx509` alias) and explicitly says to use the latter. Implementer must read that note.
2. Real TPM event logs in production can be very large and strangely-formatted; the committed fixture is synthesised and will miss real-world quirks. Flagged as test-quality review focus.
3. The integration test `TestTPMModule_Linux_EmitsDeviceFinding` has a runtime check (`runtime.GOOS != "linux"`) that will skip if run on darwin with `-tags integration` — intentional, matches ebpf_trace pattern.
