# Agentless Unix Scan Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `SshReader` through the scanner `Engine` so `Orchestrator.scanUnix()` produces real findings from remote targets, matching local-scan output for the same paths.

**Architecture:** Add optional `FileReaderAware` / `CommandRunnerAware` interfaces on the `Engine` that mirror the existing `StoreAware` injection pattern. Update 17 file-based Tier 1 modules to implement `FileReaderAware` and pass the reader into `walkTarget`. Replace `scanUnix()` to construct an `SshReader`, register default modules, inject the reader, and run the standard scan pipeline.

**Tech Stack:** Go 1.25, existing `pkg/scanner/fsadapter` (FileReader/LocalReader/SshReader), `pkg/scanner` Engine, `pkg/scanner/netscan/orchestrator.go`, `pkg/scanner/netadapter/transport.SSHClient`.

**Spec:** `docs/plans/2026-04-14-agentless-unix-wiring-design.md`

---

## File Map

**Create:**
- `pkg/scanner/engine_inject_test.go` — unit tests for FileReader injection + hostname override

**Modify:**
- `pkg/scanner/engine.go` — add interfaces, fields, setters, injection loop, hostname override
- 17 module files (add `reader` field + `SetFileReader` + wire into `walkerConfig`):
  - `pkg/scanner/certificate.go`
  - `pkg/scanner/key.go`
  - `pkg/scanner/library.go`
  - `pkg/scanner/binary.go`
  - `pkg/scanner/kernel.go`
  - `pkg/scanner/config.go`
  - `pkg/scanner/script.go`
  - `pkg/scanner/webapp.go`
  - `pkg/scanner/web_server.go`
  - `pkg/scanner/vpn_config.go`
  - `pkg/scanner/container_signatures.go`
  - `pkg/scanner/password_hash.go`
  - `pkg/scanner/auth_material.go`
  - `pkg/scanner/deps_ecosystems.go`
  - `pkg/scanner/service_mesh.go`
  - `pkg/scanner/xml_dsig.go`
  - `pkg/scanner/mail_server.go`
- `pkg/scanner/netscan/orchestrator.go` — replace `scanUnix()`

---

### Task 1: Engine API — add FileReaderAware/CommandRunnerAware, fields, setters

**Files:**
- Modify: `pkg/scanner/engine.go`

- [ ] **Step 1: Add the two interfaces below `StoreAware` (around line 35)**

```go
// FileReaderAware is implemented by modules that can scan over an
// abstract filesystem (local or remote via SSH).
type FileReaderAware interface {
    SetFileReader(r fsadapter.FileReader)
}

// CommandRunnerAware is implemented by modules that need to execute
// commands on the target (local exec or remote via SSH). Reserved
// for future agentless Tier 2 work; no module implements this in v1.
type CommandRunnerAware interface {
    SetCommandRunner(r netadapter.CommandRunner)
}
```

Add imports:
```go
"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
"github.com/amiryahaya/triton/pkg/scanner/netadapter"
```

- [ ] **Step 2: Extend the `Engine` struct (lines 37-42)**

```go
type Engine struct {
    config           *scannerconfig.Config
    modules          []Module
    store            store.Store
    reader           fsadapter.FileReader
    commandRunner    netadapter.CommandRunner
    hostnameOverride string
}
```

- [ ] **Step 3: Add three setters below `SetStore`**

```go
func (e *Engine) SetFileReader(r fsadapter.FileReader)        { e.reader = r }
func (e *Engine) SetCommandRunner(r netadapter.CommandRunner) { e.commandRunner = r }
func (e *Engine) SetHostnameOverride(h string)                { e.hostnameOverride = h }
```

- [ ] **Step 4: Use hostname override inside `Scan()` — replace line 220**

```go
hostname := e.hostnameOverride
if hostname == "" {
    hostname, _ = os.Hostname()
}
```

- [ ] **Step 5: Add FileReader/CommandRunner injection after StoreAware block (after line 252)**

```go
if e.reader != nil {
    for _, m := range e.modules {
        if fa, ok := m.(FileReaderAware); ok {
            fa.SetFileReader(e.reader)
        }
    }
}
if e.commandRunner != nil {
    for _, m := range e.modules {
        if ca, ok := m.(CommandRunnerAware); ok {
            ca.SetCommandRunner(e.commandRunner)
        }
    }
}
```

- [ ] **Step 6: Verify build**

Run: `go build ./...`
Expected: success (no modules implement FileReaderAware yet; additions compile)

- [ ] **Step 7: Commit**

```bash
git add pkg/scanner/engine.go
git commit -m "feat(scanner): add FileReaderAware/CommandRunnerAware injection on Engine"
```

---

### Task 2: Write engine injection tests (TDD — red)

**Files:**
- Create: `pkg/scanner/engine_inject_test.go`

- [ ] **Step 1: Write failing tests**

```go
package scanner

import (
    "context"
    "io/fs"
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

type stubReader struct{}

func (stubReader) ReadFile(ctx context.Context, p string) ([]byte, error)         { return nil, nil }
func (stubReader) Stat(ctx context.Context, p string) (fs.FileInfo, error)        { return nil, nil }
func (stubReader) ReadDir(ctx context.Context, p string) ([]fs.DirEntry, error)   { return nil, nil }
func (stubReader) Walk(ctx context.Context, r string, fn fsadapter.WalkFunc) error { return nil }

type stubFRAware struct {
    name   string
    reader fsadapter.FileReader
}

func (s *stubFRAware) Name() string                              { return s.name }
func (s *stubFRAware) Category() model.ModuleCategory             { return model.CategoryPassiveFile }
func (s *stubFRAware) ScanTargetType() model.ScanTargetType       { return model.TargetFilesystem }
func (s *stubFRAware) Scan(ctx context.Context, t model.ScanTarget, f chan<- *model.Finding) error {
    return nil
}
func (s *stubFRAware) SetFileReader(r fsadapter.FileReader) { s.reader = r }

func TestEngineInjectsFileReader(t *testing.T) {
    cfg := &scannerconfig.Config{Workers: 1}
    eng := New(cfg)
    m := &stubFRAware{name: "stub"}
    eng.RegisterModule(m)
    r := stubReader{}
    eng.SetFileReader(r)

    progressCh := make(chan Progress, 4)
    eng.Scan(context.Background(), progressCh)

    if m.reader == nil {
        t.Fatal("expected FileReader to be injected into module")
    }
}

func TestEngineHostnameOverride(t *testing.T) {
    cfg := &scannerconfig.Config{Workers: 1}
    eng := New(cfg)
    eng.SetHostnameOverride("remote-host.example")

    progressCh := make(chan Progress, 4)
    result := eng.Scan(context.Background(), progressCh)

    if result.Metadata.Hostname != "remote-host.example" {
        t.Fatalf("expected hostname override, got %q", result.Metadata.Hostname)
    }
}
```

- [ ] **Step 2: Run tests, verify they pass (Engine work from Task 1 already makes them green)**

Run: `go test -run TestEngineInjectsFileReader -run TestEngineHostnameOverride ./pkg/scanner/`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/scanner/engine_inject_test.go
git commit -m "test(scanner): cover Engine FileReader injection and hostname override"
```

---

### Task 3: Update CertificateModule (pilot — proves the pattern)

**Files:**
- Modify: `pkg/scanner/certificate.go`

- [ ] **Step 1: Add `reader` field and `SetFileReader` method**

Replace struct block (lines 26-33):

```go
type CertificateModule struct {
    config      *scannerconfig.Config
    lastScanned int64
    lastMatched int64
    store       store.Store
    reader      fsadapter.FileReader
}

func (m *CertificateModule) SetStore(s store.Store)              { m.store = s }
func (m *CertificateModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }
```

- [ ] **Step 2: Pass reader into walkerConfig inside `Scan()`**

In the `walkTarget(walkerConfig{...})` call (line 58), add:

```go
reader: m.reader,
```

- [ ] **Step 3: Build + run existing cert tests**

Run: `go build ./... && go test ./pkg/scanner/ -run TestCertificate`
Expected: PASS (local scans unchanged when reader=nil)

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/certificate.go
git commit -m "feat(scanner): certificate module implements FileReaderAware"
```

---

### Task 4: Update the remaining 16 modules (mechanical)

**Files (modify each):**
- `pkg/scanner/key.go`
- `pkg/scanner/library.go`
- `pkg/scanner/binary.go`
- `pkg/scanner/kernel.go`
- `pkg/scanner/config.go`
- `pkg/scanner/script.go`
- `pkg/scanner/webapp.go`
- `pkg/scanner/web_server.go`
- `pkg/scanner/vpn_config.go`
- `pkg/scanner/container_signatures.go`
- `pkg/scanner/password_hash.go`
- `pkg/scanner/auth_material.go`
- `pkg/scanner/deps_ecosystems.go`
- `pkg/scanner/service_mesh.go`
- `pkg/scanner/xml_dsig.go`
- `pkg/scanner/mail_server.go`

Apply the same three changes per file. Each file has a `<ModuleName>Module` struct and a `Scan` method that calls `walkTarget(walkerConfig{...})`.

- [ ] **Step 1: For each file, add `reader fsadapter.FileReader` field**

```go
type KeyModule struct {
    // ... existing fields ...
    reader fsadapter.FileReader
}
```

If the file doesn't already import `fsadapter`, add:
```go
"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
```

- [ ] **Step 2: Add `SetFileReader` method (next to `SetStore` if present, else after constructor)**

```go
func (m *KeyModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }
```

- [ ] **Step 3: Add `reader: m.reader,` to the `walkerConfig` literal in `Scan()`**

- [ ] **Step 4: Build after each module or in a batch of 4-5**

Run: `go build ./...`
Expected: success

- [ ] **Step 5: Run all scanner tests**

Run: `go test ./pkg/scanner/...`
Expected: PASS (local scans still default to LocalReader when reader=nil)

- [ ] **Step 6: Commit in batches by logical grouping, e.g.:**

```bash
git add pkg/scanner/key.go pkg/scanner/library.go pkg/scanner/binary.go pkg/scanner/kernel.go pkg/scanner/config.go
git commit -m "feat(scanner): file-crypto modules implement FileReaderAware"

git add pkg/scanner/script.go pkg/scanner/webapp.go pkg/scanner/web_server.go pkg/scanner/vpn_config.go pkg/scanner/container_signatures.go
git commit -m "feat(scanner): code/config/supply-chain modules implement FileReaderAware"

git add pkg/scanner/password_hash.go pkg/scanner/auth_material.go pkg/scanner/deps_ecosystems.go pkg/scanner/service_mesh.go pkg/scanner/xml_dsig.go pkg/scanner/mail_server.go
git commit -m "feat(scanner): auth/ecosystem/mesh modules implement FileReaderAware"
```

---

### Task 5: Module-level smoke test (FileReader actually routes I/O)

**Files:**
- Create: `pkg/scanner/certificate_reader_test.go`

- [ ] **Step 1: Write test that feeds a stub reader and confirms findings**

```go
package scanner

import (
    "context"
    "io/fs"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// stubFile is a minimal fs.FileInfo + fs.DirEntry for the test reader.
type stubFile struct {
    name string
    data []byte
}

func (s stubFile) Name() string               { return s.name }
func (s stubFile) Size() int64                { return int64(len(s.data)) }
func (s stubFile) Mode() fs.FileMode          { return 0644 }
func (s stubFile) ModTime() time.Time         { return time.Now() }
func (s stubFile) IsDir() bool                { return false }
func (s stubFile) Sys() any                   { return nil }
func (s stubFile) Type() fs.FileMode          { return 0 }
func (s stubFile) Info() (fs.FileInfo, error) { return s, nil }

type inMemReader struct {
    root  string
    files map[string][]byte
}

func (r *inMemReader) ReadFile(ctx context.Context, p string) ([]byte, error) {
    if b, ok := r.files[p]; ok {
        return b, nil
    }
    return nil, os.ErrNotExist
}
func (r *inMemReader) Stat(ctx context.Context, p string) (fs.FileInfo, error) {
    if b, ok := r.files[p]; ok {
        return stubFile{name: filepath.Base(p), data: b}, nil
    }
    return nil, os.ErrNotExist
}
func (r *inMemReader) ReadDir(ctx context.Context, p string) ([]fs.DirEntry, error) { return nil, nil }
func (r *inMemReader) Walk(ctx context.Context, root string, fn fsadapter.WalkFunc) error {
    for p, b := range r.files {
        if err := fn(p, stubFile{name: filepath.Base(p), data: b}, nil); err != nil {
            return err
        }
    }
    return nil
}

func TestCertificateModuleUsesInjectedReader(t *testing.T) {
    // Load the test fixture from local disk (once) — any real cert will do.
    pem, err := os.ReadFile("testdata/certs/rsa2048.pem")
    if err != nil {
        t.Skipf("fixture missing: %v", err)
    }

    reader := &inMemReader{
        root:  "/remote/etc/ssl",
        files: map[string][]byte{"/remote/etc/ssl/cert.pem": pem},
    }

    m := NewCertificateModule(&scannerconfig.Config{})
    m.SetFileReader(reader)

    findings := make(chan *model.Finding, 10)
    go func() {
        _ = m.Scan(context.Background(), model.ScanTarget{
            Type:  model.TargetFilesystem,
            Value: "/remote/etc/ssl",
        }, findings)
        close(findings)
    }()

    got := 0
    for range findings {
        got++
    }
    if got == 0 {
        t.Fatal("expected at least one finding from injected reader")
    }
}
```

- [ ] **Step 2: Find or create a small cert fixture**

If `pkg/scanner/testdata/certs/rsa2048.pem` does not exist:

```bash
mkdir -p pkg/scanner/testdata/certs
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out pkg/scanner/testdata/certs/rsa2048.pem -days 1 -nodes -subj "/CN=test"
rm /tmp/k.pem
```

- [ ] **Step 3: Run test**

Run: `go test -run TestCertificateModuleUsesInjectedReader ./pkg/scanner/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/certificate_reader_test.go pkg/scanner/testdata/certs/
git commit -m "test(scanner): certificate module routes I/O through injected FileReader"
```

---

### Task 6: Rewrite `Orchestrator.scanUnix` to run the real engine

**Files:**
- Modify: `pkg/scanner/netscan/orchestrator.go`

- [ ] **Step 1: Add imports**

```go
"github.com/amiryahaya/triton/internal/scannerconfig"
"github.com/amiryahaya/triton/pkg/scanner"
"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
```

- [ ] **Step 2: Replace `scanUnix` (lines 120-155) with:**

```go
// scanUnix runs the standard Tier 1 scanner pipeline against a remote
// Unix host via SSH. Constructs an SshReader, registers default modules,
// injects reader + hostname override, and drains the progress channel.
func (o *Orchestrator) scanUnix(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
    sshCfg, err := o.credToSSHConfig(d, cred)
    if err != nil {
        return nil, err
    }
    client, err := transport.NewSSHClient(ctx, sshCfg)
    if err != nil {
        return nil, fmt.Errorf("ssh connect: %w", err)
    }
    defer func() { _ = client.Close() }()

    reader := fsadapter.NewSshReader(client)

    paths := d.ScanPaths
    if len(paths) == 0 {
        paths = []string{"/etc", "/usr/local/etc", "/opt"}
    }

    cfg := scannerconfig.Load("standard")
    cfg.DBUrl = ""
    cfg.Workers = 4
    cfg.ScanTargets = make([]model.ScanTarget, 0, len(paths))
    for _, p := range paths {
        cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
            Type:  model.TargetFilesystem,
            Value: p,
            Depth: 10,
        })
    }

    eng := scanner.New(cfg)
    eng.RegisterDefaultModules()
    eng.SetFileReader(reader)
    eng.SetHostnameOverride(d.Name)

    progressCh := make(chan scanner.Progress, 32)
    go func() {
        for range progressCh {
        }
    }()

    result := eng.Scan(ctx, progressCh)
    if result == nil {
        return nil, fmt.Errorf("engine returned nil result")
    }
    result.Metadata.AgentID = "triton-netscan"
    result.Metadata.ScanProfile = "agentless-unix"
    return result, nil
}
```

- [ ] **Step 3: Confirm `Device.ScanPaths` exists; if not, add to `inventory.go`**

Check: `grep -n "ScanPaths" pkg/scanner/netscan/inventory.go`
If missing, add `ScanPaths []string \`yaml:"scan_paths,omitempty"\`` to the `Device` struct.

- [ ] **Step 4: Build**

Run: `go build ./...`
Expected: success

- [ ] **Step 5: Run netscan tests**

Run: `go test ./pkg/scanner/netscan/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/netscan/orchestrator.go pkg/scanner/netscan/inventory.go
git commit -m "feat(netscan): scanUnix runs real Engine via SshReader"
```

---

### Task 7: Full verification pass

- [ ] **Step 1: Format, lint, build**

Run: `make fmt && make lint && make build`
Expected: all succeed

- [ ] **Step 2: Unit tests**

Run: `make test`
Expected: PASS

- [ ] **Step 3: Integration tests**

Run: `TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" make test-integration`
Expected: PASS (agentless wiring should not break existing integration tests)

- [ ] **Step 4: Commit any formatting fixes**

```bash
git add -u
git diff --cached --quiet || git commit -m "style: gofmt"
```

---

### Task 8: Request code review

- [ ] **Step 1: Dispatch superpowers:code-reviewer** against the branch diff.

Prompt body:
- Implemented: Engine FileReader/CommandRunner injection + 17 module updates + orchestrator scanUnix rewrite
- Spec: `docs/plans/2026-04-14-agentless-unix-wiring-design.md`
- BASE_SHA: `main` tip before this branch
- HEAD_SHA: current HEAD
- Focus: correctness of injection order vs module registration, backward compat (nil reader path), resource cleanup (SSH client + progress goroutine), any module missed

- [ ] **Step 2: Address feedback**

Fix Critical + Important issues; commit per fix.

---

## Self-Review Checklist

1. **Spec coverage:** ✅ Engine API (Task 1-2), 17 modules (Task 3-4), orchestrator (Task 6), tests (Tasks 2, 5, 7).
2. **Placeholders:** none — all code blocks complete.
3. **Type consistency:** `SetFileReader(r fsadapter.FileReader)` signature identical across engine, stub, and all 17 modules. `SetHostnameOverride` referenced in Task 1 Step 3 and used in Task 2 test + Task 6 orchestrator.
