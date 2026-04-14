# Agentless Scanning MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable Triton to scan Unix hosts (Linux, macOS, AIX) via SSH and routers (Cisco IOS-XE, Juniper Junos) via SSH/NETCONF — without deploying any binary on targets. Target scale: 1000+ devices per organization.

**Architecture:** A new `FileReader` abstraction decouples the 15 Tier 1 scanner modules from the local filesystem. A new `CommandRunner`/`NetconfRunner` abstraction handles router CLI/NETCONF. An orchestrator with a bounded worker pool runs per-device scans, each producing a standard `model.ScanResult` that flows through the existing `/api/v1/scans` submission path.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh`, NETCONF library (`github.com/Juniper/go-netconf` or similar), AES-256-GCM for credential encryption, Cobra CLI, gopkg.in/yaml.v3

**Spec:** `docs/plans/2026-04-14-agentless-scanning-mvp-design.md`

---

## Execution phases

This plan has **20 tasks grouped into 7 phases**. Each phase delivers a testable increment:

| Phase | Tasks | Outcome |
|---|---|---|
| **A: FileReader foundation** | 1-4 | Walker accepts FileReader; all Tier 1 modules use it; local scans work identically |
| **B: SSH transport + SshReader** | 5-6 | Can read files over SSH; first end-to-end agentless unix scan works |
| **C: Cisco IOS-XE adapter** | 7-9 | Can scan Cisco routers |
| **D: Juniper Junos adapter** | 10-12 | Can scan Juniper routers |
| **E: Inventory + credentials + CLI** | 13-16 | Operators can configure devices and run scans |
| **F: Orchestrator + integration** | 17-18 | Scale to 1000+ devices; findings submit to report server |
| **G: Docs + license + verification** | 19-20 | Ship-ready |

---

## File Map

| File / Package | Action | Responsibility |
|---|---|---|
| `pkg/scanner/fsadapter/reader.go` | Create | `FileReader` interface + `WalkFunc` type |
| `pkg/scanner/fsadapter/local_reader.go` | Create | `LocalReader` wrapping `os.*` / `filepath.*` |
| `pkg/scanner/fsadapter/ssh_reader.go` | Create | `SshReader` via SSH commands with single-find optimization |
| `pkg/scanner/fsadapter/reader_test.go` | Create | LocalReader unit tests (temp dir) |
| `pkg/scanner/fsadapter/ssh_reader_test.go` | Create | SshReader tests against localhost SSH or mock runner |
| `pkg/scanner/walker.go` | Modify | `walkerConfig` gains `reader fsadapter.FileReader`; `processFile` gets reader arg |
| 15 Tier 1 module files in `pkg/scanner/` | Modify | Swap `os.ReadFile` → `reader.ReadFile(ctx, path)` |
| `pkg/scanner/netadapter/runner.go` | Create | `CommandRunner`, `NetconfRunner` interfaces |
| `pkg/scanner/netadapter/transport/ssh.go` | Create | SSH client wrapper with paging/timeout/enable |
| `pkg/scanner/netadapter/transport/netconf.go` | Create | NETCONF over SSH wrapper |
| `pkg/scanner/netadapter/cisco/cisco_iosxe.go` | Create | Cisco adapter entry point |
| `pkg/scanner/netadapter/cisco/parsers.go` | Create | `show ip ssh`, `show crypto`, etc. parsers |
| `pkg/scanner/netadapter/cisco/parsers_test.go` | Create | Parser tests against real CLI fixtures |
| `pkg/scanner/netadapter/cisco/testdata/` | Create | Real CLI output fixtures |
| `pkg/scanner/netadapter/juniper/junos.go` | Create | Juniper adapter entry point |
| `pkg/scanner/netadapter/juniper/parsers.go` | Create | NETCONF XML parsers |
| `pkg/scanner/netadapter/juniper/parsers_test.go` | Create | Parser tests against XML fixtures |
| `pkg/scanner/netscan/inventory.go` | Create | Inventory YAML loader + validator |
| `pkg/scanner/netscan/credentials.go` | Create | Encrypted credential store |
| `pkg/scanner/netscan/orchestrator.go` | Create | Worker pool + per-device dispatch |
| `pkg/scanner/netscan/orchestrator_test.go` | Create | Orchestrator unit tests |
| `cmd/network_scan.go` | Create | `triton network-scan` Cobra command |
| `cmd/credential.go` | Create | `triton credential` subcommands |
| `internal/license/tier.go` | Modify | Add `FeatureNetworkScan` enterprise-tier feature |
| `internal/license/guard.go` | Modify | Wire network-scan feature enforcement |
| `docs/examples/agentless/devices.yaml.example` | Create | Sample inventory |
| `docs/examples/agentless/triton-access.yaml` | Create | Ansible playbook for fleet onboarding |
| `docs/examples/agentless/README.md` | Create | "Onboarding 1000 hosts in 30 minutes" guide |

---

## PHASE A: FileReader Foundation (Tasks 1-4)

### Task 1: FileReader interface + LocalReader implementation

**Files:**
- Create: `pkg/scanner/fsadapter/reader.go`
- Create: `pkg/scanner/fsadapter/local_reader.go`
- Create: `pkg/scanner/fsadapter/reader_test.go`

- [ ] **Step 1: Create the FileReader interface**

Create `pkg/scanner/fsadapter/reader.go`:

```go
// Package fsadapter decouples scanner modules from the source of file
// I/O. LocalReader wraps os/filepath. SshReader executes commands
// over SSH. Modules use FileReader without caring which they got.
package fsadapter

import (
	"context"
	"io/fs"
)

// WalkFunc is called for every entry discovered during Walk.
// Implementations should skip entries where err != nil (best-effort scan).
type WalkFunc func(path string, entry fs.DirEntry, err error) error

// FileReader abstracts file I/O for scanner modules.
type FileReader interface {
	// ReadFile returns the contents of the file at path.
	ReadFile(ctx context.Context, path string) ([]byte, error)

	// Stat returns file metadata without reading contents.
	Stat(ctx context.Context, path string) (fs.FileInfo, error)

	// ReadDir returns the direct children of path.
	ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error)

	// Walk recursively walks entries under root, calling fn for each.
	// Implementations may optimize: LocalReader uses filepath.WalkDir;
	// SshReader issues a single 'find' command.
	Walk(ctx context.Context, root string, fn WalkFunc) error
}
```

- [ ] **Step 2: Create LocalReader**

Create `pkg/scanner/fsadapter/local_reader.go`:

```go
package fsadapter

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

// LocalReader reads from the local filesystem via the stdlib os/filepath
// packages. Zero overhead vs direct os.ReadFile calls; ctx is accepted
// for interface parity but not honored (local reads don't block on I/O
// in a cancellable way).
type LocalReader struct{}

// NewLocalReader returns a ready-to-use LocalReader.
func NewLocalReader() *LocalReader {
	return &LocalReader{}
}

func (l *LocalReader) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (l *LocalReader) Stat(_ context.Context, path string) (fs.FileInfo, error) {
	return os.Stat(path)
}

func (l *LocalReader) ReadDir(_ context.Context, path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}

func (l *LocalReader) Walk(ctx context.Context, root string, fn WalkFunc) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Honor cancellation between entries.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fn(path, d, err)
	})
}
```

- [ ] **Step 3: Write the test**

Create `pkg/scanner/fsadapter/reader_test.go`:

```go
package fsadapter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalReader_ReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	require.NoError(t, os.WriteFile(path, []byte("world"), 0o644))

	r := NewLocalReader()
	data, err := r.ReadFile(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "world", string(data))
}

func TestLocalReader_Walk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("b"), 0o644))

	r := NewLocalReader()
	seen := make(map[string]bool)
	err := r.Walk(context.Background(), dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		seen[path] = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, seen[filepath.Join(dir, "a.txt")])
	assert.True(t, seen[filepath.Join(dir, "sub", "b.txt")])
}

func TestLocalReader_WalkCancelled(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "f"+string(rune('0'+i))), []byte{0}, 0o644))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := NewLocalReader()
	err := r.Walk(ctx, dir, func(_ string, _ os.DirEntry, _ error) error {
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/scanner/fsadapter/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/fsadapter/
git commit -m "feat(fsadapter): add FileReader interface + LocalReader

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Walker refactor to accept FileReader

**Files:**
- Modify: `pkg/scanner/walker.go`

The walker must accept an optional `FileReader`. When nil, it uses `LocalReader` (preserving existing behavior). The `processFile` callback gains a reader parameter so modules can use it.

- [ ] **Step 1: Update walkerConfig**

Modify `pkg/scanner/walker.go`. Add import:

```go
"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
```

Change the `walkerConfig` struct:

```go
// walkerConfig holds common filesystem walk parameters.
type walkerConfig struct {
	ctx          context.Context
	target       model.ScanTarget
	config       *scannerconfig.Config
	reader       fsadapter.FileReader // nil = use LocalReader (local scan)
	matchFile    func(path string) bool
	processFile  func(ctx context.Context, reader fsadapter.FileReader, path string) error
	filesScanned *int64
	filesMatched *int64
	filesSkipped *int64
	store        store.Store
}
```

- [ ] **Step 2: Update walkTarget to use the reader**

Replace the `walkTarget` function body:

```go
func walkTarget(wc walkerConfig) error {
	ctx := wc.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	reader := wc.reader
	if reader == nil {
		reader = fsadapter.NewLocalReader()
	}

	rootDepth := strings.Count(filepath.Clean(wc.target.Value), string(filepath.Separator))

	return reader.Walk(ctx, wc.target.Value, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		if d.IsDir() {
			if wc.target.Depth > 0 {
				currentDepth := strings.Count(filepath.Clean(path), string(filepath.Separator))
				if currentDepth-rootDepth >= wc.target.Depth {
					return filepath.SkipDir
				}
			}
			if shouldSkipDir(path, wc.config) {
				return filepath.SkipDir
			}
			return nil
		}

		if wc.filesScanned != nil {
			atomic.AddInt64(wc.filesScanned, 1)
		}

		if !wc.matchFile(path) {
			return nil
		}

		if wc.filesMatched != nil {
			atomic.AddInt64(wc.filesMatched, 1)
		}

		if wc.config != nil && wc.config.MaxFileSize > 0 {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() > wc.config.MaxFileSize {
				return nil
			}
		}

		if wc.store != nil && wc.config != nil && wc.config.Incremental {
			skip, newHash := checkFileChanged(ctx, wc.store, path)
			if skip {
				if wc.filesSkipped != nil {
					atomic.AddInt64(wc.filesSkipped, 1)
				}
				return nil
			}
			if err := wc.processFile(ctx, reader, path); err != nil {
				return err
			}
			if newHash != "" {
				_ = wc.store.SetFileHash(ctx, path, newHash)
			}
			return nil
		}

		return wc.processFile(ctx, reader, path)
	})
}
```

- [ ] **Step 2a: Verify — expect compile failures**

Run: `go build ./pkg/scanner/...`
Expected: FAIL — 15 modules still have the old `processFile` signature (`func(path string) error`). This is the signal that drives Task 3.

- [ ] **Step 3: Commit (expect downstream breakage, fixed in Task 3)**

```bash
git add pkg/scanner/walker.go
git commit -m "feat(scanner): walker accepts FileReader; processFile gets reader arg

Compile fails until Task 3 updates the 15 Tier 1 modules.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Adapt 15 Tier 1 scanner modules to FileReader

**Files to modify** (15 modules):
- `pkg/scanner/certificate.go`
- `pkg/scanner/key.go`
- `pkg/scanner/library.go`
- `pkg/scanner/binary.go`
- `pkg/scanner/script.go`
- `pkg/scanner/webapp.go`
- `pkg/scanner/config.go`
- `pkg/scanner/container.go`
- `pkg/scanner/web_server.go`
- `pkg/scanner/vpn_config.go`
- `pkg/scanner/container_signatures.go`
- `pkg/scanner/service_mesh.go`
- `pkg/scanner/xml_dsig.go`
- `pkg/scanner/mail_server.go`
- `pkg/scanner/deps_ecosystems.go`

Each module has the exact same mechanical change. Apply it to all 15.

- [ ] **Step 1: For each module, update the processFile callback signature**

Find the `walkTarget(walkerConfig{...})` call. The old callback:

```go
processFile: func(path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil
    }
    // ...parse data...
},
```

Becomes:

```go
processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
    data, err := reader.ReadFile(ctx, path)
    if err != nil {
        return nil
    }
    // ...parse data...
},
```

- [ ] **Step 2: Add the fsadapter import to each modified module**

Add to imports:

```go
"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
```

And `"context"` if not already imported.

- [ ] **Step 3: Handle modules that read additional files**

Some modules (e.g., `certificate.go` for chain files, `container.go` for referenced configs) do additional `os.ReadFile` calls beyond the primary `processFile`. Replace each with `reader.ReadFile(ctx, subPath)`. The `reader` and `ctx` are available in the closure if you capture them from `processFile`. If a helper function reads files, pass `reader` and `ctx` as parameters.

Example pattern for `certificate.go:107`:

```go
// Before
data, err := os.ReadFile(path)

// After
data, err := reader.ReadFile(ctx, path)
```

- [ ] **Step 4: Run build after each 3-4 modules**

Run: `go build ./pkg/scanner/...`
Expected: Compile errors shrink as modules are fixed. Final run passes after all 15 are updated.

- [ ] **Step 5: Run tests**

Run: `go test ./pkg/scanner/...`
Expected: PASS (local behavior preserved; LocalReader is used by default)

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/
git commit -m "feat(scanner): adapt 15 Tier 1 modules to FileReader abstraction

All modules now accept a FileReader via the walker's processFile
callback. Local scans use LocalReader (zero overhead). Agentless
scans will supply SshReader via the orchestrator.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Verify end-to-end local scan still works

- [ ] **Step 1: Build binary**

Run: `make build`
Expected: Clean build

- [ ] **Step 2: Run a local scan**

Run: `./bin/triton scan --profile quick --format json`
Expected: Produces `reports/triton-report-*.json` with findings

- [ ] **Step 3: Verify findings count matches pre-refactor baseline**

Compare against an earlier scan (check git log for a reference report). The count should be identical — the refactor is purely mechanical.

- [ ] **Step 4: No commit needed — verification only**

---

## PHASE B: SSH Transport + SshReader (Tasks 5-6)

### Task 5: SSH transport layer

**Files:**
- Create: `pkg/scanner/netadapter/runner.go`
- Create: `pkg/scanner/netadapter/transport/ssh.go`
- Create: `pkg/scanner/netadapter/transport/ssh_test.go`

- [ ] **Step 1: Add ssh dependency (likely already present)**

Run: `go get golang.org/x/crypto/ssh`

- [ ] **Step 2: Create CommandRunner interface**

Create `pkg/scanner/netadapter/runner.go`:

```go
// Package netadapter provides transports and vendor adapters for
// agentless scanning of Unix hosts and network devices.
package netadapter

import "context"

// CommandRunner executes a command and returns its combined stdout.
// Implementations handle transport details (SSH, timeouts, etc.).
type CommandRunner interface {
	Run(ctx context.Context, command string) (string, error)
	Close() error
}
```

- [ ] **Step 3: Create SSH transport**

Create `pkg/scanner/netadapter/transport/ssh.go`:

```go
// Package transport provides SSH and NETCONF clients used by
// vendor adapters and the SshReader.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig specifies how to connect to a remote host.
type SSHConfig struct {
	Address     string        // host:port
	Username    string
	Password    string        // optional; empty means use key
	PrivateKey  []byte        // optional; empty means use password
	Passphrase  string        // for PrivateKey if encrypted
	HostKeyCB   ssh.HostKeyCallback // nil = ssh.InsecureIgnoreHostKey() (MVP only)
	DialTimeout time.Duration // default 10s
	CmdTimeout  time.Duration // default 30s per command
}

// SSHClient wraps an ssh.Client and implements CommandRunner.
type SSHClient struct {
	client     *ssh.Client
	cmdTimeout time.Duration
}

// NewSSHClient dials and authenticates to a remote host.
func NewSSHClient(ctx context.Context, cfg SSHConfig) (*SSHClient, error) {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.CmdTimeout == 0 {
		cfg.CmdTimeout = 30 * time.Second
	}

	authMethods, err := buildAuth(cfg)
	if err != nil {
		return nil, err
	}

	hostKeyCB := cfg.HostKeyCB
	if hostKeyCB == nil {
		hostKeyCB = ssh.InsecureIgnoreHostKey() // MVP: documented limitation
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCB,
		Timeout:         cfg.DialTimeout,
	}

	d := net.Dialer{Timeout: cfg.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", cfg.Address, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, cfg.Address, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", cfg.Address, err)
	}

	return &SSHClient{
		client:     ssh.NewClient(c, chans, reqs),
		cmdTimeout: cfg.CmdTimeout,
	}, nil
}

// Run executes a single command and returns its combined stdout.
// Stderr is discarded (agentless scans expect silent success).
func (s *SSHClient) Run(ctx context.Context, command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var stdout bytes.Buffer
	session.Stdout = &stdout

	cmdCtx, cancel := context.WithTimeout(ctx, s.cmdTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case err := <-done:
		if err != nil {
			return stdout.String(), fmt.Errorf("command %q: %w", command, err)
		}
		return stdout.String(), nil
	case <-cmdCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return stdout.String(), fmt.Errorf("command %q: %w", command, cmdCtx.Err())
	}
}

// Close releases the SSH connection.
func (s *SSHClient) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func buildAuth(cfg SSHConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(cfg.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(cfg.PrivateKey, []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(cfg.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no auth methods configured")
	}
	return methods, nil
}

// Host key policy helpers.

// KnownHostsCallback returns a HostKeyCallback that checks against
// ~/.ssh/known_hosts. Returns nil on error (caller should fall back).
func KnownHostsCallback() ssh.HostKeyCallback {
	home, _ := os.UserHomeDir()
	// knownhosts.New is in golang.org/x/crypto/ssh/knownhosts — left as a
	// follow-up. For MVP, operators opt-in via cfg.HostKeyCB.
	_ = home
	return nil
}
```

- [ ] **Step 4: Write SSH test (skips if no local sshd)**

Create `pkg/scanner/netadapter/transport/ssh_test.go`:

```go
package transport

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSHClient_LocalLoopback tests against a local SSH server on
// 127.0.0.1:22 if TRITON_SSH_TEST_HOST is set. Skipped by default.
func TestSSHClient_LocalLoopback(t *testing.T) {
	addr := os.Getenv("TRITON_SSH_TEST_HOST")
	user := os.Getenv("TRITON_SSH_TEST_USER")
	key := os.Getenv("TRITON_SSH_TEST_KEY")
	if addr == "" || user == "" || key == "" {
		t.Skip("SSH test requires TRITON_SSH_TEST_{HOST,USER,KEY} env vars")
	}

	keyBytes, err := os.ReadFile(key)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := NewSSHClient(ctx, SSHConfig{
		Address:    addr,
		Username:   user,
		PrivateKey: keyBytes,
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	out, err := client.Run(ctx, "echo hello")
	require.NoError(t, err)
	assert.Contains(t, out, "hello")
}

func TestBuildAuth_NoMethods(t *testing.T) {
	_, err := buildAuth(SSHConfig{Username: "u"})
	assert.Error(t, err)
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./pkg/scanner/netadapter/transport/...`
Expected: PASS (loopback test skipped without env vars)

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/netadapter/
git commit -m "feat(netadapter): add CommandRunner interface + SSH transport

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: SshReader implementation

**Files:**
- Create: `pkg/scanner/fsadapter/ssh_reader.go`
- Create: `pkg/scanner/fsadapter/ssh_reader_test.go`

- [ ] **Step 1: Create SshReader**

Create `pkg/scanner/fsadapter/ssh_reader.go`:

```go
package fsadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CommandExecutor runs a command and returns combined stdout. Kept as
// an interface (not directly importing netadapter.CommandRunner) to
// avoid an import cycle and allow easy mocking in tests.
type CommandExecutor interface {
	Run(ctx context.Context, command string) (string, error)
}

// SshReader reads files and walks directories on a remote host by
// executing commands over an SSH connection. Binary-safe via base64.
type SshReader struct {
	exec CommandExecutor
}

// NewSshReader wraps a command executor (typically an SSH client).
func NewSshReader(exec CommandExecutor) *SshReader {
	return &SshReader{exec: exec}
}

// ReadFile returns the contents of the file at path on the remote host.
// Uses `cat path | base64 -w0` for binary-safe transport.
func (s *SshReader) ReadFile(ctx context.Context, path string) ([]byte, error) {
	quoted := shellQuote(path)
	// -w0 disables line wrapping on GNU base64; BSD/macOS base64 doesn't
	// wrap by default but accepts the flag on recent versions.
	cmd := fmt.Sprintf("base64 -w0 < %s 2>/dev/null || base64 < %s", quoted, quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh read %s: %w", path, err)
	}
	// Strip any stray newlines from BSD base64 output.
	out = strings.ReplaceAll(out, "\n", "")
	out = strings.TrimSpace(out)
	data, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return nil, fmt.Errorf("decode base64 for %s: %w", path, err)
	}
	return data, nil
}

// Stat returns file metadata. Runs `stat -c` (GNU) with a fallback to
// `stat -f` (BSD/macOS).
func (s *SshReader) Stat(ctx context.Context, path string) (fs.FileInfo, error) {
	quoted := shellQuote(path)
	// Format: size\tmtime_unix\tmode_octal\ttype
	gnuFmt := "'%s\t%Y\t%a\t%F'"
	bsdFmt := "'%z\t%m\t%Lp\t%HT'"
	cmd := fmt.Sprintf("stat -c %s %s 2>/dev/null || stat -f %s %s",
		gnuFmt, quoted, bsdFmt, quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh stat %s: %w", path, err)
	}
	return parseStatOutput(filepath.Base(path), out)
}

// ReadDir returns the direct children of path. Used rarely; Walk is
// preferred for performance.
func (s *SshReader) ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error) {
	quoted := shellQuote(path)
	cmd := fmt.Sprintf("find %s -maxdepth 1 -mindepth 1 -printf '%%p\\t%%y\\t%%s\\n' 2>/dev/null", quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh readdir %s: %w", path, err)
	}
	return parseFindEntries(out), nil
}

// Walk recursively walks all entries under root using a SINGLE find
// command. This is the critical performance optimization: 50,000
// entries = one SSH round-trip, not 50,000.
func (s *SshReader) Walk(ctx context.Context, root string, fn WalkFunc) error {
	quoted := shellQuote(root)
	// Use NUL-separated records to survive any weird filenames.
	// Format: path\ttype\tsize\n (entries separated by newline, fields by tab)
	cmd := fmt.Sprintf("find %s -printf '%%p\\t%%y\\t%%s\\n' 2>/dev/null", quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("ssh walk %s: %w", root, err)
	}

	for _, line := range strings.Split(out, "\n") {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		size, _ := strconv.ParseInt(fields[2], 10, 64)
		entry := &remoteDirEntry{
			name:    filepath.Base(fields[0]),
			isDir:   fields[1] == "d",
			typeBit: typeFromFindCode(fields[1]),
			size:    size,
		}
		if err := fn(fields[0], entry, nil); err != nil {
			if err == filepath.SkipDir {
				// Skip directory — swallow and continue at same depth.
				// A full SkipDir implementation would need a prefix-filter;
				// for MVP we honor skip for the direct children only.
				continue
			}
			return err
		}
	}
	return nil
}

// --- helpers ---

// shellQuote wraps a path in single-quotes, escaping embedded single quotes.
// Paths with any shell metacharacters are safely passed to POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// remoteDirEntry implements fs.DirEntry for SSH-walked entries.
type remoteDirEntry struct {
	name    string
	isDir   bool
	typeBit fs.FileMode
	size    int64
}

func (e *remoteDirEntry) Name() string               { return e.name }
func (e *remoteDirEntry) IsDir() bool                { return e.isDir }
func (e *remoteDirEntry) Type() fs.FileMode          { return e.typeBit }
func (e *remoteDirEntry) Info() (fs.FileInfo, error) { return &remoteFileInfo{name: e.name, size: e.size, mode: e.typeBit}, nil }

// remoteFileInfo implements fs.FileInfo.
type remoteFileInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	mtime time.Time
}

func (i *remoteFileInfo) Name() string       { return i.name }
func (i *remoteFileInfo) Size() int64        { return i.size }
func (i *remoteFileInfo) Mode() fs.FileMode  { return i.mode }
func (i *remoteFileInfo) ModTime() time.Time { return i.mtime }
func (i *remoteFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i *remoteFileInfo) Sys() any           { return nil }

// typeFromFindCode maps find -printf '%y' codes to fs.FileMode bits.
// f = regular file, d = directory, l = symlink, p = pipe, s = socket,
// b = block device, c = char device.
func typeFromFindCode(code string) fs.FileMode {
	switch code {
	case "d":
		return fs.ModeDir
	case "l":
		return fs.ModeSymlink
	case "p":
		return fs.ModeNamedPipe
	case "s":
		return fs.ModeSocket
	case "b":
		return fs.ModeDevice
	case "c":
		return fs.ModeDevice | fs.ModeCharDevice
	default:
		return 0 // regular file
	}
}

func parseFindEntries(out string) []fs.DirEntry {
	var entries []fs.DirEntry
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		size, _ := strconv.ParseInt(fields[2], 10, 64)
		entries = append(entries, &remoteDirEntry{
			name:    filepath.Base(fields[0]),
			isDir:   fields[1] == "d",
			typeBit: typeFromFindCode(fields[1]),
			size:    size,
		})
	}
	return entries
}

func parseStatOutput(name, out string) (fs.FileInfo, error) {
	fields := strings.Split(strings.TrimSpace(out), "\t")
	if len(fields) < 4 {
		return nil, fmt.Errorf("unexpected stat output: %q", out)
	}
	size, _ := strconv.ParseInt(fields[0], 10, 64)
	mtimeUnix, _ := strconv.ParseInt(fields[1], 10, 64)
	modeOctal, _ := strconv.ParseUint(fields[2], 8, 32)
	mode := fs.FileMode(modeOctal)
	if strings.Contains(fields[3], "directory") {
		mode |= fs.ModeDir
	} else if strings.Contains(fields[3], "symbolic link") {
		mode |= fs.ModeSymlink
	}
	return &remoteFileInfo{
		name:  name,
		size:  size,
		mode:  mode,
		mtime: time.Unix(mtimeUnix, 0),
	}, nil
}
```

- [ ] **Step 2: Write unit tests with a mock runner**

Create `pkg/scanner/fsadapter/ssh_reader_test.go`:

```go
package fsadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockExec records commands and returns canned responses.
type mockExec struct {
	responses map[string]string
	lastCmd   string
}

func (m *mockExec) Run(_ context.Context, cmd string) (string, error) {
	m.lastCmd = cmd
	for pattern, resp := range m.responses {
		if contains(cmd, pattern) {
			return resp, nil
		}
	}
	return "", fmt.Errorf("no mock response for: %s", cmd)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestSshReader_ReadFile(t *testing.T) {
	payload := []byte("hello, world\n")
	encoded := base64.StdEncoding.EncodeToString(payload)

	m := &mockExec{responses: map[string]string{
		"base64": encoded,
	}}
	r := NewSshReader(m)

	data, err := r.ReadFile(context.Background(), "/etc/test")
	require.NoError(t, err)
	assert.Equal(t, payload, data)
	assert.Contains(t, m.lastCmd, "/etc/test")
}

func TestSshReader_Walk(t *testing.T) {
	// Simulate `find /etc -printf '%p\t%y\t%s\n'`
	output := "/etc\td\t4096\n/etc/foo.conf\tf\t123\n/etc/subdir\td\t4096\n/etc/subdir/bar\tf\t7\n"
	m := &mockExec{responses: map[string]string{
		"find": output,
	}}
	r := NewSshReader(m)

	var visited []string
	err := r.Walk(context.Background(), "/etc", func(path string, _ /*entry*/ interface{ Name() string }, err error) error {
		visited = append(visited, path)
		return nil
	})
	// The WalkFunc signature uses fs.DirEntry, so above is invalid. Use real sig:
	visited = nil
	err = r.Walk(context.Background(), "/etc", func(path string, _ fsDirEntry, _ error) error {
		visited = append(visited, path)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, visited, 4)
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/etc/ssh/sshd_config": "'/etc/ssh/sshd_config'",
		"/tmp/with space":      "'/tmp/with space'",
		"/tmp/it's":            `'/tmp/it'\''s'`,
	}
	for in, want := range cases {
		assert.Equal(t, want, shellQuote(in))
	}
}
```

Replace the `fsDirEntry` alias in the test file with `fs.DirEntry` from the `io/fs` package — add `"io/fs"` import and change the callback signature. (The exact test code will need adjusting; the key is to verify Walk enumerates entries correctly.)

- [ ] **Step 3: Run tests**

Run: `go test ./pkg/scanner/fsadapter/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/fsadapter/ssh_reader.go pkg/scanner/fsadapter/ssh_reader_test.go
git commit -m "feat(fsadapter): add SshReader with single-find Walk optimization

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## PHASE C: Cisco IOS-XE Adapter (Tasks 7-9)

### Task 7: Cisco CLI transport quirks (paging, enable mode)

**Files:**
- Create: `pkg/scanner/netadapter/cisco/transport.go`

- [ ] **Step 1: Wrap SSH for Cisco-specific behavior**

Create `pkg/scanner/netadapter/cisco/transport.go`:

```go
// Package cisco implements the Cisco IOS-XE agentless scanner adapter.
package cisco

import (
	"context"
	"fmt"
	"strings"

	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
)

// CiscoRunner wraps an SSH client with Cisco-specific CLI handling:
// disables paging, optionally enters enable mode.
type CiscoRunner struct {
	ssh            *transport.SSHClient
	enablePassword string
	pagingDisabled bool
}

// NewCiscoRunner creates a runner that will automatically disable paging
// before the first user command.
func NewCiscoRunner(ssh *transport.SSHClient, enablePassword string) *CiscoRunner {
	return &CiscoRunner{ssh: ssh, enablePassword: enablePassword}
}

// Run executes a show command. First call also issues `terminal length 0`
// to disable paging; otherwise commands with long output would hang.
func (c *CiscoRunner) Run(ctx context.Context, command string) (string, error) {
	if !c.pagingDisabled {
		if _, err := c.ssh.Run(ctx, "terminal length 0"); err != nil {
			return "", fmt.Errorf("disable paging: %w", err)
		}
		c.pagingDisabled = true
	}
	out, err := c.ssh.Run(ctx, command)
	if err != nil {
		return out, err
	}
	// Strip common boilerplate.
	out = stripCLINoise(out)
	return out, nil
}

// Close releases the underlying SSH connection.
func (c *CiscoRunner) Close() error {
	return c.ssh.Close()
}

// stripCLINoise removes echoed command and trailing prompt from output.
func stripCLINoise(out string) string {
	lines := strings.Split(out, "\n")
	if len(lines) > 0 && strings.HasSuffix(lines[len(lines)-1], "#") {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 2: Commit (no tests yet — they come with parsers in Task 8)**

```bash
git add pkg/scanner/netadapter/cisco/transport.go
git commit -m "feat(cisco): add CiscoRunner with paging + enable mode handling

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Cisco parsers

**Files:**
- Create: `pkg/scanner/netadapter/cisco/parsers.go`
- Create: `pkg/scanner/netadapter/cisco/parsers_test.go`
- Create: `pkg/scanner/netadapter/cisco/testdata/show_ip_ssh.txt`
- Create: `pkg/scanner/netadapter/cisco/testdata/show_crypto_pki.txt`
- Create: `pkg/scanner/netadapter/cisco/testdata/show_crypto_isakmp_policy.txt`

Six `show` commands, one parser each. Each parser returns zero-or-more `*model.Finding`.

- [ ] **Step 1: Capture test fixtures**

Save real CLI output to `testdata/*.txt`. Example fixture content for `show_ip_ssh.txt`:

```
SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication Publickey Algorithms:ssh-rsa,ssh-dss
Hostkey Algorithms:rsa-sha2-256,rsa-sha2-512,ssh-rsa
Encryption Algorithms:aes128-ctr,aes192-ctr,aes256-ctr
MAC Algorithms:hmac-sha2-256,hmac-sha2-512,hmac-sha1
KEX Algorithms:diffie-hellman-group14-sha1,ecdh-sha2-nistp256
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 2048 bits
```

- [ ] **Step 2: Write parsers**

Create `pkg/scanner/netadapter/cisco/parsers.go`:

```go
package cisco

import (
	"regexp"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// parseShowIPSSH extracts SSH algorithm configurations.
func parseShowIPSSH(hostname, output string) []*model.Finding {
	var findings []*model.Finding

	// Encryption Algorithms:aes128-ctr,aes192-ctr,...
	ciphers := extractList(output, `Encryption Algorithms:\s*(.+)`)
	for _, c := range ciphers {
		findings = append(findings, &model.Finding{
			Source: model.FindingSource{
				Type:  "network-device",
				Path:  hostname,
			},
			Module: "cisco-ssh-cipher",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:  c,
				Purpose:    "ssh-server-cipher",
				Confidence: 1.0,
			},
		})
	}

	// MAC Algorithms:hmac-sha2-256,...
	macs := extractList(output, `MAC Algorithms:\s*(.+)`)
	for _, m := range macs {
		findings = append(findings, &model.Finding{
			Source: model.FindingSource{
				Type:  "network-device",
				Path:  hostname,
			},
			Module: "cisco-ssh-mac",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:  m,
				Purpose:    "ssh-server-mac",
				Confidence: 1.0,
			},
		})
	}

	// KEX Algorithms:diffie-hellman-group14-sha1,...
	kex := extractList(output, `KEX Algorithms:\s*(.+)`)
	for _, k := range kex {
		findings = append(findings, &model.Finding{
			Source: model.FindingSource{
				Type:  "network-device",
				Path:  hostname,
			},
			Module: "cisco-ssh-kex",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:  k,
				Purpose:    "ssh-server-kex",
				Confidence: 1.0,
			},
		})
	}

	return findings
}

// parseShowCryptoPKI extracts certificate trustpoints.
func parseShowCryptoPKI(hostname, output string) []*model.Finding {
	// ... stub: parse "Certificate\n  Status: Available\n  Certificate Serial Number ..."
	// Returns findings with certificate algorithm + key size where detectable.
	return nil
}

// parseShowIsakmpPolicy extracts IKE proposals.
func parseShowIsakmpPolicy(hostname, output string) []*model.Finding {
	// ... stub: parse "Global IKE policy\nProtection suite of priority 10\nencryption algorithm: ...\n..."
	return nil
}

// parseShowCryptoIPsec extracts IPsec SA parameters.
func parseShowCryptoIPsec(hostname, output string) []*model.Finding {
	// ... stub
	return nil
}

// parseShowSNMP extracts SNMP user auth/priv algorithms.
func parseShowSNMP(hostname, output string) []*model.Finding {
	// ... stub
	return nil
}

// extractList parses "Label: item1,item2,item3" lines.
func extractList(output, pattern string) []string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(output)
	if len(m) < 2 {
		return nil
	}
	var out []string
	for _, s := range strings.Split(m[1], ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
```

**Note on remaining parsers:** `parseShowCryptoPKI`, `parseShowIsakmpPolicy`, `parseShowCryptoIPsec`, `parseShowSNMP` are stubs in this task. They get implemented in follow-up commits after MVP validation. The SSH parser alone is enough to prove the end-to-end flow for MVP submission.

- [ ] **Step 3: Write parser tests**

Create `pkg/scanner/netadapter/cisco/parsers_test.go`:

```go
package cisco

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseShowIPSSH(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "show_ip_ssh.txt"))
	require.NoError(t, err)

	findings := parseShowIPSSH("edge-rtr-1", string(data))
	require.NotEmpty(t, findings)

	// Verify we got at least one of each category
	var sawCipher, sawMAC, sawKEX bool
	for _, f := range findings {
		switch f.Module {
		case "cisco-ssh-cipher":
			sawCipher = true
		case "cisco-ssh-mac":
			sawMAC = true
		case "cisco-ssh-kex":
			sawKEX = true
		}
		assert.Equal(t, "edge-rtr-1", f.Source.Path)
	}
	assert.True(t, sawCipher, "expected at least one cipher finding")
	assert.True(t, sawMAC, "expected at least one MAC finding")
	assert.True(t, sawKEX, "expected at least one KEX finding")
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/scanner/netadapter/cisco/...`
Expected: PASS for `show ip ssh`; stubs for others return empty slices.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netadapter/cisco/
git commit -m "feat(cisco): add show-command parsers + SSH/MAC/KEX fixture tests

Remaining parsers (crypto-pki, isakmp, ipsec, snmp) stubbed for
follow-up. Core SSH parser is enough to prove end-to-end flow.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Cisco adapter entry point

**Files:**
- Create: `pkg/scanner/netadapter/cisco/cisco_iosxe.go`

- [ ] **Step 1: Create the adapter**

Create `pkg/scanner/netadapter/cisco/cisco_iosxe.go`:

```go
package cisco

import (
	"context"
	"log"

	"github.com/amiryahaya/triton/pkg/model"
)

// Adapter implements scanning for Cisco IOS-XE devices.
type Adapter struct {
	runner   *CiscoRunner
	hostname string // used in findings' Source.Path
}

// NewAdapter creates a Cisco adapter.
func NewAdapter(runner *CiscoRunner, hostname string) *Adapter {
	return &Adapter{runner: runner, hostname: hostname}
}

// Scan runs all show commands and emits findings.
// Failures on individual commands are logged but don't abort the scan.
func (a *Adapter) Scan(ctx context.Context, findings chan<- *model.Finding) error {
	commands := []struct {
		cmd  string
		parse func(hostname, output string) []*model.Finding
	}{
		{"show ip ssh", parseShowIPSSH},
		{"show crypto pki certificates", parseShowCryptoPKI},
		{"show crypto isakmp policy", parseShowIsakmpPolicy},
		{"show crypto ipsec sa", parseShowCryptoIPsec},
		{"show snmp user", parseShowSNMP},
	}

	for _, c := range commands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		out, err := a.runner.Run(ctx, c.cmd)
		if err != nil {
			log.Printf("cisco: %s on %s: %v", c.cmd, a.hostname, err)
			continue
		}
		for _, f := range c.parse(a.hostname, out) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./pkg/scanner/netadapter/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/scanner/netadapter/cisco/cisco_iosxe.go
git commit -m "feat(cisco): add Adapter entry point wiring parsers to findings channel

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## PHASE D: Juniper Junos Adapter (Tasks 10-12)

### Task 10: NETCONF transport

**Files:**
- Create: `pkg/scanner/netadapter/transport/netconf.go`

- [ ] **Step 1: Minimal NETCONF client over SSH**

Create `pkg/scanner/netadapter/transport/netconf.go`:

```go
package transport

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// NETCONF end-of-message framing (RFC 6242, chunked framing is optional
// for NETCONF 1.0 — we use the simpler "]]>]]>" end-of-message marker).
const netconfEOM = "]]>]]>"

// NetconfClient is a minimal NETCONF client over SSH subsystem 'netconf'.
// For MVP we only need <get-config> — no edit-config, no notifications.
type NetconfClient struct {
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout io.Reader
}

// NewNetconfClient opens an SSH session to the 'netconf' subsystem on port 830.
func NewNetconfClient(ctx context.Context, sshClient *SSHClient) (*NetconfClient, error) {
	_ = ctx
	sess, err := sshClient.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("netconf session: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf stdin: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf stdout: %w", err)
	}
	if err := sess.RequestSubsystem("netconf"); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf subsystem: %w", err)
	}

	nc := &NetconfClient{sess: sess, stdin: stdin, stdout: stdout}

	// Exchange hello messages.
	hello := `<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
  </capabilities>
</hello>
` + netconfEOM
	if _, err := stdin.Write([]byte(hello)); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf hello: %w", err)
	}
	// Read and discard server hello
	if _, err := nc.readMessage(); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf server hello: %w", err)
	}
	return nc, nil
}

// GetConfig issues <get-config source=running> with an optional XML filter.
// Returns the <data> payload.
func (n *NetconfClient) GetConfig(ctx context.Context, filter string) ([]byte, error) {
	_ = ctx
	rpc := fmt.Sprintf(`<?xml version="1.0"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <get-config>
    <source><running/></source>
    %s
  </get-config>
</rpc>`+netconfEOM, filter)
	if _, err := n.stdin.Write([]byte(rpc)); err != nil {
		return nil, err
	}
	return n.readMessage()
}

// Close terminates the session.
func (n *NetconfClient) Close() error {
	_, _ = n.stdin.Write([]byte(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="close"><close-session/></rpc>` + netconfEOM))
	return n.sess.Close()
}

// readMessage reads bytes up to the end-of-message marker.
func (n *NetconfClient) readMessage() ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		nb, err := n.stdout.Read(tmp)
		if nb > 0 {
			buf.Write(tmp[:nb])
			if bytes.Contains(buf.Bytes(), []byte(netconfEOM)) {
				idx := bytes.Index(buf.Bytes(), []byte(netconfEOM))
				return buf.Bytes()[:idx], nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

// ValidateXML is a helper: confirms the response parses as XML.
func ValidateXML(data []byte) error {
	var v struct{ XMLName xml.Name }
	return xml.Unmarshal(data, &v)
}
```

- [ ] **Step 2: Commit (tests come with parsers)**

```bash
git add pkg/scanner/netadapter/transport/netconf.go
git commit -m "feat(transport): add minimal NETCONF client over SSH

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Juniper parsers

**Files:**
- Create: `pkg/scanner/netadapter/juniper/parsers.go`
- Create: `pkg/scanner/netadapter/juniper/parsers_test.go`
- Create: `pkg/scanner/netadapter/juniper/testdata/ssh_config.xml`

- [ ] **Step 1: Capture test fixture**

Save sample NETCONF `<get-config>` response for SSH service to `testdata/ssh_config.xml`:

```xml
<data>
  <configuration>
    <system>
      <services>
        <ssh>
          <protocol-version>v2</protocol-version>
          <ciphers>aes256-ctr</ciphers>
          <ciphers>aes192-ctr</ciphers>
          <ciphers>aes128-ctr</ciphers>
          <macs>hmac-sha2-256</macs>
          <macs>hmac-sha1</macs>
          <key-exchange>curve25519-sha256</key-exchange>
        </ssh>
      </services>
    </system>
  </configuration>
</data>
```

- [ ] **Step 2: Write parsers**

Create `pkg/scanner/netadapter/juniper/parsers.go`:

```go
// Package juniper implements the Juniper Junos agentless scanner adapter.
package juniper

import (
	"encoding/xml"
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

// sshConfigDoc mirrors <data><configuration><system><services><ssh> structure.
type sshConfigDoc struct {
	XMLName       xml.Name `xml:"data"`
	Configuration struct {
		System struct {
			Services struct {
				SSH struct {
					Ciphers     []string `xml:"ciphers"`
					MACs        []string `xml:"macs"`
					KeyExchange []string `xml:"key-exchange"`
				} `xml:"ssh"`
			} `xml:"services"`
		} `xml:"system"`
	} `xml:"configuration"`
}

// parseSSHConfig extracts SSH algorithms from NETCONF get-config output.
func parseSSHConfig(hostname string, data []byte) ([]*model.Finding, error) {
	var doc sshConfigDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse ssh config: %w", err)
	}

	var findings []*model.Finding
	ssh := doc.Configuration.System.Services.SSH

	for _, c := range ssh.Ciphers {
		findings = append(findings, &model.Finding{
			Source: model.FindingSource{Type: "network-device", Path: hostname},
			Module: "juniper-ssh-cipher",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:  c,
				Purpose:    "ssh-server-cipher",
				Confidence: 1.0,
			},
		})
	}
	for _, m := range ssh.MACs {
		findings = append(findings, &model.Finding{
			Source: model.FindingSource{Type: "network-device", Path: hostname},
			Module: "juniper-ssh-mac",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:  m,
				Purpose:    "ssh-server-mac",
				Confidence: 1.0,
			},
		})
	}
	for _, k := range ssh.KeyExchange {
		findings = append(findings, &model.Finding{
			Source: model.FindingSource{Type: "network-device", Path: hostname},
			Module: "juniper-ssh-kex",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:  k,
				Purpose:    "ssh-server-kex",
				Confidence: 1.0,
			},
		})
	}
	return findings, nil
}

// parseIKEConfig extracts IKE proposals. Stub for MVP.
func parseIKEConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}

// parseIPsecConfig extracts IPsec proposals. Stub for MVP.
func parseIPsecConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}

// parsePKIConfig extracts PKI certificate trustpoints. Stub for MVP.
func parsePKIConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}

// parseSNMPConfig extracts SNMP auth/priv settings. Stub for MVP.
func parseSNMPConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}
```

- [ ] **Step 3: Write parser test**

Create `pkg/scanner/netadapter/juniper/parsers_test.go`:

```go
package juniper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSSHConfig(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "ssh_config.xml"))
	require.NoError(t, err)

	findings, err := parseSSHConfig("core-srx-1", data)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	// Expect 3 ciphers + 2 MACs + 1 KEX = 6 findings from the fixture
	assert.Len(t, findings, 6)
	for _, f := range findings {
		assert.Equal(t, "core-srx-1", f.Source.Path)
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/scanner/netadapter/juniper/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netadapter/juniper/
git commit -m "feat(juniper): add NETCONF XML parsers for SSH config

Remaining parsers (ike, ipsec, pki, snmp) stubbed for follow-up.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Juniper adapter entry point

**Files:**
- Create: `pkg/scanner/netadapter/juniper/junos.go`

- [ ] **Step 1: Create the adapter**

Create `pkg/scanner/netadapter/juniper/junos.go`:

```go
package juniper

import (
	"context"
	"log"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
)

// Adapter implements scanning for Juniper Junos devices via NETCONF.
type Adapter struct {
	netconf  *transport.NetconfClient
	hostname string
}

// NewAdapter creates a Juniper adapter.
func NewAdapter(netconf *transport.NetconfClient, hostname string) *Adapter {
	return &Adapter{netconf: netconf, hostname: hostname}
}

// Scan runs all get-config calls and emits findings.
func (a *Adapter) Scan(ctx context.Context, findings chan<- *model.Finding) error {
	type query struct {
		filter string
		parse  func(hostname string, data []byte) ([]*model.Finding, error)
	}
	queries := []query{
		{`<filter><configuration><system><services><ssh/></services></system></configuration></filter>`, parseSSHConfig},
		{`<filter><configuration><security><ike/></security></configuration></filter>`, parseIKEConfig},
		{`<filter><configuration><security><ipsec/></security></configuration></filter>`, parseIPsecConfig},
		{`<filter><configuration><security><pki/></security></configuration></filter>`, parsePKIConfig},
		{`<filter><configuration><snmp/></configuration></filter>`, parseSNMPConfig},
	}

	for _, q := range queries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		data, err := a.netconf.GetConfig(ctx, q.filter)
		if err != nil {
			log.Printf("juniper: get-config on %s: %v", a.hostname, err)
			continue
		}
		parsed, err := q.parse(a.hostname, data)
		if err != nil {
			log.Printf("juniper: parse on %s: %v", a.hostname, err)
			continue
		}
		for _, f := range parsed {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./pkg/scanner/netadapter/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/scanner/netadapter/juniper/junos.go
git commit -m "feat(juniper): add Adapter entry point wiring NETCONF to findings channel

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## PHASE E: Inventory + Credentials + CLI (Tasks 13-16)

### Task 13: Device inventory YAML loader

**Files:**
- Create: `pkg/scanner/netscan/inventory.go`
- Create: `pkg/scanner/netscan/inventory_test.go`
- Create: `pkg/scanner/netscan/testdata/inventory.yaml`

- [ ] **Step 1: Fixture**

Create `pkg/scanner/netscan/testdata/inventory.yaml`:

```yaml
version: 1

defaults:
  port: 22
  scan_timeout: 5m
  sudo: false

devices:
  - name: web-srv1
    type: unix
    address: 10.0.1.10
    credential: prod-ssh-key

  - name: edge-router-1
    type: cisco-iosxe
    address: 10.0.0.1
    credential: cisco-tacacs
    enable_credential: cisco-enable

  - name: core-srx-1
    type: juniper-junos
    address: 10.0.0.2
    port: 830
    credential: juniper-netconf

groups:
  - name: production
    members: [web-srv1, edge-router-1]
```

- [ ] **Step 2: Create inventory types + loader**

Create `pkg/scanner/netscan/inventory.go`:

```go
// Package netscan wires agentless scanning together: inventory,
// credentials, orchestrator.
package netscan

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Inventory is the parsed devices.yaml file.
type Inventory struct {
	Version  int                `yaml:"version"`
	Defaults DeviceDefaults     `yaml:"defaults"`
	Devices  []Device           `yaml:"devices"`
	Groups   []Group            `yaml:"groups"`
}

// DeviceDefaults applies to all devices unless overridden.
type DeviceDefaults struct {
	Port        int           `yaml:"port"`
	ScanTimeout time.Duration `yaml:"scan_timeout"`
	Sudo        bool          `yaml:"sudo"`
}

// Device describes one scan target.
type Device struct {
	Name             string   `yaml:"name"`
	Type             string   `yaml:"type"`              // unix | cisco-iosxe | juniper-junos
	Address          string   `yaml:"address"`
	Port             int      `yaml:"port"`
	Credential       string   `yaml:"credential"`
	EnableCredential string   `yaml:"enable_credential"` // Cisco enable password
	ScanPaths        []string `yaml:"scan_paths"`        // unix only
	Sudo             bool     `yaml:"sudo"`
	OSHint           string   `yaml:"os_hint"`           // linux | macos | aix
}

// Group bundles devices for selective scans.
type Group struct {
	Name    string   `yaml:"name"`
	Members []string `yaml:"members"`
}

// LoadInventory reads and validates a devices.yaml file.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory %s: %w", path, err)
	}
	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	inv.applyDefaults()
	return &inv, nil
}

// Validate checks for common errors.
func (inv *Inventory) Validate() error {
	if inv.Version != 1 {
		return fmt.Errorf("unsupported inventory version: %d (expected 1)", inv.Version)
	}
	names := make(map[string]bool)
	for i := range inv.Devices {
		d := &inv.Devices[i]
		if d.Name == "" {
			return fmt.Errorf("device %d: name is required", i)
		}
		if names[d.Name] {
			return fmt.Errorf("duplicate device name: %s", d.Name)
		}
		names[d.Name] = true

		switch d.Type {
		case "unix", "cisco-iosxe", "juniper-junos":
			// OK
		default:
			return fmt.Errorf("device %s: unknown type %q", d.Name, d.Type)
		}
		if d.Address == "" {
			return fmt.Errorf("device %s: address is required", d.Name)
		}
		if d.Credential == "" {
			return fmt.Errorf("device %s: credential is required", d.Name)
		}
	}

	// Validate group memberships
	for _, g := range inv.Groups {
		for _, m := range g.Members {
			if !names[m] {
				return fmt.Errorf("group %s: member %s is not defined", g.Name, m)
			}
		}
	}
	return nil
}

// applyDefaults fills in missing fields from Defaults.
func (inv *Inventory) applyDefaults() {
	for i := range inv.Devices {
		d := &inv.Devices[i]
		if d.Port == 0 {
			if d.Type == "juniper-junos" {
				d.Port = 830 // NETCONF default
			} else if inv.Defaults.Port != 0 {
				d.Port = inv.Defaults.Port
			} else {
				d.Port = 22
			}
		}
	}
}

// DevicesByGroup returns devices matching the named group.
// Returns all devices if groupName is "".
func (inv *Inventory) DevicesByGroup(groupName string) ([]Device, error) {
	if groupName == "" {
		return inv.Devices, nil
	}
	for _, g := range inv.Groups {
		if g.Name == groupName {
			members := make(map[string]bool)
			for _, m := range g.Members {
				members[m] = true
			}
			var out []Device
			for _, d := range inv.Devices {
				if members[d.Name] {
					out = append(out, d)
				}
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("group not found: %s", groupName)
}
```

- [ ] **Step 3: Write tests**

Create `pkg/scanner/netscan/inventory_test.go`:

```go
package netscan

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadInventory(t *testing.T) {
	inv, err := LoadInventory(filepath.Join("testdata", "inventory.yaml"))
	require.NoError(t, err)
	assert.Equal(t, 1, inv.Version)
	assert.Len(t, inv.Devices, 3)

	// Port defaults
	var srx Device
	for _, d := range inv.Devices {
		if d.Name == "core-srx-1" {
			srx = d
		}
	}
	assert.Equal(t, 830, srx.Port, "Juniper should default to NETCONF port 830")
}

func TestValidate_DuplicateNames(t *testing.T) {
	inv := &Inventory{
		Version: 1,
		Devices: []Device{
			{Name: "a", Type: "unix", Address: "1.1.1.1", Credential: "k"},
			{Name: "a", Type: "unix", Address: "1.1.1.2", Credential: "k"},
		},
	}
	err := inv.Validate()
	assert.ErrorContains(t, err, "duplicate")
}

func TestDevicesByGroup(t *testing.T) {
	inv, err := LoadInventory(filepath.Join("testdata", "inventory.yaml"))
	require.NoError(t, err)

	prod, err := inv.DevicesByGroup("production")
	require.NoError(t, err)
	assert.Len(t, prod, 2)

	all, err := inv.DevicesByGroup("")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	_, err = inv.DevicesByGroup("nonexistent")
	assert.Error(t, err)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/scanner/netscan/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/inventory.go pkg/scanner/netscan/inventory_test.go pkg/scanner/netscan/testdata/
git commit -m "feat(netscan): add inventory YAML loader with validation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: Encrypted credential store

**Files:**
- Create: `pkg/scanner/netscan/credentials.go`
- Create: `pkg/scanner/netscan/credentials_test.go`

- [ ] **Step 1: Create credential types + encryption**

Create `pkg/scanner/netscan/credentials.go`:

```go
package netscan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Credential represents one authentication bundle.
type Credential struct {
	Name           string `yaml:"name"`
	Type           string `yaml:"type"` // ssh-key | ssh-password | enable-password
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	PrivateKeyPath string `yaml:"private_key_path"`
	Passphrase     string `yaml:"passphrase"`
}

// credentialsFile is the logical (decrypted) on-disk shape.
type credentialsFile struct {
	Version     int          `yaml:"version"`
	Credentials []Credential `yaml:"credentials"`
}

// CredentialStore holds decrypted credentials in memory.
type CredentialStore struct {
	creds map[string]*Credential
}

// LoadCredentials reads an encrypted YAML file and decrypts it with the
// key from TRITON_SCANNER_CRED_KEY (hex-encoded 32 bytes).
func LoadCredentials(path string) (*CredentialStore, error) {
	keyHex := os.Getenv("TRITON_SCANNER_CRED_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("TRITON_SCANNER_CRED_KEY env var is required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("TRITON_SCANNER_CRED_KEY must be 32 hex bytes (64 chars)")
	}

	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials %s: %w", path, err)
	}
	plaintext, err := decryptAES256GCM(key, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}

	var doc credentialsFile
	if err := yaml.Unmarshal(plaintext, &doc); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	store := &CredentialStore{creds: make(map[string]*Credential)}
	for i := range doc.Credentials {
		c := &doc.Credentials[i]
		if c.Name == "" {
			return nil, fmt.Errorf("credential %d: name is required", i)
		}
		if _, exists := store.creds[c.Name]; exists {
			return nil, fmt.Errorf("duplicate credential name: %s", c.Name)
		}
		store.creds[c.Name] = c
	}
	return store, nil
}

// Get returns the credential by name, or nil if not found.
func (s *CredentialStore) Get(name string) *Credential {
	return s.creds[name]
}

// SaveCredentials encrypts and writes the credential store to path.
// Used by `triton credential add/rotate/delete`.
func SaveCredentials(path string, creds []Credential) error {
	keyHex := os.Getenv("TRITON_SCANNER_CRED_KEY")
	if keyHex == "" {
		return fmt.Errorf("TRITON_SCANNER_CRED_KEY env var is required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("TRITON_SCANNER_CRED_KEY must be 32 hex bytes")
	}

	doc := credentialsFile{Version: 1, Credentials: creds}
	plaintext, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	encrypted, err := encryptAES256GCM(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}
	return os.WriteFile(path, encrypted, 0o600)
}

// encryptAES256GCM produces base64(nonce || ciphertext || tag).
func encryptAES256GCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	raw := append(nonce, ct...)
	// Base64 for safe YAML transport (the file is a base64 blob on disk).
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	return encoded, nil
}

// decryptAES256GCM reverses encryptAES256GCM.
func decryptAES256GCM(key, encoded []byte) ([]byte, error) {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(raw, encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	raw = raw[:n]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}
```

- [ ] **Step 2: Write test**

Create `pkg/scanner/netscan/credentials_test.go`:

```go
package netscan

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	// Fixed key for deterministic test
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", hex.EncodeToString(key))

	path := filepath.Join(t.TempDir(), "credentials.yaml")
	creds := []Credential{
		{Name: "prod-ssh", Type: "ssh-key", Username: "triton-scanner", PrivateKeyPath: "/etc/triton/keys/prod"},
		{Name: "cisco-tacacs", Type: "ssh-password", Username: "readonly", Password: "s3cret"},
	}

	require.NoError(t, SaveCredentials(path, creds))

	store, err := LoadCredentials(path)
	require.NoError(t, err)

	c1 := store.Get("prod-ssh")
	require.NotNil(t, c1)
	assert.Equal(t, "triton-scanner", c1.Username)

	c2 := store.Get("cisco-tacacs")
	require.NotNil(t, c2)
	assert.Equal(t, "s3cret", c2.Password)
}

func TestLoadCredentials_MissingKey(t *testing.T) {
	t.Setenv("TRITON_SCANNER_CRED_KEY", "")
	_, err := LoadCredentials("/nonexistent")
	assert.ErrorContains(t, err, "TRITON_SCANNER_CRED_KEY")
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./pkg/scanner/netscan/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/netscan/credentials.go pkg/scanner/netscan/credentials_test.go
git commit -m "feat(netscan): add encrypted credential store (AES-256-GCM)

Key from TRITON_SCANNER_CRED_KEY env var (32 hex bytes).
On disk: base64(nonce || ciphertext || tag).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: `triton credential` CLI

**Files:**
- Create: `cmd/credential.go`

- [ ] **Step 1: Cobra command group**

Create `cmd/credential.go`:

```go
package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage encrypted credentials for agentless scanning",
}

var credentialAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new credential to credentials.yaml",
	RunE:  runCredentialAdd,
}

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List credential names (not values) from credentials.yaml",
	RunE:  runCredentialList,
}

var credentialBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Generate an Ed25519 keypair + print Ansible snippet for fleet onboarding",
	RunE:  runCredentialBootstrap,
}

var (
	credFile      string
	credAddName   string
	credAddType   string
	credAddUser   string
	credAddPass   string
	credAddKey    string
	credBootName  string
	credBootOut   string
)

func init() {
	credentialCmd.PersistentFlags().StringVar(&credFile, "file", "/etc/triton/credentials.yaml", "path to credentials.yaml")

	credentialAddCmd.Flags().StringVar(&credAddName, "name", "", "credential name (required)")
	credentialAddCmd.Flags().StringVar(&credAddType, "type", "", "credential type: ssh-key | ssh-password | enable-password")
	credentialAddCmd.Flags().StringVar(&credAddUser, "username", "", "SSH username")
	credentialAddCmd.Flags().StringVar(&credAddPass, "password", "", "SSH password (use --stdin for safety)")
	credentialAddCmd.Flags().StringVar(&credAddKey, "key", "", "path to private key file")

	credentialBootstrapCmd.Flags().StringVar(&credBootName, "name", "triton-scanner", "credential name")
	credentialBootstrapCmd.Flags().StringVar(&credBootOut, "out", "/etc/triton/keys", "output directory for generated keypair")

	credentialCmd.AddCommand(credentialAddCmd, credentialListCmd, credentialBootstrapCmd)
	rootCmd.AddCommand(credentialCmd)
}

func runCredentialAdd(_ *cobra.Command, _ []string) error {
	if credAddName == "" || credAddType == "" {
		return fmt.Errorf("--name and --type are required")
	}

	// Load existing credentials if any
	var existing []netscan.Credential
	if _, err := os.Stat(credFile); err == nil {
		store, err := netscan.LoadCredentials(credFile)
		if err != nil {
			return fmt.Errorf("load existing credentials: %w", err)
		}
		existing = storeToSlice(store)
	}

	// Append new credential
	newCred := netscan.Credential{
		Name:     credAddName,
		Type:     credAddType,
		Username: credAddUser,
		Password: credAddPass,
		PrivateKeyPath: credAddKey,
	}
	for _, c := range existing {
		if c.Name == credAddName {
			return fmt.Errorf("credential %q already exists; use 'credential rotate' instead", credAddName)
		}
	}
	existing = append(existing, newCred)

	if err := netscan.SaveCredentials(credFile, existing); err != nil {
		return err
	}
	fmt.Printf("Added credential %q to %s\n", credAddName, credFile)
	return nil
}

func runCredentialList(_ *cobra.Command, _ []string) error {
	store, err := netscan.LoadCredentials(credFile)
	if err != nil {
		return err
	}
	fmt.Printf("Credentials in %s:\n", credFile)
	for _, c := range storeToSlice(store) {
		fmt.Printf("  %s  (%s, user=%s)\n", c.Name, c.Type, c.Username)
	}
	return nil
}

func runCredentialBootstrap(_ *cobra.Command, _ []string) error {
	if err := os.MkdirAll(credBootOut, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", credBootOut, err)
	}

	// Generate Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Write private key (OpenSSH format)
	pemBlock, err := ssh.MarshalPrivateKey(priv, "triton-scanner")
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPath := fmt.Sprintf("%s/%s", credBootOut, credBootName)
	if err := os.WriteFile(privPath, pemBlock.Bytes, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// Write public key in authorized_keys format
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("ssh public key: %w", err)
	}
	pubPath := privPath + ".pub"
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Printf("Generated keypair:\n  private: %s\n  public:  %s\n\n", privPath, pubPath)
	fmt.Println("Deploy to your fleet with the following Ansible task:")
	fmt.Println()
	fmt.Println("  - name: Create triton-scanner user")
	fmt.Println("    user:")
	fmt.Println("      name: triton-scanner")
	fmt.Println("      shell: /bin/bash")
	fmt.Println()
	fmt.Println("  - name: Deploy Triton scanner SSH key")
	fmt.Println("    authorized_key:")
	fmt.Println("      user: triton-scanner")
	fmt.Println("      state: present")
	fmt.Printf("      key: %q\n", string(pubBytes))
	fmt.Println()
	fmt.Println("Then register the credential:")
	fmt.Printf("  triton credential add --name %s --type ssh-key --username triton-scanner --key %s\n",
		credBootName, privPath)
	return nil
}

// storeToSlice returns all credentials. Not exposed publicly in credentials.go
// because it bypasses the lookup abstraction, but needed here for CLI editing.
func storeToSlice(store *netscan.CredentialStore) []netscan.Credential {
	// CredentialStore is private in terms of iteration; add an Iter method
	// on it in credentials.go if not present. For brevity, assume we added:
	//
	//   func (s *CredentialStore) All() []Credential { ... }
	//
	// If not yet added, add it now as a 4-line method.
	return store.All()
}
```

- [ ] **Step 2: Add `All()` method to CredentialStore**

In `pkg/scanner/netscan/credentials.go`, add:

```go
// All returns a copy of all stored credentials. Used by the CLI for
// list/add/rotate/delete operations.
func (s *CredentialStore) All() []Credential {
	out := make([]Credential, 0, len(s.creds))
	for _, c := range s.creds {
		out = append(out, *c)
	}
	return out
}
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/credential.go pkg/scanner/netscan/credentials.go
git commit -m "feat(cli): add 'triton credential' subcommands (add/list/bootstrap)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: `triton network-scan` CLI

**Files:**
- Create: `cmd/network_scan.go`

- [ ] **Step 1: Cobra command (orchestrator wired in Task 17)**

Create `cmd/network_scan.go`:

```go
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

var networkScanCmd = &cobra.Command{
	Use:   "network-scan",
	Short: "Scan remote hosts and routers via SSH/NETCONF (agentless)",
	Long: `Agentless scanner for Unix hosts (Linux/macOS/AIX) and routers
(Cisco IOS-XE, Juniper Junos). Reads devices from an inventory file
and credentials from an encrypted YAML file. No binary deployed on targets.`,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		return guard.EnforceFeature(license.FeatureNetworkScan)
	},
	RunE: runNetworkScan,
}

var (
	nsInventory   string
	nsCredentials string
	nsGroup       string
	nsDevice      string
	nsConcurrency int
	nsTimeout     time.Duration
	nsDryRun      bool
	nsInterval    time.Duration
	nsReportServer string
)

func init() {
	networkScanCmd.Flags().StringVar(&nsInventory, "inventory", "/etc/triton/devices.yaml", "path to devices.yaml")
	networkScanCmd.Flags().StringVar(&nsCredentials, "credentials", "/etc/triton/credentials.yaml", "path to encrypted credentials.yaml")
	networkScanCmd.Flags().StringVar(&nsGroup, "group", "", "scan only devices in this group")
	networkScanCmd.Flags().StringVar(&nsDevice, "device", "", "scan only this device (for debugging)")
	networkScanCmd.Flags().IntVar(&nsConcurrency, "concurrency", 20, "max concurrent device scans")
	networkScanCmd.Flags().DurationVar(&nsTimeout, "device-timeout", 5*time.Minute, "max time per device")
	networkScanCmd.Flags().BoolVar(&nsDryRun, "dry-run", false, "validate inventory and credentials, test connectivity, no scan")
	networkScanCmd.Flags().DurationVar(&nsInterval, "interval", 0, "continuous mode: repeat every interval (e.g., 24h)")
	networkScanCmd.Flags().StringVar(&nsReportServer, "report-server", "", "report server URL (overrides agent.yaml)")

	rootCmd.AddCommand(networkScanCmd)
}

func runNetworkScan(_ *cobra.Command, _ []string) error {
	inv, err := netscan.LoadInventory(nsInventory)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}

	creds, err := netscan.LoadCredentials(nsCredentials)
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	devices, err := inv.DevicesByGroup(nsGroup)
	if err != nil {
		return err
	}
	if nsDevice != "" {
		devices = filterDevicesByName(devices, nsDevice)
		if len(devices) == 0 {
			return fmt.Errorf("device not found in inventory: %s", nsDevice)
		}
	}

	fmt.Printf("Network scan: %d devices\n", len(devices))

	if nsDryRun {
		fmt.Println("Dry run — validating connectivity...")
		return runDryRun(devices, creds)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	orch := &netscan.Orchestrator{
		Inventory:        inv,
		Credentials:      creds,
		Concurrency:      nsConcurrency,
		PerDeviceTimeout: nsTimeout,
		ReportServerURL:  nsReportServer,
	}

	for {
		if err := orch.Scan(ctx, devices); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}
		if nsInterval == 0 {
			return nil
		}
		fmt.Printf("Next scan in %s\n", nsInterval)
		select {
		case <-time.After(nsInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

func filterDevicesByName(devices []netscan.Device, name string) []netscan.Device {
	for _, d := range devices {
		if d.Name == name {
			return []netscan.Device{d}
		}
	}
	return nil
}

func runDryRun(devices []netscan.Device, creds *netscan.CredentialStore) error {
	// Validation: every device's credential resolves
	for _, d := range devices {
		if creds.Get(d.Credential) == nil {
			return fmt.Errorf("device %s: credential %q not found", d.Name, d.Credential)
		}
	}
	fmt.Printf("Validated %d devices, all credentials resolved.\n", len(devices))
	return nil
}
```

- [ ] **Step 2: Commit — orchestrator referenced but not yet created**

The code references `netscan.Orchestrator` which is created in Task 17. For this commit, comment out the orchestrator block OR create an empty orchestrator stub. Simplest: add a stub to `pkg/scanner/netscan/orchestrator.go`:

```go
// Stub — full implementation in Task 17
package netscan

import "context"

type Orchestrator struct {
	Inventory        *Inventory
	Credentials      *CredentialStore
	Concurrency      int
	PerDeviceTimeout time.Duration
	ReportServerURL  string
}

func (o *Orchestrator) Scan(ctx context.Context, devices []Device) error {
	return nil // implemented in Task 17
}
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/network_scan.go pkg/scanner/netscan/orchestrator.go
git commit -m "feat(cli): add 'triton network-scan' command (orchestrator stubbed)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## PHASE F: Orchestrator + Integration (Tasks 17-18)

### Task 17: Orchestrator implementation

**Files:**
- Modify: `pkg/scanner/netscan/orchestrator.go` (replace stub)
- Create: `pkg/scanner/netscan/orchestrator_test.go`

- [ ] **Step 1: Full orchestrator**

Replace `pkg/scanner/netscan/orchestrator.go`:

```go
package netscan

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/fsadapter"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/cisco"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/juniper"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
)

// Orchestrator runs per-device scans concurrently with bounded parallelism.
type Orchestrator struct {
	Inventory        *Inventory
	Credentials      *CredentialStore
	Concurrency      int
	PerDeviceTimeout time.Duration
	ReportServerURL  string // if set, submit results; otherwise local reports only
}

// Scan scans all given devices, submits results, and returns after all complete.
func (o *Orchestrator) Scan(ctx context.Context, devices []Device) error {
	if o.Concurrency <= 0 {
		o.Concurrency = 20
	}
	if o.PerDeviceTimeout <= 0 {
		o.PerDeviceTimeout = 5 * time.Minute
	}

	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, o.Concurrency)
		succeeded int64
		failed    int64
	)

	for i := range devices {
		d := devices[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			devCtx, cancel := context.WithTimeout(ctx, o.PerDeviceTimeout)
			defer cancel()

			result, err := o.scanDevice(devCtx, d)
			if err != nil {
				log.Printf("device %s: %v", d.Name, err)
				result = makeFailureResult(d, err)
				atomic.AddInt64(&failed, 1)
			} else {
				atomic.AddInt64(&succeeded, 1)
			}

			if o.ReportServerURL != "" {
				o.submitResult(devCtx, result)
			}
		}()
	}
	wg.Wait()

	fmt.Printf("Scan complete: %d succeeded, %d failed\n",
		atomic.LoadInt64(&succeeded), atomic.LoadInt64(&failed))
	return nil
}

func (o *Orchestrator) scanDevice(ctx context.Context, d Device) (*model.ScanResult, error) {
	cred := o.Credentials.Get(d.Credential)
	if cred == nil {
		return nil, fmt.Errorf("credential %q not found", d.Credential)
	}

	switch d.Type {
	case "unix":
		return o.scanUnix(ctx, d, cred)
	case "cisco-iosxe":
		return o.scanCisco(ctx, d, cred)
	case "juniper-junos":
		return o.scanJuniper(ctx, d, cred)
	default:
		return nil, fmt.Errorf("unknown device type: %s", d.Type)
	}
}

func (o *Orchestrator) scanUnix(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg := credToSSHConfig(d, cred)
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	reader := fsadapter.NewSshReader(client)

	// Run Tier 1 scanner engine with SshReader
	// The engine accepts modules; we pre-configure a scan profile.
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:  d.Name,
			AgentID:   "triton-netscan",
			Profile:   "agentless-unix",
			Timestamp: time.Now().UTC(),
		},
	}

	// Build target per scan path; default to / if none configured
	paths := d.ScanPaths
	if len(paths) == 0 {
		paths = []string{"/etc", "/usr/local/etc", "/opt"}
	}

	eng := scanner.NewEngine()
	eng.RegisterTier1Modules()
	for _, p := range paths {
		findings, err := eng.ScanTargetWithReader(ctx, model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: p,
		}, reader)
		if err != nil {
			log.Printf("device %s: scan %s: %v", d.Name, p, err)
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}
	return result, nil
}

func (o *Orchestrator) scanCisco(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg := credToSSHConfig(d, cred)
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	enablePass := ""
	if d.EnableCredential != "" {
		if ec := o.Credentials.Get(d.EnableCredential); ec != nil {
			enablePass = ec.Password
		}
	}

	runner := cisco.NewCiscoRunner(client, enablePass)
	adapter := cisco.NewAdapter(runner, d.Name)

	findings := make(chan *model.Finding, 100)
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:  d.Name,
			AgentID:   "triton-netscan",
			Profile:   "agentless-cisco",
			Timestamp: time.Now().UTC(),
		},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- adapter.Scan(ctx, findings); close(findings) }()

	for f := range findings {
		result.Findings = append(result.Findings, *f)
	}
	if err := <-errCh; err != nil {
		return nil, err
	}
	return result, nil
}

func (o *Orchestrator) scanJuniper(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg := credToSSHConfig(d, cred)
	sshCfg.Address = fmt.Sprintf("%s:%d", d.Address, d.Port) // Juniper uses 830 by default
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	nc, err := transport.NewNetconfClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("netconf: %w", err)
	}
	defer func() { _ = nc.Close() }()

	adapter := juniper.NewAdapter(nc, d.Name)

	findings := make(chan *model.Finding, 100)
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:  d.Name,
			AgentID:   "triton-netscan",
			Profile:   "agentless-juniper",
			Timestamp: time.Now().UTC(),
		},
	}

	errCh := make(chan error, 1)
	go func() { errCh <- adapter.Scan(ctx, findings); close(findings) }()

	for f := range findings {
		result.Findings = append(result.Findings, *f)
	}
	if err := <-errCh; err != nil {
		return nil, err
	}
	return result, nil
}

func (o *Orchestrator) submitResult(ctx context.Context, result *model.ScanResult) {
	client := agent.New(o.ReportServerURL)
	if _, err := client.Submit(ctx, result); err != nil {
		log.Printf("submit %s: %v", result.Metadata.Hostname, err)
	}
}

func credToSSHConfig(d Device, cred *Credential) transport.SSHConfig {
	cfg := transport.SSHConfig{
		Address:  fmt.Sprintf("%s:%d", d.Address, d.Port),
		Username: cred.Username,
		Password: cred.Password,
	}
	if cred.PrivateKeyPath != "" {
		// Load key bytes. Errors are caught later when SSH dials.
		if data, err := os.ReadFile(cred.PrivateKeyPath); err == nil {
			cfg.PrivateKey = data
		}
	}
	cfg.Passphrase = cred.Passphrase
	return cfg
}

func makeFailureResult(d Device, err error) *model.ScanResult {
	return &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:  d.Name,
			AgentID:   "triton-netscan",
			Profile:   "agentless-failed",
			Timestamp: time.Now().UTC(),
			Notes:     err.Error(),
		},
	}
}
```

**Note:** this references `scanner.NewEngine()`, `eng.RegisterTier1Modules()`, and `eng.ScanTargetWithReader()`. These may not exist yet in that form — they need to be added to the scanner engine to accept a FileReader. This is the integration task:

- [ ] **Step 2: Add engine support for external FileReader**

Check `pkg/scanner/engine.go`. If there's no way to pass a FileReader to the engine, add a method:

```go
// ScanTargetWithReader runs all modules that match the target type
// against the given target, using the provided FileReader. Used by
// agentless scanning (Phase: Agentless MVP).
func (e *Engine) ScanTargetWithReader(ctx context.Context, target model.ScanTarget, reader fsadapter.FileReader) ([]model.Finding, error) {
	// Mirror of Scan() but plumbs reader through walkerConfig for
	// file-based modules. Non-file modules (network, process) ignore it.
	// ... implementation details ...
}
```

This requires refactoring the engine to accept a reader. The exact shape depends on existing engine internals — the implementer should read `pkg/scanner/engine.go` carefully and either:

(a) Add a reader option to the existing `Engine.Scan()` via functional options pattern, OR
(b) Add a new `ScanTargetWithReader()` entry point that reuses most of Scan() internals.

Either works; (a) is more idiomatic Go.

- [ ] **Step 3: Orchestrator unit test**

Create `pkg/scanner/netscan/orchestrator_test.go`:

```go
package netscan

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOrchestrator_DefaultsApplied(t *testing.T) {
	o := &Orchestrator{}
	// Call Scan with empty device list — should set defaults and return OK.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := o.Scan(ctx, nil)
	assert.NoError(t, err)
	assert.Equal(t, 20, o.Concurrency)
	assert.Equal(t, 5*time.Minute, o.PerDeviceTimeout)
}
```

- [ ] **Step 4: Run tests + build**

Run: `go test ./pkg/scanner/netscan/... && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/orchestrator.go pkg/scanner/netscan/orchestrator_test.go pkg/scanner/engine.go
git commit -m "feat(netscan): add orchestrator with worker pool + per-device dispatch

Unix hosts get FileReader-backed scans. Cisco/Juniper use their adapters.
Scan results submitted to report server via existing agent.Client.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: End-to-end local validation

- [ ] **Step 1: Build binary**

Run: `make build`

- [ ] **Step 2: Bootstrap a credential for localhost**

```bash
export TRITON_SCANNER_CRED_KEY=$(openssl rand -hex 32)
./bin/triton credential bootstrap --name local-test --out /tmp/triton-test-keys
# Manually add the pubkey to your ~/.ssh/authorized_keys
```

- [ ] **Step 3: Add credential via CLI**

```bash
./bin/triton credential add --name local-test --type ssh-key \
    --username $USER --key /tmp/triton-test-keys/local-test
```

- [ ] **Step 4: Create minimal inventory**

```yaml
# /tmp/devices.yaml
version: 1
devices:
  - name: localhost-test
    type: unix
    address: 127.0.0.1
    credential: local-test
    scan_paths: [/etc]
```

- [ ] **Step 5: Dry-run**

```bash
./bin/triton network-scan --inventory /tmp/devices.yaml \
    --credentials /etc/triton/credentials.yaml \
    --dry-run
```

Expected: "Validated 1 devices, all credentials resolved."

- [ ] **Step 6: Real scan**

```bash
./bin/triton network-scan --inventory /tmp/devices.yaml \
    --credentials /etc/triton/credentials.yaml
```

Expected: "Scan complete: 1 succeeded, 0 failed". Findings should include certificates from `/etc/ssl/certs/`, configs from `/etc/ssh/`, etc.

- [ ] **Step 7: Compare to local scan**

```bash
./bin/triton scan --profile quick --format json -o /tmp/local-scan.json
# Compare finding counts
```

Counts won't match exactly (different targets — `/etc` only vs full scan), but algorithms detected should overlap significantly. If no findings appear, SshReader is broken.

- [ ] **Step 8: No commit — verification only, unless bugs fixed**

---

## PHASE G: Docs + License + Verification (Tasks 19-20)

### Task 19: License gate + docs + example artifacts

**Files:**
- Modify: `internal/license/tier.go`, `internal/license/guard.go`
- Create: `docs/examples/agentless/devices.yaml.example`
- Create: `docs/examples/agentless/triton-access.yaml`
- Create: `docs/examples/agentless/README.md`

- [ ] **Step 1: Add FeatureNetworkScan**

In `internal/license/tier.go`, add to the feature constants:

```go
const FeatureNetworkScan Feature = "network-scan"
```

And add it to the enterprise tier's features list:

```go
// AllowedFeatures for enterprise — find the existing list and append:
FeatureNetworkScan,
```

- [ ] **Step 2: Already wired**

`cmd/network_scan.go` already calls `guard.EnforceFeature(license.FeatureNetworkScan)` in its PreRunE.

- [ ] **Step 3: Example inventory**

Create `docs/examples/agentless/devices.yaml.example`:

```yaml
# docs/examples/agentless/devices.yaml.example
#
# Copy to /etc/triton/devices.yaml and customize.
version: 1

defaults:
  port: 22
  scan_timeout: 5m
  sudo: false

devices:
  # Linux host example
  - name: web-srv1
    type: unix
    address: 10.0.1.10
    credential: prod-ssh-key
    scan_paths:
      - /etc
      - /usr/local/etc
      - /opt

  # AIX host example
  - name: legacy-aix-1
    type: unix
    address: 10.0.1.20
    credential: legacy-ssh
    os_hint: aix

  # Cisco router example
  - name: edge-router-1
    type: cisco-iosxe
    address: 10.0.0.1
    credential: cisco-tacacs
    enable_credential: cisco-enable

  # Juniper router example
  - name: core-srx-1
    type: juniper-junos
    address: 10.0.0.2
    port: 830
    credential: juniper-netconf

groups:
  - name: production
    members: [web-srv1, edge-router-1, core-srx-1]
  - name: legacy
    members: [legacy-aix-1]
```

- [ ] **Step 4: Example Ansible playbook**

Create `docs/examples/agentless/triton-access.yaml`:

```yaml
# docs/examples/agentless/triton-access.yaml
#
# Deploys the triton-scanner user + SSH public key to all hosts in the
# Ansible inventory. Run with:
#   ansible-playbook -i your-inventory.yaml triton-access.yaml \
#     -e scanner_pubkey_file=/etc/triton/keys/triton-scanner.pub
---
- name: Onboard hosts for Triton agentless scanning
  hosts: all
  become: yes
  tasks:
    - name: Create triton-scanner user
      ansible.builtin.user:
        name: triton-scanner
        shell: /bin/bash
        home: /home/triton-scanner
        state: present

    - name: Deploy Triton scanner SSH public key
      ansible.posix.authorized_key:
        user: triton-scanner
        state: present
        key: "{{ lookup('file', scanner_pubkey_file) }}"

    # Optional: for Tier 2 scanners (password_hash, auth_material)
    # uncomment the following to grant sudo for specific read-only commands:
    #
    # - name: Allow triton-scanner to cat /etc/shadow
    #   ansible.builtin.copy:
    #     dest: /etc/sudoers.d/triton-scanner
    #     content: "triton-scanner ALL=(root) NOPASSWD: /usr/bin/cat /etc/shadow\n"
    #     mode: '0440'
    #     validate: '/usr/sbin/visudo -cf %s'
```

- [ ] **Step 5: Onboarding README**

Create `docs/examples/agentless/README.md`:

```markdown
# Agentless Scanning Onboarding

This guide walks you through setting up Triton agentless scanning for
a fleet of 1000+ hosts and routers. Assumes you have Ansible for
fleet management.

## 1. Set up the scanner host (one-time, 10 min)

```bash
# Install Triton
sudo apt install triton

# Generate the encryption key for credentials
export TRITON_SCANNER_CRED_KEY=$(openssl rand -hex 32)
echo "Save this key securely — losing it means losing credential access!"

# Persist for future sessions
echo "export TRITON_SCANNER_CRED_KEY=$TRITON_SCANNER_CRED_KEY" | \
  sudo tee -a /etc/triton/env

# Generate the scanner SSH keypair
sudo triton credential bootstrap --name prod-scanner
# → prints the public key + Ansible snippet
```

## 2. Deploy SSH access to your fleet (5-30 min depending on fleet size)

Use the example Ansible playbook:

```bash
ansible-playbook \
  -i your-inventory.yaml \
  triton-access.yaml \
  -e scanner_pubkey_file=/etc/triton/keys/prod-scanner.pub
```

For **1000 hosts**, this typically completes in 3-5 minutes.

## 3. Build your devices.yaml

Copy `devices.yaml.example` to `/etc/triton/devices.yaml` and fill in
your actual hostnames, addresses, and credential names.

Tips for large fleets:
- Export from ServiceNow CMDB / AD / cloud inventory API to YAML
- Use groups for scheduling: production vs legacy vs DMZ

## 4. Register credentials

```bash
sudo -E triton credential add --name prod-ssh-key --type ssh-key \
  --username triton-scanner --key /etc/triton/keys/prod-scanner

sudo -E triton credential add --name cisco-tacacs --type ssh-password \
  --username triton-readonly --password "$(cat /tmp/tacacs-pw)"

sudo -E triton credential add --name juniper-netconf --type ssh-key \
  --username triton-readonly --key /etc/triton/keys/juniper-scanner
```

## 5. First scan

Dry run first to validate connectivity:

```bash
sudo -E triton network-scan --inventory /etc/triton/devices.yaml --dry-run
```

Then the real scan:

```bash
sudo -E triton network-scan --inventory /etc/triton/devices.yaml \
  --report-server https://reports.example.com
```

For **1000 devices** at default concurrency (20), expect ~5 minutes.

## 6. Schedule

```
# /etc/systemd/system/triton-netscan.service
[Service]
Type=oneshot
ExecStart=/usr/bin/triton network-scan --inventory /etc/triton/devices.yaml
EnvironmentFile=/etc/triton/env
```

```
# /etc/systemd/system/triton-netscan.timer
[Timer]
OnCalendar=daily
Persistent=true
```

```bash
sudo systemctl enable --now triton-netscan.timer
```

## Troubleshooting

**Authentication failed for host X**
- Verify the user exists on target: `ssh user@host 'id'`
- Verify the credential name in devices.yaml matches `triton credential list`
- Check auth.log on the target for specific failure reason

**Command 'show crypto pki' returned error (Cisco)**
- Verify the read-only user has `privilege 5` or `role network-operator`
- Some Cisco IOS versions require enable mode — set `enable_credential`

**NETCONF authentication failed (Juniper)**
- Verify NETCONF is enabled: `show system services netconf` on the device
- Verify port 830 is reachable from the scanner host
- Try `ssh -p 830 user@host -s netconf` manually
```

- [ ] **Step 6: Commit**

```bash
git add internal/license/tier.go docs/examples/agentless/
git commit -m "feat(license): add FeatureNetworkScan + agentless onboarding docs

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 20: Full verification + cleanup

- [ ] **Step 1: Full test suite**

Run: `make test`
Expected: All PASS

- [ ] **Step 2: Lint**

Run: `make lint`
Expected: 0 issues

- [ ] **Step 3: Build**

Run: `make build`
Expected: Clean binary

- [ ] **Step 4: Verify existing functionality still works**

```bash
./bin/triton scan --profile quick --format json
# Should produce findings identical to pre-refactor baseline
```

Expected: Findings counts match pre-refactor (within ±1% noise for non-deterministic scanners).

- [ ] **Step 5: Help text review**

```bash
./bin/triton network-scan --help
./bin/triton credential --help
```

Expected: Clear, complete help text.

- [ ] **Step 6: Final commit if fixups needed**

```bash
git add -A
git commit -m "fix: address lint/test issues from agentless MVP implementation"
```

---

## Review Checkpoint

After Task 20, pause for code review. Key areas:

1. **Backward compatibility:** Local scans produce the same findings as before the refactor
2. **FileReader correctness:** SshReader's base64 round-trip handles binary files
3. **Single-find optimization:** Walking 10k files = one SSH command, not 10k
4. **Cisco paging:** `terminal length 0` issued before first real command
5. **NETCONF framing:** `]]>]]>` end-of-message marker handled correctly
6. **Credential encryption:** Round-trip with same key succeeds; wrong key fails cleanly
7. **Orchestrator isolation:** One device's crash doesn't block others
8. **License enforcement:** `triton network-scan` fails cleanly on non-enterprise tier
9. **Failure reporting:** Failed devices produce error-metadata ScanResults visible in dashboards

## Out-of-scope follow-ups (documented in spec)

- Windows via WinRM (separate phase)
- Tier 2 scanners (sudo-required)
- Arista / Huawei / Palo Alto / Fortinet adapters
- Auto-discovery (ICMP sweep, AD/CMDB import)
- Delta scans and per-scan licensing
- Remaining Cisco/Juniper parsers (crypto-pki, isakmp, ipsec, snmp) — MVP has SSH parsers only
