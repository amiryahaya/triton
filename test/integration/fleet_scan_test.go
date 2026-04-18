//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// testCredKey is a deterministic 32-byte (hex-encoded, 64 chars) key used
// only for encrypting the ephemeral test credentials.yaml fixture. It is
// NOT a secret — the credentials file it protects references only the
// disposable testdata/fleet/test_ed25519 keypair checked into the tree.
const testCredKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// licenseFixture holds a single per-process keypair + Pro token used to
// bypass the FeatureFleetScan licence gate. Generated once and shared
// across all fleet-scan integration tests, since embedding the public
// key requires a go build + ldflags pass (~15s) and re-using it keeps
// the test suite fast.
type licenseFixture struct {
	binPath string // path to a triton binary built with the test pubkey embedded
	token   string // machine-bound Pro-tier token signed by the matching priv key
}

var (
	licenseOnce    sync.Once
	sharedFixture  *licenseFixture
	licenseInitErr error
)

// getLicenseFixture lazily builds a triton binary with a test ed25519
// public key embedded via ldflags and issues a matching Pro token for
// FeatureFleetScan. Returns the same fixture for every caller to keep
// the total build cost to ~15s per `go test` invocation.
func getLicenseFixture(t *testing.T) *licenseFixture {
	t.Helper()
	licenseOnce.Do(func() {
		pub, priv, err := license.GenerateKeypair()
		if err != nil {
			licenseInitErr = fmt.Errorf("generate keypair: %w", err)
			return
		}
		pubHex := hex.EncodeToString(pub)
		// Issue an UNBOUND token (bind=false): the same token must validate
		// on both the CI runner (where fleet-scan parent runs) and the
		// Docker sshd container (where the remote triton runs). A bound
		// token would fail machine-fingerprint check on the container and
		// degrade to free tier, rejecting --format all.
		token, err := license.IssueTokenWithOptions(priv, license.TierPro, "fleet-test-org", 10, 365, false)
		if err != nil {
			licenseInitErr = fmt.Errorf("issue token: %w", err)
			return
		}

		// Persist the binary in a temp dir that survives the whole test
		// process; using t.TempDir() would remove it between subtests.
		tmp, err := os.MkdirTemp("", "triton-fleet-test-*")
		if err != nil {
			licenseInitErr = fmt.Errorf("mkdtemp: %w", err)
			return
		}
		bin := filepath.Join(tmp, "triton-test")
		ldflags := fmt.Sprintf("-X github.com/amiryahaya/triton/internal/license.publicKeyHex=%s", pubHex)
		cmd := exec.Command("go", "build", "-ldflags", ldflags,
			"-o", bin, "github.com/amiryahaya/triton")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			licenseInitErr = fmt.Errorf("go build triton with test pubkey: %w", err)
			return
		}
		sharedFixture = &licenseFixture{binPath: bin, token: token}
	})
	if licenseInitErr != nil {
		t.Fatalf("license fixture: %v", licenseInitErr)
	}
	return sharedFixture
}

// dockerAvailable reports whether the docker CLI is installed and the
// daemon is reachable. Tests that require docker should call this first
// and t.Skip() when false so they remain compilable on CI runners that
// lack docker.
func dockerAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	cmd := exec.Command("docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// buildAndStartSSHDContainer builds the named dockerfile, launches a
// detached container mapping the container's port 22 to hostPort, and
// waits up to 30s for sshd to accept TCP connections. Returns a cleanup
// func that removes the container.
func buildAndStartSSHDContainer(t *testing.T, dockerfile, name string, hostPort int) func() {
	t.Helper()
	// Build the image. Context is the current working directory
	// (test/integration when `go test` runs) so the COPY of
	// testdata/fleet/test_ed25519.pub resolves.
	buildCmd := exec.Command("docker", "build",
		"-f", dockerfile,
		"-t", name+":test",
		".")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("docker build %s: %v", dockerfile, err)
	}
	// Run detached.
	runCmd := exec.Command("docker", "run", "--rm", "-d",
		"--name", name,
		"-p", fmt.Sprintf("%d:22", hostPort),
		name+":test")
	if out, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v (%s)", name, err, out)
	}
	// Wait for sshd to bind.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hostPort), time.Second)
		if err == nil {
			_ = conn.Close()
			return func() { _ = exec.Command("docker", "rm", "-f", name).Run() }
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
	t.Fatalf("sshd %s not listening on 127.0.0.1:%d within 30s", name, hostPort)
	return nil
}

// writeTestInventory emits a minimal single-host devices.yaml at
// dir/devices.yaml pointing at 127.0.0.1:hostPort with
// credential "test-ssh" and sudo enabled.
func writeTestInventory(t *testing.T, dir string, hostPort int) string {
	t.Helper()
	path := filepath.Join(dir, "devices.yaml")
	content := fmt.Sprintf(`version: 1
defaults:
  port: 22
  sudo: true
devices:
  - name: testhost
    type: unix
    address: 127.0.0.1
    port: %d
    credential: test-ssh
    sudo: true
`, hostPort)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return path
}

// writeTestCredentials writes an encrypted credentials.yaml at
// dir/credentials.yaml pointing PrivateKeyPath at the testdata ed25519
// key. Caller MUST have set TRITON_SCANNER_CRED_KEY=testCredKey before
// invoking, because SaveCredentials reads it via loadKey().
func writeTestCredentials(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "credentials.yaml")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	keyPath := filepath.Join(wd, "testdata", "fleet", "test_ed25519")
	creds := []netscan.Credential{
		{
			Name:           "test-ssh",
			Type:           "ssh-key",
			Username:       "triton-test",
			PrivateKeyPath: keyPath,
		},
	}
	if err := netscan.SaveCredentials(path, creds); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}
	return path
}

// fleetScanEnv returns the environment slice to hand to each triton
// fleet-scan subprocess: inherits os.Environ plus TRITON_SCANNER_CRED_KEY
// and TRITON_LICENSE_KEY (the Pro-tier token from the shared fixture).
func fleetScanEnv(f *licenseFixture) []string {
	return append(os.Environ(),
		"TRITON_SCANNER_CRED_KEY="+testCredKey,
		"TRITON_LICENSE_KEY="+f.token,
	)
}

// TestFleetScan_EndToEnd_SingleHost drives fleet-scan against a single
// dockerized sshd, exercising the full pipeline: binary push → detach →
// poll → collect → tar. We assert summary.json shows one success and the
// host tarball lands in latest/hosts/.
func TestFleetScan_EndToEnd_SingleHost(t *testing.T) {
	if !dockerAvailable(t) {
		t.Skip("docker not available")
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", testCredKey)
	fx := getLicenseFixture(t)

	cleanup := buildAndStartSSHDContainer(t, "Dockerfile.sshd", "triton-fleet-sshd", 2222)
	defer cleanup()

	outDir := t.TempDir()
	fixDir := t.TempDir()
	inv := writeTestInventory(t, fixDir, 2222)
	creds := writeTestCredentials(t, fixDir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, fx.binPath, "fleet-scan",
		"--inventory", inv,
		"--credentials", creds,
		"--output-dir", outDir,
		"--profile", "quick",
		"--device-timeout", "3m",
		"--insecure-host-key",
		"--binary", fx.binPath,
	)
	cmd.Env = fleetScanEnv(fx)
	out, err := cmd.CombinedOutput()
	t.Logf("fleet-scan output:\n%s", out)
	if err != nil {
		// Exit 2 (some hosts failed) is acceptable only if summary.json
		// still shows >=1 success. Exit 3 (max-failures) / other errors
		// are caught by the count assertion below.
		t.Logf("fleet-scan exit: %v", err)
	}

	latest, err := filepath.EvalSymlinks(filepath.Join(outDir, "latest"))
	if err != nil {
		t.Fatalf("latest symlink: %v", err)
	}
	sumBytes, err := os.ReadFile(filepath.Join(latest, "summary.json"))
	if err != nil {
		t.Fatalf("read summary.json: %v", err)
	}
	var sum map[string]interface{}
	if err := json.Unmarshal(sumBytes, &sum); err != nil {
		t.Fatalf("unmarshal summary.json: %v", err)
	}
	counts, ok := sum["counts"].(map[string]interface{})
	if !ok {
		t.Fatalf("summary.json counts missing or wrong type: %v", sum["counts"])
	}
	if succ, _ := counts["succeeded"].(float64); succ < 1 {
		t.Errorf("expected at least 1 succeeded, got counts=%v", counts)
	}
	tarPath := filepath.Join(latest, "hosts", "testhost.tar.gz")
	if _, err := os.Stat(tarPath); err != nil {
		t.Errorf("testhost.tar.gz not found: %v", err)
	}
}

// TestFleetScan_DryRun validates that --dry-run exercises preflight
// (SSH connect + sudo check) without producing any tarballs.
func TestFleetScan_DryRun(t *testing.T) {
	if !dockerAvailable(t) {
		t.Skip("docker not available")
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", testCredKey)
	fx := getLicenseFixture(t)

	cleanup := buildAndStartSSHDContainer(t, "Dockerfile.sshd", "triton-fleet-sshd-dryrun", 2223)
	defer cleanup()

	outDir := t.TempDir()
	fixDir := t.TempDir()
	inv := writeTestInventory(t, fixDir, 2223)
	creds := writeTestCredentials(t, fixDir)

	cmd := exec.Command(fx.binPath, "fleet-scan",
		"--inventory", inv,
		"--credentials", creds,
		"--output-dir", outDir,
		"--dry-run",
		"--insecure-host-key",
		"--binary", fx.binPath,
	)
	cmd.Env = fleetScanEnv(fx)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dry-run: %v (%s)", err, out)
	}
	// Dry-run must not produce any per-host tarballs.
	matches, _ := filepath.Glob(filepath.Join(outDir, "*", "hosts", "*.tar.gz"))
	if len(matches) > 0 {
		t.Errorf("dry-run produced tars: %v", matches)
	}
}

// TestFleetScan_SudoFailure points fleet-scan at a sshd container whose
// triton-test user has no NOPASSWD sudo entry. The scan should abort in
// the "sudo check" phase and surface that phase label in output.
func TestFleetScan_SudoFailure(t *testing.T) {
	if !dockerAvailable(t) {
		t.Skip("docker not available")
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", testCredKey)
	fx := getLicenseFixture(t)

	cleanup := buildAndStartSSHDContainer(t, "Dockerfile.sshd-nosudo", "triton-fleet-nosudo", 2224)
	defer cleanup()

	outDir := t.TempDir()
	fixDir := t.TempDir()
	inv := writeTestInventory(t, fixDir, 2224)
	creds := writeTestCredentials(t, fixDir)

	cmd := exec.Command(fx.binPath, "fleet-scan",
		"--inventory", inv,
		"--credentials", creds,
		"--output-dir", outDir,
		"--profile", "quick",
		"--device-timeout", "30s",
		"--insecure-host-key",
		"--binary", fx.binPath,
	)
	cmd.Env = fleetScanEnv(fx)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("fleet-scan against nosudo host should exit non-zero")
	}
	if !strings.Contains(string(out), "sudo check") {
		t.Errorf("error output should mention 'sudo check', got: %s", out)
	}
}

// TestFleetScan_MaxFailures verifies the circuit breaker: with three
// unreachable hosts and --max-failures=2, the process must exit with
// code 3. This test does not require docker because every host is
// deliberately unreachable via TCP to RFC 5737 test addresses.
func TestFleetScan_MaxFailures(t *testing.T) {
	t.Setenv("TRITON_SCANNER_CRED_KEY", testCredKey)
	fx := getLicenseFixture(t)

	outDir := t.TempDir()
	fixDir := t.TempDir()

	invPath := filepath.Join(fixDir, "devices.yaml")
	if err := os.WriteFile(invPath, []byte(`version: 1
defaults: {port: 22}
devices:
  - {name: unreachable-1, type: unix, address: 10.255.255.1, credential: test-ssh}
  - {name: unreachable-2, type: unix, address: 10.255.255.2, credential: test-ssh}
  - {name: unreachable-3, type: unix, address: 10.255.255.3, credential: test-ssh}
`), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	creds := writeTestCredentials(t, fixDir)

	cmd := exec.Command(fx.binPath, "fleet-scan",
		"--inventory", invPath,
		"--credentials", creds,
		"--output-dir", outDir,
		"--max-failures", "2",
		"--device-timeout", "10s",
		"--insecure-host-key",
		"--binary", fx.binPath,
	)
	cmd.Env = fleetScanEnv(fx)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() != 3 {
			t.Errorf("exit code: got %d, want 3 (max-failures)", exitErr.ExitCode())
		}
	} else {
		t.Errorf("expected *exec.ExitError with code 3, got: %v", err)
	}
}
