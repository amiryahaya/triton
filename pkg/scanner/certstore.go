package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// CertStoreModule scans the operating system's certificate store for
// installed certificates and their cryptographic properties. On
// Linux and macOS it reads the system CA bundle / keychain; on
// Windows it shells out to PowerShell to enumerate the LocalMachine
// Root store. It also hunts for Java's bundled `cacerts` keystore
// on every platform that has a JDK installed.
//
// The module uses an injectable cmdRunner so tests can feed canned
// output for both the PowerShell and keytool code paths. Real
// deployments get `defaultCmdRunner`.
//
// Memory safety (H2 review): PowerShell and keytool subprocesses
// are invoked via `cmdRunnerLimited` with a hard byte cap on
// stdout. A hostile or malformed keystore with hundreds of
// thousands of entries could otherwise produce gigabytes of PEM
// output; the agent must not OOM on adversarial input.
type CertStoreModule struct {
	config           *config.Config
	cmdRunner        cmdRunnerFunc
	cmdRunnerLimited cmdRunnerLimitedFunc
}

// cmdRunnerLimitedFunc runs a subprocess and caps its stdout at
// `limit` bytes, returning whatever fit in the cap on overflow.
// Injectable for testing alongside cmdRunnerFunc.
type cmdRunnerLimitedFunc func(ctx context.Context, limit int64, name string, args ...string) ([]byte, error)

// defaultCmdRunnerLimited is the production implementation: it
// pipes stdout through an io.LimitReader so the agent's memory
// use is bounded regardless of what the subprocess emits.
func defaultCmdRunnerLimited(ctx context.Context, limit int64, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Read up to `limit` bytes, then drain any excess in a
	// bounded sink so the subprocess doesn't block forever on a
	// full pipe buffer while we wait for it to exit.
	out, readErr := io.ReadAll(io.LimitReader(stdout, limit))
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if readErr != nil {
		return out, readErr
	}
	return out, waitErr
}

// NewCertStoreModule constructs a CertStoreModule wired to real
// subprocess execution.
func NewCertStoreModule(cfg *config.Config) *CertStoreModule {
	return &CertStoreModule{
		config:           cfg,
		cmdRunner:        defaultCmdRunner,
		cmdRunnerLimited: defaultCmdRunnerLimited,
	}
}

// Per-subprocess stdout byte caps. Chosen so that realistic
// enterprise keystores (a few thousand entries) fit comfortably
// while hostile inputs are truncated before they balloon the
// agent's heap.
const (
	// 32 MB ≈ 10k PEM certs (~3 KB each). A JDK cacerts ships
	// with 150; an operator-managed keystore with a few thousand
	// internal CAs fits. Adversarial keystores with 100k entries
	// are truncated.
	javaCacertsStdoutCap = 32 * 1024 * 1024
	// 16 MB is enough for the LocalMachine\Root store (~200 CAs
	// on a typical Windows install, ~5 KB per base64 DER line).
	windowsRootStoreStdoutCap = 16 * 1024 * 1024
)

// Per-subprocess wall-clock deadlines. Subprocess calls
// (`keytool`, PowerShell) should be near-instant on healthy
// systems. A generous 30-second cap protects the agent from
// a hung subprocess (e.g., keytool prompting on stdin when
// the default password is wrong, or a misconfigured PowerShell
// module waiting for user confirmation) without aborting
// legitimate slow operations.
const certstoreSubprocessTimeout = 30 * time.Second

func (m *CertStoreModule) Name() string                         { return "certstore" }
func (m *CertStoreModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *CertStoreModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// Scan reads the OS certificate store, plus any Java cacerts
// keystores we can discover, and emits findings for each cert.
//
// Errors from individual code paths (missing PowerShell, missing
// keytool, unreadable bundle) are swallowed so a partial scan
// still produces useful findings rather than aborting entirely.
func (m *CertStoreModule) Scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	// OS native store.
	switch runtime.GOOS {
	case "darwin":
		if pemData, err := m.readMacOSCerts(ctx); err == nil {
			_ = m.parsePEMCerts(ctx, pemData, "os:certstore:darwin", "System trust anchor (macOS keychain)", findings)
		}
	case "linux":
		if pemData, err := m.readLinuxCerts(); err == nil {
			_ = m.parsePEMCerts(ctx, pemData, "os:certstore:linux", "System trust anchor (CA bundle)", findings)
		}
	case "windows":
		_ = m.scanWindowsCertStore(ctx, findings)
	}

	// Java cacerts — cross-platform. Every discovered keystore is
	// parsed independently so one unreadable keystore doesn't hide
	// findings from the others.
	for _, path := range discoverJavaCacerts() {
		_ = m.scanJavaCacerts(ctx, path, findings)
	}

	return nil
}

// readMacOSCerts reads certificates from the macOS system root
// keychain via the `security` CLI. Returns PEM output.
func (m *CertStoreModule) readMacOSCerts(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p",
		"/System/Library/Keychains/SystemRootCertificates.keychain")
	return cmd.Output()
}

// readLinuxCerts reads the system CA certificate bundle from any
// of the well-known paths shipped by the major distributions.
func (m *CertStoreModule) readLinuxCerts() ([]byte, error) {
	paths := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("no CA bundle found")
}

// scanWindowsCertStore enumerates the Windows LocalMachine Root
// store via PowerShell. We ask for each cert's raw DER as base64
// on its own line; each line is then wrapped into a PEM block and
// fed through the existing parser. Requires PowerShell on PATH —
// which every Windows install since 2009 has.
func (m *CertStoreModule) scanWindowsCertStore(ctx context.Context, findings chan<- *model.Finding) error {
	// The command enumerates the LocalMachine\Root store and emits
	// one base64 DER per line. Using -NoProfile keeps startup fast
	// (no $PROFILE load) and avoids any user-tuned PowerShell env.
	//
	// Stdout is capped at windowsRootStoreStdoutCap via the
	// limited runner so a hostile or misconfigured cert store
	// cannot balloon the agent's heap (H2 review). Wall-clock
	// capped at certstoreSubprocessTimeout so a wedged PowerShell
	// session cannot stall the whole scan.
	subCtx, cancel := context.WithTimeout(ctx, certstoreSubprocessTimeout)
	defer cancel()
	const script = `Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object { [Convert]::ToBase64String($_.RawData) }`
	out, err := m.cmdRunnerLimited(subCtx, windowsRootStoreStdoutCap,
		"powershell", "-NoProfile", "-Command", script)
	if err != nil {
		// PowerShell missing or the store inaccessible — emit zero
		// findings rather than failing the whole scan. This is the
		// same tolerance the Linux/macOS paths use.
		return nil
	}
	return m.parseBase64DERList(ctx, out, "os:certstore:windows", "System trust anchor (Windows Root store)", findings)
}

// parseBase64DERList consumes a newline-delimited list of base64-
// encoded DER certificates and emits one finding per cert. Blank
// lines and undecodable/unparseable entries are silently skipped
// so a single corrupt line doesn't poison the rest of the scan.
func (m *CertStoreModule) parseBase64DERList(ctx context.Context, data []byte, sourcePath, purpose string, findings chan<- *model.Finding) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // DER certs can be large
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if err := m.emitCertFinding(ctx, cert, sourcePath, "OS certificate store", purpose, findings); err != nil {
			return err
		}
	}
	return nil
}

// maxCacertsKeystores caps the number of Java cacerts keystores
// the discovery pass will return. Enterprise hosts rarely have
// more than one or two JDK installs; CI runners can have 3-5
// (multiple OpenJDK versions side-by-side). A cap prevents
// per-subprocess timeouts from compounding into a multi-minute
// total wall-clock cost.
const maxCacertsKeystores = 4

// discoverJavaCacerts walks the well-known JDK install locations
// on every platform and returns the absolute paths of any cacerts
// files that exist. Returns nil when no JDK is installed, which
// makes Scan a zero-cost no-op on JDK-less hosts.
//
// Capped at maxCacertsKeystores results so a host with many
// JDKs side-by-side doesn't balloon the scan time.
func discoverJavaCacerts() []string {
	var found []string

	// Environment variable pointer wins — operators sometimes
	// install JDKs in non-standard locations and use JAVA_HOME
	// (or JDK_HOME) to wire their builds.
	for _, env := range []string{"JAVA_HOME", "JDK_HOME"} {
		if home := os.Getenv(env); home != "" {
			candidate := filepath.Join(home, "lib", "security", "cacerts")
			if _, err := os.Stat(candidate); err == nil {
				found = append(found, candidate)
			}
		}
	}

	// Per-OS well-known install roots.
	var roots []string
	switch runtime.GOOS {
	case "darwin":
		// Homebrew casks, Oracle installers, and OS-managed JDKs.
		roots = []string{
			"/Library/Java/JavaVirtualMachines",
			"/opt/homebrew/opt",
			"/usr/local/opt",
		}
	case "linux":
		roots = []string{
			"/usr/lib/jvm",
			"/usr/java",
			"/opt",
		}
	case "windows":
		roots = []string{
			`C:\Program Files\Java`,
			`C:\Program Files (x86)\Java`,
			`C:\Program Files\Eclipse Adoptium`,
			`C:\Program Files\Zulu`,
		}
	}

	// Shallow scan under each root: one directory level deep plus
	// lib/security/cacerts. Keeps the discovery cheap on deep
	// trees while catching every canonical layout.
	for _, root := range roots {
		if len(found) >= maxCacertsKeystores {
			break
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if len(found) >= maxCacertsKeystores {
				break
			}
			if !entry.IsDir() {
				continue
			}
			// Plain "<root>/<jdk>/lib/security/cacerts"
			candidate := filepath.Join(root, entry.Name(), "lib", "security", "cacerts")
			if _, err := os.Stat(candidate); err == nil {
				found = append(found, candidate)
				continue
			}
			// macOS nested layout: "<jvm>/Contents/Home/lib/security/cacerts"
			nested := filepath.Join(root, entry.Name(), "Contents", "Home", "lib", "security", "cacerts")
			if _, err := os.Stat(nested); err == nil {
				found = append(found, nested)
			}
		}
	}

	return found
}

// scanJavaCacerts shells out to `keytool -list -rfc` which dumps
// every trusted cert in the keystore as PEM. The output also
// contains header noise (keystore type, alias names, etc.) which
// parsePEMCerts safely ignores because it only looks for
// CERTIFICATE blocks.
//
// Sprint review B2: the `changeit` password appears on the
// command line and is therefore visible in `/proc/<pid>/cmdline`
// for the lifetime of the subprocess. That is ACCEPTABLE here
// because:
//
//  1. `changeit` is the publicly documented Oracle default
//     password for every JDK's cacerts since 1996 — it is not a
//     secret and leaks no information about operator-set values.
//  2. If the operator has changed the password, keytool exits
//     non-zero, we treat it as a soft skip, and no keystore
//     data is exposed.
//  3. The alternative (`-storepass:env VAR`) would require
//     setting an env var on the subprocess, which cmdRunnerFunc
//     doesn't support today. Refactoring cmdRunnerFunc to take
//     an env slice is a future enhancement.
func (m *CertStoreModule) scanJavaCacerts(ctx context.Context, path string, findings chan<- *model.Finding) error {
	// keytool is in $JAVA_HOME/bin and usually on PATH when a JDK
	// is installed. Stdout is capped at javaCacertsStdoutCap via
	// the limited runner so a keystore with tens of thousands of
	// entries cannot OOM the agent (H2 review). Wall-clock capped
	// at certstoreSubprocessTimeout so a keytool that wedges
	// (e.g., waiting on interactive stdin because the default
	// password was changed) cannot stall the whole scan — CI
	// was hitting the 10-minute package timeout before this
	// deadline was added.
	subCtx, cancel := context.WithTimeout(ctx, certstoreSubprocessTimeout)
	defer cancel()
	out, err := m.cmdRunnerLimited(subCtx, javaCacertsStdoutCap, "keytool",
		"-list", "-rfc",
		"-keystore", path,
		"-storepass", "changeit",
	)
	if err != nil {
		return nil // missing keytool or wrong password — skip silently
	}
	return m.parsePEMCerts(ctx, out, path, "Java cacerts keystore", findings)
}

// parsePEMCerts decodes PEM data and emits findings for each
// certificate. sourcePath goes into Finding.Source.Path so the
// report shows where the cert came from (file path, "os:certstore:
// linux", etc.). function is the CryptoAsset.Function label —
// "OS certificate store" for native stores, "Java cacerts
// keystore" for JDK trust anchors.
func (m *CertStoreModule) parsePEMCerts(ctx context.Context, pemData []byte, sourcePath, function string, findings chan<- *model.Finding) error {
	rest := pemData
	for len(rest) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if err := m.emitCertFinding(ctx, cert, sourcePath, function, "System trust anchor", findings); err != nil {
			return err
		}
	}
	return nil
}

// emitCertFinding constructs a CryptoAsset + Finding from a parsed
// certificate and sends it on the findings channel. Centralized so
// every code path (Linux bundle, macOS keychain, Windows Root store,
// Java cacerts) emits identically-shaped findings.
func (m *CertStoreModule) emitCertFinding(
	ctx context.Context,
	cert *x509.Certificate,
	sourcePath, function, purpose string,
	findings chan<- *model.Finding,
) error {
	algoName, keySize := certKeyInfo(cert)
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     function,
		Algorithm:    algoName,
		KeySize:      keySize,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    &notBefore,
		NotAfter:     &notAfter,
		IsCA:         cert.IsCA,
		Purpose:      purpose,
	}
	crypto.ClassifyCryptoAsset(asset)

	finding := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 2, // Certificates
		Source: model.FindingSource{
			Type:            "file",
			Path:            sourcePath,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "certstore",
		Timestamp:   time.Now(),
	}

	select {
	case findings <- finding:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// certKeyInfo extracts the algorithm name and key size from a
// certificate. Thin wrapper around the shared helper so the
// public signature stays local to this file.
func certKeyInfo(cert *x509.Certificate) (algo string, size int) {
	return certPublicKeyInfo(cert)
}
