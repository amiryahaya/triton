// Package scanexec runs scan jobs on the engine: keystore credential
// lookup → SSH client → existing scanner.Engine against an SshReader.
package scanexec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/engine/credentials"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// KeystoreReader is the narrow interface the executor needs. *keystore.Keystore
// satisfies it directly. Tests inject a fake.
type KeystoreReader interface {
	Get(ctx context.Context, secretRef string) (authType string, plaintext []byte, err error)
}

// sshDialer abstracts the SSH dial so tests can bypass the network.
// runScanner abstracts the scanner engine so tests can stub it out.
type (
	sshDialer  func(ctx context.Context, addr string, cfg *ssh.ClientConfig) (sshRunner, error)
	runScanner func(ctx context.Context, profile, hostname string, reader fsadapter.FileReader) (*model.ScanResult, error)
)

// sshRunner is the subset of *ssh.Client used by SshReader (via
// fsadapter.CommandExecutor) plus a Close() hook.
type sshRunner interface {
	Run(ctx context.Context, command string) (string, error)
	Close() error
}

// Executor runs a single scan job against one host.
type Executor struct {
	Keystore    KeystoreReader
	DialTimeout time.Duration

	// Test hooks. nil in production.
	dial sshDialer
	run  runScanner
}

// HostTarget is the subset of ScanJobPayload host data needed to scan.
type HostTarget struct {
	ID       string
	Address  string
	Port     int
	Hostname string
	OS       string
}

// HostResult is the outcome of scanning one host.
type HostResult struct {
	HostID   string
	Success  bool
	Findings int
	Result   *model.ScanResult
	Error    string
}

// ScanHost performs the full scan lifecycle for one host: fetch credential
// from keystore → build SSH client → run scanner.Engine via SshReader.
func (e *Executor) ScanHost(ctx context.Context, host HostTarget, secretRef, authType, profile string) HostResult {
	if e.DialTimeout == 0 {
		e.DialTimeout = 30 * time.Second
	}

	// 1. Keystore lookup.
	at, pt, err := e.Keystore.Get(ctx, secretRef)
	if err != nil {
		return HostResult{HostID: host.ID, Error: "keystore get: " + err.Error()}
	}
	defer func() {
		for i := range pt {
			pt[i] = 0
		}
	}()

	if at != authType {
		return HostResult{HostID: host.ID, Error: fmt.Sprintf("auth_type mismatch: wanted %q got %q", authType, at)}
	}

	var secret credentials.Secret
	if err := json.Unmarshal(pt, &secret); err != nil {
		return HostResult{HostID: host.ID, Error: "parse secret: " + err.Error()}
	}
	defer secret.Zero()

	// 2. Build SSH client.
	sshCfg, err := buildSSHConfig(authType, secret, e.DialTimeout)
	if err != nil {
		return HostResult{HostID: host.ID, Error: "build ssh config: " + err.Error()}
	}
	addr := net.JoinHostPort(host.Address, strconv.Itoa(host.Port))

	dial := e.dial
	if dial == nil {
		dial = defaultDialSSH
	}
	client, err := dial(ctx, addr, sshCfg)
	if err != nil {
		return HostResult{HostID: host.ID, Error: "ssh dial: " + err.Error()}
	}
	defer func() { _ = client.Close() }()

	// 3. SshReader wraps the SSH command runner.
	reader := fsadapter.NewSshReader(client)

	// 4. Run scanner engine.
	run := e.run
	if run == nil {
		run = defaultRunScanner
	}
	result, err := run(ctx, profile, host.Hostname, reader)
	if err != nil {
		return HostResult{HostID: host.ID, Error: "scan run: " + err.Error()}
	}
	if result == nil {
		return HostResult{HostID: host.ID, Error: "scan run: nil result"}
	}

	if result.Metadata.Hostname == "" {
		result.Metadata.Hostname = host.Hostname
	}
	if result.Metadata.OS == "" {
		result.Metadata.OS = host.OS
	}

	return HostResult{
		HostID:   host.ID,
		Success:  true,
		Findings: len(result.Findings),
		Result:   result,
	}
}

// defaultRunScanner constructs scanner.Engine with RegisterDefaultModules
// and drains the progress channel.
func defaultRunScanner(ctx context.Context, profile, hostname string, reader fsadapter.FileReader) (*model.ScanResult, error) {
	cfg := scannerconfig.Load(profile)
	cfg.DBUrl = "" // scan results stream back via the portal; no local DB
	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()
	eng.SetFileReader(reader)
	if hostname != "" {
		eng.SetHostnameOverride(hostname)
	}

	progressCh := make(chan scanner.Progress, 32)
	go func() {
		for range progressCh {
		}
	}()
	result := eng.Scan(ctx, progressCh)
	if result == nil {
		return nil, fmt.Errorf("engine returned nil result")
	}
	return result, nil
}

// defaultDialSSH dials and completes the SSH handshake with a context-aware
// TCP dial. ssh.Dial itself has no ctx variant.
func defaultDialSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig) (sshRunner, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &sshClientRunner{client: ssh.NewClient(sshConn, chans, reqs), timeout: cfg.Timeout}, nil
}

// sshClientRunner adapts *ssh.Client to the sshRunner interface used by
// SshReader. It opens a fresh session per command and captures stdout,
// mirroring netadapter/transport.SSHClient.Run.
type sshClientRunner struct {
	client  *ssh.Client
	timeout time.Duration
}

func (s *sshClientRunner) Run(ctx context.Context, command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	cmdTimeout := s.timeout
	if cmdTimeout == 0 {
		cmdTimeout = 30 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput(command)
		done <- result{out: out, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return string(r.out), fmt.Errorf("command %q: %w", command, r.err)
		}
		return string(r.out), nil
	case <-cmdCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("command %q: %w", command, cmdCtx.Err())
	}
}

func (s *sshClientRunner) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// buildSSHConfig maps an auth_type + Secret into an *ssh.ClientConfig.
// Host-key verification is deliberately insecure for MVP — the executor is
// invoked only against hosts the operator has already enrolled; strict
// host-key pinning is a follow-up.
func buildSSHConfig(authType string, s credentials.Secret, timeout time.Duration) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            s.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // MVP scan path
		Timeout:         timeout,
	}
	switch authType {
	case "ssh-password", "bootstrap-admin":
		cfg.Auth = []ssh.AuthMethod{ssh.Password(s.Password)}
	case "ssh-key":
		var signer ssh.Signer
		var err error
		if s.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(s.PrivateKey), []byte(s.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(s.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	case "winrm-password":
		return nil, fmt.Errorf("winrm not supported for scanning (use agent-push in Phase 6)")
	default:
		return nil, fmt.Errorf("unknown auth_type: %q", authType)
	}
	return cfg, nil
}
