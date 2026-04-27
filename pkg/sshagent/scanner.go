// Package sshagent provides an SSH-based remote scanner that dials into a
// host and runs the full Triton scanner engine against the remote filesystem
// via fsadapter.SshReader. It is the agentless scanning path for the Manage
// Server: no triton-agent binary is required on the target host.
package sshagent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// Credentials holds the authentication material needed to SSH into a host.
type Credentials struct {
	Username   string
	Password   string
	PrivateKey []byte // PEM-encoded private key; takes precedence over Password when non-nil
	Passphrase string // optional passphrase protecting PrivateKey
	Port       int    // SSH port; defaults to 22 when zero
}

// Scanner is the interface exposed by this package.
type Scanner interface {
	Scan(ctx context.Context, hostname, address string, creds Credentials, profile string) (*model.ScanResult, error)
}

// SSHScanner implements Scanner. Zero value is usable; DialTimeout defaults
// to 30 s when not set.
type SSHScanner struct {
	DialTimeout time.Duration
}

// Scan dials the remote host over SSH, wraps the connection in an
// fsadapter.SshReader, runs the full scanner engine, and returns the result
// with Metadata.Source set to model.ScanSourceSSHAgent.
func (s *SSHScanner) Scan(ctx context.Context, hostname, address string, creds Credentials, profile string) (*model.ScanResult, error) {
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	port := creds.Port
	if port == 0 {
		port = 22
	}

	// 1. Build SSH client config.
	sshCfg, err := buildSSHConfig(creds, timeout)
	if err != nil {
		return nil, fmt.Errorf("sshagent: build ssh config: %w", err)
	}

	// 2. Dial with context-aware TCP dialer (ssh.Dial has no ctx variant).
	addr := net.JoinHostPort(address, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshagent: tcp dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sshagent: ssh handshake %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	// 3. Wrap the SSH client in an SshReader (one find/cat per file, binary-safe).
	runner := &sshCommandExecutor{client: client, timeout: timeout}
	reader := fsadapter.NewSshReader(runner)

	// 4. Run the scanner engine.
	result, err := runScanner(ctx, profile, hostname, reader)
	if err != nil {
		return nil, fmt.Errorf("sshagent: scan %s: %w", hostname, err)
	}

	// 5. Tag the result so consumers know it came from agentless SSH.
	result.Metadata.Source = model.ScanSourceSSHAgent

	return result, nil
}

// runScanner constructs a scanner.Engine, registers default modules,
// injects the remote FileReader and optional hostname override, and runs
// the scan to completion.
func runScanner(ctx context.Context, profile, hostname string, reader fsadapter.FileReader) (*model.ScanResult, error) {
	cfg := scannerconfig.Load(profile)
	cfg.DBUrl = "" // results stream back via the portal; no local DB

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()
	eng.SetFileReader(reader)
	if hostname != "" {
		eng.SetHostnameOverride(hostname)
	}

	// Drain the progress channel so the engine never blocks on send.
	// The goroutine terminates as soon as Scan closes the channel.
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

// sshCommandExecutor implements fsadapter.CommandExecutor by opening a fresh
// SSH session per command. It mirrors sshClientRunner in
// pkg/engine/scanexec/executor.go.
type sshCommandExecutor struct {
	client  *ssh.Client
	timeout time.Duration
}

// Run executes command on the remote host and returns combined stdout+stderr.
func (e *sshCommandExecutor) Run(ctx context.Context, command string) (string, error) {
	session, err := e.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	cmdTimeout := e.timeout
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

// buildSSHConfig maps Credentials into an *ssh.ClientConfig.
// Host-key verification is deliberately insecure for the MVP agentless path —
// operators enroll hosts explicitly; strict pinning is a follow-up.
func buildSSHConfig(creds Credentials, timeout time.Duration) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            creds.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // MVP agentless path
		Timeout:         timeout,
	}

	switch {
	case len(creds.PrivateKey) > 0:
		var signer ssh.Signer
		var err error
		if creds.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(creds.PrivateKey, []byte(creds.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(creds.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

	case creds.Password != "":
		cfg.Auth = []ssh.AuthMethod{ssh.Password(creds.Password)}

	default:
		return nil, fmt.Errorf("credentials must have either PrivateKey or Password")
	}

	return cfg, nil
}
