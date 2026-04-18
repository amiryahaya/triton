// Package transport provides SSH and NETCONF clients used by
// vendor adapters and the SshReader.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// resolveHostKeyCallback determines the host-key verification policy
// from the config in priority order:
//  1. Explicit HostKeyCB (test injection or custom resolver)
//  2. KnownHostsFile (production path — pins host keys)
//  3. InsecureHostKey=true (explicit opt-in for lab use)
//
// If none are set, returns an error forcing the operator to make a
// conscious security decision rather than silently defaulting to MITM-
// vulnerable "accept any host key".
func resolveHostKeyCallback(cfg SSHConfig) (ssh.HostKeyCallback, error) {
	if cfg.HostKeyCB != nil {
		return cfg.HostKeyCB, nil
	}
	if cfg.KnownHostsFile != "" {
		cb, err := knownhosts.New(cfg.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts %s: %w", cfg.KnownHostsFile, err)
		}
		return cb, nil
	}
	if cfg.InsecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit operator opt-in
	}
	return nil, fmt.Errorf("no host key verification: set KnownHostsFile or InsecureHostKey=true explicitly")
}

// SSHConfig specifies how to connect to a remote host.
type SSHConfig struct {
	Address         string // host:port
	Username        string
	Password        string              // optional; empty means use key
	PrivateKey      []byte              // optional; empty means use password
	Passphrase      string              // for PrivateKey if encrypted
	HostKeyCB       ssh.HostKeyCallback // if set, overrides KnownHostsFile
	KnownHostsFile  string              // path to known_hosts; empty = see InsecureHostKey
	InsecureHostKey bool                // if true AND no HostKeyCB/KnownHostsFile, accept any host key (opt-in)
	DialTimeout     time.Duration       // default 10s
	CmdTimeout      time.Duration       // default 30s per command
}

// SSHClient wraps an ssh.Client and implements CommandRunner.
type SSHClient struct {
	client     *ssh.Client
	cmdTimeout time.Duration
}

// Client exposes the underlying ssh.Client for NETCONF subsystem usage.
// Not part of the CommandRunner interface.
func (s *SSHClient) Client() *ssh.Client {
	return s.client
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

	hostKeyCB, err := resolveHostKeyCallback(cfg)
	if err != nil {
		return nil, err
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

// Run executes a single command and returns its stdout. On non-zero exit
// the stderr (truncated to 1 KiB) is included in the error message so
// fleet-scan and device-scan callers can surface remote diagnostics. On
// success, stderr is discarded.
func (s *SSHClient) Run(ctx context.Context, command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmdCtx, cancel := context.WithTimeout(ctx, s.cmdTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case err := <-done:
		if err != nil {
			errTail := truncateErr(stderr.String(), 1024)
			return stdout.String(), fmt.Errorf("command %q: %w (stderr: %s)", command, err, errTail)
		}
		return stdout.String(), nil
	case <-cmdCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		errTail := truncateErr(stderr.String(), 1024)
		return stdout.String(), fmt.Errorf("command %q: %w (stderr: %s)", command, cmdCtx.Err(), errTail)
	}
}

// truncateErr returns s trimmed to maxLen bytes plus an ellipsis if longer.
func truncateErr(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…(truncated)"
}

// Upload copies localPath to the remote host at remotePath with the given
// file mode via the SFTP subsystem. Creates remote parent directory via
// MkdirAll if needed. Fails fast if localPath does not exist.
func (s *SSHClient) Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	local, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file %s: %w", localPath, err)
	}
	defer func() { _ = local.Close() }()

	client, err := sftp.NewClient(s.client)
	if err != nil {
		return fmt.Errorf("open sftp subsystem: %w", err)
	}
	defer func() { _ = client.Close() }()

	remoteDir := remoteDirOf(remotePath)
	if remoteDir != "" && remoteDir != "/" {
		if err := client.MkdirAll(remoteDir); err != nil {
			return fmt.Errorf("mkdir remote dir %s: %w", remoteDir, err)
		}
	}

	remote, err := client.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file %s: %w", remotePath, err)
	}
	defer func() { _ = remote.Close() }()

	if _, err := io.Copy(remote, local); err != nil {
		return fmt.Errorf("copy to remote: %w", err)
	}
	if err := client.Chmod(remotePath, mode); err != nil {
		return fmt.Errorf("chmod remote file: %w", err)
	}
	_ = ctx
	return nil
}

// remoteDirOf returns the directory portion of a POSIX path.
func remoteDirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return ""
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
