// Package transport provides SSH and NETCONF clients used by
// vendor adapters and the SshReader.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig specifies how to connect to a remote host.
type SSHConfig struct {
	Address     string // host:port
	Username    string
	Password    string              // optional; empty means use key
	PrivateKey  []byte              // optional; empty means use password
	Passphrase  string              // for PrivateKey if encrypted
	HostKeyCB   ssh.HostKeyCallback // nil = ssh.InsecureIgnoreHostKey() (MVP only)
	DialTimeout time.Duration       // default 10s
	CmdTimeout  time.Duration       // default 30s per command
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

	hostKeyCB := cfg.HostKeyCB
	if hostKeyCB == nil {
		//nolint:gosec // MVP documented limitation; production needs known_hosts
		hostKeyCB = ssh.InsecureIgnoreHostKey()
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
