package agentpush

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/pkg/engine/credentials"
)

// KeystoreReader is the narrow interface the executor needs from the
// engine's encrypted keystore. *keystore.Keystore satisfies it.
type KeystoreReader interface {
	Get(ctx context.Context, secretRef string) (authType string, plaintext []byte, err error)
}

// HostTarget identifies a single host to push the agent to.
type HostTarget struct {
	ID       string
	Address  string
	Port     int
	Hostname string
	OS       string
}

// PushResult is the outcome of pushing the agent to one host.
type PushResult struct {
	HostID      string
	Success     bool
	Fingerprint string // cert fingerprint on success
	Error       string
}

// sshDialer abstracts SSH dial for testability. Production code uses
// defaultDialSSH; tests inject a fake.
type sshDialer func(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error)

// sftpOpener abstracts SFTP client creation for testability.
type sftpOpener func(client *ssh.Client) (sftpClient, error)

// sftpClient is the subset of *sftp.Client used by the executor.
type sftpClient interface {
	MkdirAll(path string) error
	Create(path string) (*sftp.File, error)
	Close() error
}

// sshSessionRunner abstracts SSH command execution for testability.
type sshSessionRunner func(client *ssh.Client, cmd string) error

// Executor pushes the triton-agent binary, per-host TLS cert, and
// systemd service to a single host via SSH + SFTP. It mirrors the
// scanexec.Executor pattern: keystore lookup -> SSH dial -> work.
type Executor struct {
	Keystore      KeystoreReader
	EngineCert    *x509.Certificate
	EngineKey     crypto.Signer
	EngineAddress string // e.g. "10.0.0.5:9443" — goes into agent config
	AgentBinary   []byte // pre-loaded triton-agent binary for the target arch
	ScanProfile   string // default "standard"
	DialTimeout   time.Duration

	// Test hooks. nil in production.
	dial     sshDialer
	openSFTP sftpOpener
	runCmd   sshSessionRunner
}

// PushToHost performs the full push lifecycle for one host: fetch
// credential from keystore -> build SSH client -> mint cert -> upload
// files via SFTP -> install + start systemd service.
func (e *Executor) PushToHost(ctx context.Context, host HostTarget, secretRef, authType string) PushResult {
	if e.DialTimeout == 0 {
		e.DialTimeout = 30 * time.Second
	}
	if e.ScanProfile == "" {
		e.ScanProfile = "standard"
	}

	// 1. Keystore lookup.
	at, pt, err := e.Keystore.Get(ctx, secretRef)
	if err != nil {
		return PushResult{HostID: host.ID, Error: "keystore get: " + err.Error()}
	}
	defer func() {
		for i := range pt {
			pt[i] = 0
		}
	}()

	if at != authType {
		return PushResult{HostID: host.ID, Error: fmt.Sprintf("auth_type mismatch: want %q got %q", authType, at)}
	}

	var secret credentials.Secret
	if err := json.Unmarshal(pt, &secret); err != nil {
		return PushResult{HostID: host.ID, Error: "parse secret: " + err.Error()}
	}
	defer secret.Zero()

	// 2. Build SSH client.
	sshCfg, err := buildPushSSHConfig(authType, secret, e.DialTimeout)
	if err != nil {
		return PushResult{HostID: host.ID, Error: "ssh config: " + err.Error()}
	}
	addr := net.JoinHostPort(host.Address, strconv.Itoa(host.Port))

	dial := e.dial
	if dial == nil {
		dial = defaultPushDialSSH
	}
	sshClient, err := dial(ctx, addr, sshCfg)
	if err != nil {
		return PushResult{HostID: host.ID, Error: "ssh dial: " + err.Error()}
	}
	defer func() { _ = sshClient.Close() }()

	// 3. Mint per-host cert.
	agentCert, err := MintAgentCert(e.EngineCert, e.EngineKey, host.Hostname)
	if err != nil {
		return PushResult{HostID: host.ID, Error: "mint cert: " + err.Error()}
	}

	// 4. Render agent config.
	agentConfig, err := RenderAgentConfig(AgentConfigData{
		EngineURL:   "https://" + e.EngineAddress,
		ScanProfile: e.ScanProfile,
		HostID:      host.ID,
	})
	if err != nil {
		return PushResult{HostID: host.ID, Error: "render config: " + err.Error()}
	}

	// 5. Upload files via SFTP.
	openSFTP := e.openSFTP
	if openSFTP == nil {
		openSFTP = defaultOpenSFTP
	}
	sftpCl, err := openSFTP(sshClient)
	if err != nil {
		return PushResult{HostID: host.ID, Error: "sftp: " + err.Error()}
	}
	defer func() { _ = sftpCl.Close() }()

	// Create target directory.
	_ = sftpCl.MkdirAll("/opt/triton")

	type uploadEntry struct {
		data []byte
		mode uint32
	}
	files := map[string]uploadEntry{
		"/opt/triton/triton-agent":                 {e.AgentBinary, 0o755},
		"/opt/triton/agent.crt":                    {agentCert.CertPEM, 0o644},
		"/opt/triton/agent.key":                    {agentCert.KeyPEM, 0o600},
		"/opt/triton/engine-ca.crt":                {agentCert.EngineCACert, 0o644},
		"/opt/triton/agent.yaml":                   {agentConfig, 0o644},
		"/etc/systemd/system/triton-agent.service": {[]byte(systemdUnit), 0o644},
	}

	for path, f := range files {
		if err := sftpWriteFile(sftpCl, path, f.data, f.mode); err != nil {
			return PushResult{HostID: host.ID, Error: fmt.Sprintf("upload %s: %v", filepath.Base(path), err)}
		}
	}

	// 6. Install + start systemd service via SSH.
	// The unit file is already uploaded via SFTP above — no heredoc needed.
	runCmd := e.runCmd
	if runCmd == nil {
		runCmd = defaultSSHRunCommand
	}
	commands := []string{
		"systemctl daemon-reload",
		"systemctl enable triton-agent",
		"systemctl start triton-agent",
	}
	for _, cmd := range commands {
		if err := runCmd(sshClient, cmd); err != nil {
			label := cmd
			if len(label) > 40 {
				label = label[:40]
			}
			return PushResult{HostID: host.ID, Error: fmt.Sprintf("ssh cmd %q: %v", label, err)}
		}
	}

	return PushResult{
		HostID:      host.ID,
		Success:     true,
		Fingerprint: agentCert.Fingerprint,
	}
}

// sftpWriteFile writes data to path via the given SFTP client and sets
// the file mode. Create truncates any existing file.
func sftpWriteFile(c sftpClient, path string, data []byte, mode uint32) error {
	f, err := c.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Chmod(fs.FileMode(mode))
}

// defaultSSHRunCommand opens a new session and runs a single command.
func defaultSSHRunCommand(client *ssh.Client, cmd string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	return sess.Run(cmd)
}

// defaultPushDialSSH dials and completes the SSH handshake with a
// context-aware TCP dial.
func defaultPushDialSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// defaultOpenSFTP creates a real SFTP client from an SSH connection.
func defaultOpenSFTP(client *ssh.Client) (sftpClient, error) {
	return sftp.NewClient(client)
}

// buildPushSSHConfig maps an auth_type + Secret into an *ssh.ClientConfig.
// Host-key verification is deliberately insecure for MVP — the executor
// is invoked only against hosts the operator has already enrolled.
func buildPushSSHConfig(authType string, s credentials.Secret, timeout time.Duration) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            s.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // MVP push — bootstrap credential
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
	default:
		return nil, fmt.Errorf("unsupported auth_type for push: %q", authType)
	}
	return cfg, nil
}
