// Package credentials implements the engine-side credential delivery
// pipeline: a handler that decrypts sealed-box deliveries into the
// encrypted keystore, and a test worker that probes target hosts with
// stored secrets to validate them.
package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// ProbeResult is the outcome of probing a single host with a secret.
type ProbeResult struct {
	Success   bool
	LatencyMs int
	Error     string
}

// Prober probes target hosts with supplied credentials. The zero value
// uses a 10s dial timeout.
type Prober struct {
	DialTimeout time.Duration
}

// Secret is the decrypted credential material. Callers MUST call
// Secret.Zero (typically via defer) when done.
//
// PrivateKey is a string (not []byte) because the browser serializes
// the SSH key as a PEM-encoded string (`-----BEGIN OPENSSH PRIVATE
// KEY-----...`); encoding/json would otherwise try to base64-decode
// it and fail with "illegal base64 data at input byte 0". Go strings
// are immutable, so Zero() is best-effort — a hardened implementation
// would use a []byte field with a manual TLV parse to sidestep
// encoding/json's base64 handling for []byte.
type Secret struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// ParseSecret decodes the keystore plaintext payload into a Secret.
func ParseSecret(plaintext []byte) (Secret, error) {
	var s Secret
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return Secret{}, fmt.Errorf("parse secret json: %w", err)
	}
	return s, nil
}

// Zero wipes sensitive fields best-effort. Go strings are immutable,
// so we can only reassign to the empty string and hope the GC collects
// the underlying byte storage promptly. A hardened implementation
// would use []byte fields and manual TLV parsing, but that is deferred.
func (s *Secret) Zero() {
	s.Username = ""
	s.Password = ""
	s.PrivateKey = ""
	s.Passphrase = ""
}

// Probe attempts to authenticate to address:port using the given
// auth_type. Returns Success=true iff the SSH handshake completes.
func (p *Prober) Probe(ctx context.Context, authType string, secret Secret, address string, port int) ProbeResult {
	switch authType {
	case "ssh-password", "ssh-key", "bootstrap-admin":
		return p.probeSSH(ctx, authType, secret, address, port)
	case "winrm-password":
		return ProbeResult{Success: false, Error: "winrm probe not implemented in MVP"}
	default:
		return ProbeResult{Success: false, Error: "unknown auth_type: " + authType}
	}
}

func (p *Prober) probeSSH(ctx context.Context, authType string, s Secret, addr string, port int) ProbeResult {
	dialTimeout := p.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}

	var auth []ssh.AuthMethod
	switch authType {
	case "ssh-password", "bootstrap-admin":
		auth = []ssh.AuthMethod{ssh.Password(s.Password)}
	case "ssh-key":
		var signer ssh.Signer
		var err error
		if s.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(s.PrivateKey), []byte(s.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(s.PrivateKey))
		}
		if err != nil {
			return ProbeResult{Success: false, Error: "parse private key: " + err.Error()}
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}

	cfg := &ssh.ClientConfig{
		User: s.Username,
		Auth: auth,
		// InsecureIgnoreHostKey: MVP credential-probe only performs
		// an SSH handshake — we never open channels, never run
		// commands, never transfer data. Host-key pinning will be
		// added when the scanner itself runs, not in the probe path.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // documented probe-only tradeoff
		Timeout:         dialTimeout,
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	addrPort := net.JoinHostPort(addr, strconv.Itoa(port))

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addrPort)
	if err != nil {
		return ProbeResult{Success: false, Error: "dial: " + err.Error()}
	}
	defer func() { _ = conn.Close() }()

	sc, chans, reqs, err := ssh.NewClientConn(conn, addrPort, cfg)
	if err != nil {
		return ProbeResult{
			Success:   false,
			LatencyMs: int(time.Since(start).Milliseconds()),
			Error:     "ssh handshake: " + err.Error(),
		}
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "probe-only")
		}
	}()

	return ProbeResult{
		Success:   true,
		LatencyMs: int(time.Since(start).Milliseconds()),
	}
}
