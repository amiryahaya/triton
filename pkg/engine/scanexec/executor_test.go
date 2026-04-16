package scanexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/pkg/engine/credentials"
	"github.com/amiryahaya/triton/pkg/engine/keystore"
)

// fakeKeystore lets us return canned (authType, plaintext, err) tuples.
type fakeKeystore struct {
	authType  string
	plaintext []byte
	err       error
}

func (f *fakeKeystore) Get(_ context.Context, _ string) (string, []byte, error) {
	if f.err != nil {
		return "", nil, f.err
	}
	out := make([]byte, len(f.plaintext))
	copy(out, f.plaintext)
	return f.authType, out, nil
}

func mustSecretJSON(t *testing.T, s credentials.Secret) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	return b
}

func TestScanHost_KeystoreMiss_ReturnsError(t *testing.T) {
	ex := &Executor{Keystore: &fakeKeystore{err: keystore.ErrNotFound}}
	res := ex.ScanHost(context.Background(), HostTarget{ID: "h1", Address: "127.0.0.1", Port: 22}, "ref", "ssh-password", "quick")
	if res.Success {
		t.Fatalf("expected failure")
	}
	if !strings.Contains(res.Error, "keystore get") {
		t.Errorf("want keystore error, got %q", res.Error)
	}
}

func TestScanHost_AuthTypeMismatch_ReturnsError(t *testing.T) {
	ex := &Executor{Keystore: &fakeKeystore{
		authType:  "ssh-password",
		plaintext: mustSecretJSON(t, credentials.Secret{Username: "u", Password: "p"}),
	}}
	res := ex.ScanHost(context.Background(), HostTarget{ID: "h1"}, "ref", "ssh-key", "quick")
	if res.Success || !strings.Contains(res.Error, "auth_type mismatch") {
		t.Errorf("want mismatch error, got %q", res.Error)
	}
}

func TestScanHost_BadSecretJSON_ReturnsError(t *testing.T) {
	ex := &Executor{Keystore: &fakeKeystore{
		authType:  "ssh-password",
		plaintext: []byte("{not-json"),
	}}
	res := ex.ScanHost(context.Background(), HostTarget{ID: "h1"}, "ref", "ssh-password", "quick")
	if res.Success || !strings.Contains(res.Error, "parse secret") {
		t.Errorf("want parse error, got %q", res.Error)
	}
}

func TestScanHost_SSHDialFail_ReturnsError(t *testing.T) {
	ex := &Executor{Keystore: &fakeKeystore{
		authType:  "ssh-password",
		plaintext: mustSecretJSON(t, credentials.Secret{Username: "u", Password: "p"}),
	}}
	// Inject a dialer that always fails — avoids real network.
	ex.dial = func(_ context.Context, _ string, _ *ssh.ClientConfig) (sshRunner, error) {
		return nil, errors.New("connection refused")
	}
	res := ex.ScanHost(context.Background(), HostTarget{ID: "h1", Address: "127.0.0.1", Port: 1}, "ref", "ssh-password", "quick")
	if res.Success || !strings.Contains(res.Error, "ssh dial") {
		t.Errorf("want ssh dial error, got %q", res.Error)
	}
}

func TestBuildSSHConfig_Password_OK(t *testing.T) {
	cfg, err := buildSSHConfig("ssh-password", credentials.Secret{Username: "u", Password: "p"}, 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.User != "u" || len(cfg.Auth) != 1 {
		t.Errorf("cfg = %+v", cfg)
	}
}

// ed25519PEM generates a fresh Ed25519 key encoded in OpenSSH-compatible
// PEM form. ssh.ParsePrivateKey requires OPENSSH format; use MarshalPrivateKey.
func ed25519PEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestBuildSSHConfig_SSHKey_OK(t *testing.T) {
	pemBytes := ed25519PEM(t)
	cfg, err := buildSSHConfig("ssh-key", credentials.Secret{Username: "u", PrivateKey: string(pemBytes)}, 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(cfg.Auth) != 1 {
		t.Errorf("no auth methods")
	}
}

func TestBuildSSHConfig_SSHKey_BadPEM_Error(t *testing.T) {
	_, err := buildSSHConfig("ssh-key", credentials.Secret{Username: "u", PrivateKey: "not-a-pem"}, 5)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildSSHConfig_WinRM_Error(t *testing.T) {
	_, err := buildSSHConfig("winrm-password", credentials.Secret{Username: "u", Password: "p"}, 5)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("want not-supported, got %v", err)
	}
}

func TestBuildSSHConfig_UnknownAuthType_Error(t *testing.T) {
	_, err := buildSSHConfig("carrier-pigeon", credentials.Secret{}, 5)
	if err == nil || !strings.Contains(err.Error(), "unknown auth_type") {
		t.Errorf("want unknown, got %v", err)
	}
}
