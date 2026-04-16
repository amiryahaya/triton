package agentpush

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/pkg/engine/credentials"
)

// --- fake keystore ---

type fakeKeystore struct {
	authType  string
	plaintext []byte
	err       error
}

func (f *fakeKeystore) Get(_ context.Context, _ string) (string, []byte, error) {
	if f.err != nil {
		return "", nil, f.err
	}
	cp := make([]byte, len(f.plaintext))
	copy(cp, f.plaintext)
	return f.authType, cp, nil
}

// --- tests ---

func TestRenderAgentConfig(t *testing.T) {
	data := AgentConfigData{
		EngineURL:   "https://10.0.0.5:9443",
		ScanProfile: "comprehensive",
		HostID:      "host-abc",
	}
	out, err := RenderAgentConfig(data)
	if err != nil {
		t.Fatalf("RenderAgentConfig: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "engine_url: https://10.0.0.5:9443") {
		t.Errorf("missing engine_url in output: %s", s)
	}
	if !strings.Contains(s, "scan_profile: comprehensive") {
		t.Errorf("missing scan_profile in output: %s", s)
	}
	if !strings.Contains(s, "host_id: host-abc") {
		t.Errorf("missing host_id in output: %s", s)
	}
	if !strings.Contains(s, "cert_path: /opt/triton/agent.crt") {
		t.Errorf("missing cert_path in output: %s", s)
	}
	if !strings.Contains(s, "key_path: /opt/triton/agent.key") {
		t.Errorf("missing key_path in output: %s", s)
	}
	if !strings.Contains(s, "ca_path: /opt/triton/engine-ca.crt") {
		t.Errorf("missing ca_path in output: %s", s)
	}
}

func TestPushToHost_KeystoreMiss(t *testing.T) {
	e := &Executor{
		Keystore: &fakeKeystore{err: errors.New("secret not found")},
	}
	host := HostTarget{ID: "h1", Address: "10.0.0.1", Port: 22, Hostname: "web1"}
	res := e.PushToHost(context.Background(), host, "ref-1", "bootstrap-admin")
	if res.Success {
		t.Fatal("expected failure on keystore miss")
	}
	if !strings.Contains(res.Error, "keystore get") {
		t.Errorf("error = %q, want keystore get prefix", res.Error)
	}
}

func TestPushToHost_AuthTypeMismatch(t *testing.T) {
	secret, _ := json.Marshal(credentials.Secret{Username: "root", Password: "pass"})
	e := &Executor{
		Keystore: &fakeKeystore{authType: "ssh-key", plaintext: secret},
	}
	host := HostTarget{ID: "h1", Address: "10.0.0.1", Port: 22, Hostname: "web1"}
	res := e.PushToHost(context.Background(), host, "ref-1", "bootstrap-admin")
	if res.Success {
		t.Fatal("expected failure on auth_type mismatch")
	}
	if !strings.Contains(res.Error, "auth_type mismatch") {
		t.Errorf("error = %q, want auth_type mismatch", res.Error)
	}
}

func TestPushToHost_SSHDialFail(t *testing.T) {
	secret, _ := json.Marshal(credentials.Secret{Username: "root", Password: "pass"})
	e := &Executor{
		Keystore: &fakeKeystore{authType: "bootstrap-admin", plaintext: secret},
		dial: func(_ context.Context, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
			return nil, errors.New("connection refused")
		},
	}
	host := HostTarget{ID: "h1", Address: "127.0.0.1", Port: 1, Hostname: "web1"}
	res := e.PushToHost(context.Background(), host, "ref-1", "bootstrap-admin")
	if res.Success {
		t.Fatal("expected failure on SSH dial")
	}
	if !strings.Contains(res.Error, "ssh dial") {
		t.Errorf("error = %q, want ssh dial prefix", res.Error)
	}
}

func TestBuildPushSSHConfig_BootstrapAdmin(t *testing.T) {
	s := credentials.Secret{Username: "root", Password: "s3cret"}
	cfg, err := buildPushSSHConfig("bootstrap-admin", s, 5*time.Second)
	if err != nil {
		t.Fatalf("buildPushSSHConfig: %v", err)
	}
	if cfg.User != "root" {
		t.Errorf("User = %q, want root", cfg.User)
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("Auth len = %d, want 1", len(cfg.Auth))
	}
}

func TestBuildPushSSHConfig_SSHPassword(t *testing.T) {
	s := credentials.Secret{Username: "admin", Password: "pw"}
	cfg, err := buildPushSSHConfig("ssh-password", s, 5*time.Second)
	if err != nil {
		t.Fatalf("buildPushSSHConfig: %v", err)
	}
	if cfg.User != "admin" {
		t.Errorf("User = %q, want admin", cfg.User)
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("Auth len = %d, want 1", len(cfg.Auth))
	}
}

func TestBuildPushSSHConfig_UnsupportedAuthType(t *testing.T) {
	s := credentials.Secret{Username: "u", Password: "p"}
	_, err := buildPushSSHConfig("winrm-password", s, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for unsupported auth_type")
	}
	if !strings.Contains(err.Error(), "unsupported auth_type") {
		t.Errorf("err = %v, want unsupported auth_type", err)
	}
}
