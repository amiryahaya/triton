package credentials

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is a minimal in-process SSH server for probe tests. It
// accepts a single connection, performs the handshake (optionally
// rejecting auth), and closes.
type testSSHServer struct {
	ln         net.Listener
	host, port string
	hostKey    ssh.Signer

	wg       sync.WaitGroup
	accept   func(meta ssh.ConnMetadata, pwd []byte) bool // nil => always accept
	stopOnce sync.Once
}

func newTestSSHServer(t *testing.T, accept func(ssh.ConnMetadata, []byte) bool) *testSSHServer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	srv := &testSSHServer{ln: ln, host: host, port: port, hostKey: signer, accept: accept}
	srv.wg.Add(1)
	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

func (s *testSSHServer) portInt() int {
	p, _ := strconv.Atoi(s.port)
	return p
}

func (s *testSSHServer) Close() {
	s.stopOnce.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
}

func (s *testSSHServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *testSSHServer) handle(conn net.Conn) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pwd []byte) (*ssh.Permissions, error) {
			if s.accept == nil || s.accept(meta, pwd) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("auth rejected")
		},
	}
	cfg.AddHostKey(s.hostKey)
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "test")
		}
	}()
	// Keep the connection open briefly so the client can measure
	// handshake latency; then tear down.
	time.AfterFunc(50*time.Millisecond, func() { _ = sc.Close() })
}

func TestProbeSSH_UnreachableHost_Errors(t *testing.T) {
	p := &Prober{DialTimeout: 500 * time.Millisecond}
	res := p.Probe(context.Background(), "ssh-password",
		Secret{Username: "u", Password: "p"}, "127.0.0.1", 1)
	if res.Success {
		t.Fatal("expected failure")
	}
	if !strings.HasPrefix(res.Error, "dial:") {
		t.Errorf("error = %q, want dial: prefix", res.Error)
	}
}

func TestProbeSSH_WrongAuth_Errors(t *testing.T) {
	srv := newTestSSHServer(t, func(_ ssh.ConnMetadata, pwd []byte) bool {
		return string(pwd) == "right"
	})
	p := &Prober{DialTimeout: 3 * time.Second}
	res := p.Probe(context.Background(), "ssh-password",
		Secret{Username: "u", Password: "wrong"}, srv.host, srv.portInt())
	if res.Success {
		t.Fatal("expected failure on wrong password")
	}
	if !strings.HasPrefix(res.Error, "ssh handshake:") {
		t.Errorf("error = %q", res.Error)
	}
}

func TestProbeSSH_Success(t *testing.T) {
	srv := newTestSSHServer(t, func(_ ssh.ConnMetadata, pwd []byte) bool {
		return string(pwd) == "pw"
	})
	p := &Prober{DialTimeout: 3 * time.Second}
	res := p.Probe(context.Background(), "ssh-password",
		Secret{Username: "u", Password: "pw"}, srv.host, srv.portInt())
	if !res.Success {
		t.Fatalf("expected success, got error=%q", res.Error)
	}
	if res.LatencyMs < 0 {
		t.Errorf("latency = %d", res.LatencyMs)
	}
}

func TestProbe_WinRM_NotImplemented(t *testing.T) {
	p := &Prober{}
	res := p.Probe(context.Background(), "winrm-password", Secret{}, "10.0.0.1", 5985)
	if res.Success {
		t.Fatal("winrm should fail")
	}
	if !strings.Contains(res.Error, "not implemented") {
		t.Errorf("error = %q", res.Error)
	}
}

func TestProbe_UnknownAuthType(t *testing.T) {
	p := &Prober{}
	res := p.Probe(context.Background(), "telnet", Secret{}, "10.0.0.1", 23)
	if res.Success {
		t.Fatal("unknown auth should fail")
	}
	if !strings.Contains(res.Error, "unknown auth_type") {
		t.Errorf("error = %q", res.Error)
	}
}

func TestSecret_Zero(t *testing.T) {
	pk := []byte("priv-key-bytes")
	s := Secret{Username: "u", Password: "p", PrivateKey: pk, Passphrase: "pp"}
	s.Zero()
	for i, b := range pk {
		if b != 0 {
			t.Errorf("PrivateKey[%d] = %d, want 0", i, b)
		}
	}
	if s.Username != "" || s.Password != "" || s.Passphrase != "" {
		t.Errorf("strings not zeroed: %+v", s)
	}
}

func TestParseSecret_OK(t *testing.T) {
	pt := []byte(`{"username":"u","password":"p"}`)
	s, err := ParseSecret(pt)
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if s.Username != "u" || s.Password != "p" {
		t.Errorf("secret = %+v", s)
	}
}

func TestParseSecret_BadJSON(t *testing.T) {
	if _, err := ParseSecret([]byte("not json")); err == nil {
		t.Fatal("expected error")
	}
}
