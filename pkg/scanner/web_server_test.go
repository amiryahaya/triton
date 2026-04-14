package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// --- Interface contract ---

var _ Module = (*WebServerModule)(nil)

func TestWebServerModule_Interface(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	assert.Equal(t, "web_server", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

// --- Matcher (isWebServerConfigFile) ---

func TestIsWebServerConfigFile_Nginx(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/etc/nginx/nginx.conf":                       true,
		"/etc/nginx/sites-enabled/example.com.conf":   true,
		"/etc/nginx/sites-available/example.com.conf": true,
		"/etc/nginx/conf.d/ssl.conf":                  true,
		"/usr/local/etc/nginx/nginx.conf":             true,
		"/etc/nginx/nginx.conf.bak":                   false, // .bak is not parsed
		"/var/log/nginx/access.log":                   false,
		"/etc/nginx/mime.types":                       false,
	}
	for path, want := range cases {
		got := isWebServerConfigFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

func TestIsWebServerConfigFile_Apache(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/etc/apache2/apache2.conf":                   true,
		"/etc/httpd/conf/httpd.conf":                  true,
		"/etc/apache2/sites-enabled/000-default.conf": true,
		"/etc/apache2/mods-enabled/ssl.conf":          true,
		"/etc/httpd/conf.d/ssl.conf":                  true,
		"/etc/apache2/ports.conf":                     true, // .conf in apache dir
	}
	for path, want := range cases {
		got := isWebServerConfigFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

func TestIsWebServerConfigFile_Haproxy(t *testing.T) {
	t.Parallel()
	assert.True(t, isWebServerConfigFile("/etc/haproxy/haproxy.cfg"))
	assert.True(t, isWebServerConfigFile("/usr/local/etc/haproxy/haproxy.cfg"))
}

func TestIsWebServerConfigFile_Caddy(t *testing.T) {
	t.Parallel()
	assert.True(t, isWebServerConfigFile("/etc/caddy/Caddyfile"))
	assert.True(t, isWebServerConfigFile("/usr/local/etc/Caddyfile"))
	// Caddy JSON config is also valid but we focus on the canonical Caddyfile
	// (JSON config is generated from it).
}

// --- nginx parser ---

const nginxStrong = `
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519:secp384r1;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
`

const nginxWeak = `
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5:RC4-SHA:DES-CBC3-SHA;
}
`

func TestParseNginx_Strong(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseNginx("/test/nginx.conf", []byte(nginxStrong))

	// Should find: 2 protocols + 3 ciphers + 2 curves + 1 HSTS = 8 minimum
	assert.GreaterOrEqual(t, len(findings), 7, "expected ≥7 findings, got %d", len(findings))

	algos := collectAlgorithms(findings)
	assert.Contains(t, algos, "TLS 1.2")
	assert.Contains(t, algos, "TLS 1.3")
	assert.Contains(t, algos, "X25519")

	hsts := findFunction(findings, "HTTP Strict Transport Security")
	require.NotNil(t, hsts, "HSTS finding missing")
	assert.Contains(t, hsts.CryptoAsset.Purpose, "max-age")
}

func TestParseNginx_Weak(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseNginx("/test/nginx.conf", []byte(nginxWeak))

	algos := collectAlgorithms(findings)
	// Weak protocols must surface as findings (they're what we're hunting for).
	assert.Contains(t, algos, "TLS 1.0")
	assert.Contains(t, algos, "TLS 1.1")
	// RC4 in cipher list must be classified.
	hasRC4 := false
	for _, a := range algos {
		if strings.Contains(strings.ToUpper(a), "RC4") {
			hasRC4 = true
			break
		}
	}
	assert.True(t, hasRC4, "RC4 cipher should surface, got %v", algos)
}

// --- Apache parser ---

const apacheStrong = `
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>
`

const apacheWeak = `
<VirtualHost *:443>
    SSLProtocol all -SSLv2 -SSLv3
    SSLCipherSuite HIGH:MEDIUM:!aNULL:DES-CBC3-SHA
</VirtualHost>
`

func TestParseApache_Strong(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseApache("/test/ssl.conf", []byte(apacheStrong))

	algos := collectAlgorithms(findings)
	assert.Contains(t, algos, "TLS 1.2")
	assert.Contains(t, algos, "TLS 1.3")

	hsts := findFunction(findings, "HTTP Strict Transport Security")
	assert.NotNil(t, hsts)
}

func TestParseApache_Weak(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseApache("/test/ssl.conf", []byte(apacheWeak))

	algos := collectAlgorithms(findings)
	// "SSLProtocol all" without explicit version pinning is itself
	// a finding because it allows whatever the OpenSSL build supports
	// (potentially TLS 1.0/1.1). We expand `all` to a finding tagged
	// "all (no version pinning)".
	hasAll := false
	for _, a := range algos {
		if strings.Contains(strings.ToLower(a), "all") {
			hasAll = true
		}
	}
	assert.True(t, hasAll, "SSLProtocol all should surface as a finding, got %v", algos)
}

// --- haproxy parser ---

const haproxyConfig = `
global
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-ciphers ECDHE-ECDSA-CHACHA20-POLY1305

frontend https
    bind *:443 ssl crt /etc/ssl/certs/example.pem
`

func TestParseHaproxy(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseHaproxy("/test/haproxy.cfg", []byte(haproxyConfig))

	require.NotEmpty(t, findings)
	algos := collectAlgorithms(findings)
	// Cipher list should produce per-cipher findings.
	hasGCM := false
	for _, a := range algos {
		if strings.Contains(strings.ToUpper(a), "GCM") || strings.Contains(strings.ToUpper(a), "AES") {
			hasGCM = true
		}
	}
	assert.True(t, hasGCM, "GCM/AES ciphers should surface, got %v", algos)
	// ssl-min-ver TLSv1.2 should produce a TLS 1.2 finding.
	assert.Contains(t, algos, "TLS 1.2")
}

// --- Caddy parser ---

const caddyfileConfig = `
example.com {
    tls {
        protocols tls1.2 tls1.3
        ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        curves x25519 secp384r1
    }
    header Strict-Transport-Security "max-age=31536000"
}
`

func TestParseCaddyfile(t *testing.T) {
	t.Parallel()
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseCaddyfile("/test/Caddyfile", []byte(caddyfileConfig))

	algos := collectAlgorithms(findings)
	assert.Contains(t, algos, "TLS 1.2")
	assert.Contains(t, algos, "TLS 1.3")
	assert.Contains(t, algos, "X25519")

	hsts := findFunction(findings, "HTTP Strict Transport Security")
	assert.NotNil(t, hsts)
}

// --- Regression: B4 Apache quoted SSLCipherSuite ---

// TestParseApache_QuotedCipherSuite reproduces the B4 review
// finding: Apache allows `SSLCipherSuite "…"` with outer
// double-quotes. Before the fix, the quotes leaked through the
// cipher-list split and produced algorithm names like `"NULL`
// and `ECDHE+AESGCM"` with literal quote characters.
func TestParseApache_QuotedCipherSuite(t *testing.T) {
	t.Parallel()
	const apacheQuoted = `
<VirtualHost *:443>
    SSLProtocol +TLSv1.2 +TLSv1.3
    SSLCipherSuite "!NULL:ECDHE+AESGCM:HIGH"
</VirtualHost>
`
	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseApache("/test/ssl.conf", []byte(apacheQuoted))
	require.NotEmpty(t, findings)

	for _, f := range findings {
		require.NotNil(t, f.CryptoAsset)
		assert.NotContains(t, f.CryptoAsset.Algorithm, `"`,
			"algorithm name %q should not contain literal quote char", f.CryptoAsset.Algorithm)
	}
}

// --- Regression: B1 nil-finding panic ---

// TestParseNginx_DegenerateCipherList reproduces the B1 review
// finding: a lone `!` as the cipher list value caused
// cipherFinding to return nil, which the channel send then
// forwarded to the engine collector's `*f` dereference. This
// test ensures the parser does not crash and that no nil
// finding leaks out.
func TestParseNginx_DegenerateCipherList(t *testing.T) {
	t.Parallel()
	const degenerate = `
server {
    listen 443 ssl;
    ssl_ciphers !;
    ssl_protocols !;
}
`
	m := NewWebServerModule(&scannerconfig.Config{})
	// Should not panic.
	findings := m.parseNginx("/test/nginx.conf", []byte(degenerate))
	// Any findings that did come back must be non-nil.
	for i, f := range findings {
		if f == nil {
			t.Errorf("finding %d is nil (B1 regression)", i)
		}
	}
}

// --- End-to-end Scan() with a real filesystem walk ---

func TestWebServerModule_ScanWalk(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	nginxPath := filepath.Join(tmp, "nginx.conf")
	require.NoError(t, os.WriteFile(nginxPath, []byte(nginxStrong), 0o644))

	// Stub a path that mimics nginx layout so isWebServerConfigFile matches.
	// Use a subdirectory with "nginx" in the path.
	nginxDir := filepath.Join(tmp, "nginx")
	require.NoError(t, os.MkdirAll(nginxDir, 0o755))
	subPath := filepath.Join(nginxDir, "test.conf")
	require.NoError(t, os.WriteFile(subPath, []byte(nginxStrong), 0o644))

	cfg := &scannerconfig.Config{MaxDepth: 5, MaxFileSize: 1024 * 1024}
	m := NewWebServerModule(cfg)

	findings := make(chan *model.Finding, 100)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	err := m.Scan(context.Background(), model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: tmp,
		Depth: 5,
	}, findings)
	require.NoError(t, err)
	close(findings)
	<-done

	require.NotEmpty(t, collected, "expected findings from nginx fixture under nginx/ dir")
	// All findings should be tagged with the web_server module name.
	for _, f := range collected {
		assert.Equal(t, "web_server", f.Module)
	}
}

// --- Hybrid PQC TLS groups (Phase 4 / Task 4) ---

// TestWebServerScan_DetectsHybridTLSGroup loads the nginx-hybrid.conf
// fixture and asserts the parser emits a finding for the hybrid
// X25519MLKEM768 group with IsHybrid=true and populated
// ComponentAlgorithms. Tests the ssl_ecdh_curve path (nginx).
func TestWebServerScan_DetectsHybridTLSGroup(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "nginx-hybrid.conf"))
	require.NoError(t, err)

	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseNginx("/etc/nginx/nginx-hybrid.conf", data)

	var hybrid *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.IsHybrid && f.CryptoAsset.Algorithm == "X25519MLKEM768" {
			hybrid = f
			break
		}
	}
	require.NotNil(t, hybrid, "expected X25519MLKEM768 hybrid group finding, got %d findings", len(findings))
	assert.True(t, hybrid.CryptoAsset.IsHybrid)
	assert.NotEmpty(t, hybrid.CryptoAsset.ComponentAlgorithms, "expected ComponentAlgorithms populated")
	assert.NotEmpty(t, hybrid.CryptoAsset.PQCStatus, "expected PQCStatus populated from registry")

	// The classical X25519 from the same directive should still be
	// emitted as a separate non-hybrid finding.
	var classical *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "X25519" && !f.CryptoAsset.IsHybrid {
			classical = f
			break
		}
	}
	assert.NotNil(t, classical, "expected separate X25519 classical finding")
}

// TestWebServerScan_DetectsHybridTLSGroupApache asserts the Apache
// SSLOpenSSLConfCmd Groups directive recognizes hybrid group names.
func TestWebServerScan_DetectsHybridTLSGroupApache(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "apache-hybrid.conf"))
	require.NoError(t, err)

	m := NewWebServerModule(&scannerconfig.Config{})
	findings := m.parseApache("/etc/apache2/sites-enabled/hybrid.conf", data)

	var hybrid *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.IsHybrid && f.CryptoAsset.Algorithm == "X25519MLKEM768" {
			hybrid = f
			break
		}
	}
	require.NotNil(t, hybrid, "expected X25519MLKEM768 hybrid finding from Apache SSLOpenSSLConfCmd Groups, got %d findings", len(findings))
	assert.NotEmpty(t, hybrid.CryptoAsset.ComponentAlgorithms)
}

// --- Test helpers ---

func collectAlgorithms(findings []*model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.CryptoAsset != nil {
			out = append(out, f.CryptoAsset.Algorithm)
		}
	}
	return out
}

func findFunction(findings []*model.Finding, function string) *model.Finding {
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == function {
			return f
		}
	}
	return nil
}
