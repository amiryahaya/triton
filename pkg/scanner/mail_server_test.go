package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*MailServerModule)(nil)

func TestMailServerModule_Interface(t *testing.T) {
	m := NewMailServerModule(&config.Config{})
	assert.Equal(t, "mail_server", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestIsMailServerConfigFile(t *testing.T) {
	cases := map[string]bool{
		"/etc/postfix/main.cf":      true,
		"/etc/postfix/master.cf":    true,
		"/etc/mail/sendmail.cf":     true,
		"/etc/mail/submit.cf":       true,
		"/etc/exim4/exim4.conf":     true,
		"/etc/opendkim.conf":        true,
		"/etc/opendkim/KeyTable":    true,
		"/etc/dkim/default.private": true,
		"/etc/nginx/nginx.conf":     false,
	}
	for path, want := range cases {
		got := isMailServerConfigFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

const postfixMainCfStrong = `# Postfix main.cf — strong TLS
smtpd_use_tls = yes
smtpd_tls_security_level = encrypt
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_exclude_ciphers = aNULL, MD5, RC4
smtpd_tls_cert_file = /etc/postfix/cert.pem
smtpd_tls_key_file = /etc/postfix/key.pem
`

const postfixMainCfWeak = `# Postfix main.cf — weak legacy config
smtpd_use_tls = yes
smtpd_tls_protocols = SSLv3, TLSv1
smtpd_tls_ciphers = medium
smtpd_tls_cipher_suites = ALL:!EXPORT:LOW
`

func TestParsePostfix_Strong(t *testing.T) {
	m := NewMailServerModule(&config.Config{})
	findings := m.parsePostfix("/etc/postfix/main.cf", []byte(postfixMainCfStrong))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	// Directive findings should surface; in this "strong" config
	// the operator excludes weak stuff, so the algorithm tokens
	// should reflect the exclusion list.
	assert.Contains(t, joined, "high")
}

func TestParsePostfix_Weak(t *testing.T) {
	m := NewMailServerModule(&config.Config{})
	findings := m.parsePostfix("/etc/postfix/main.cf", []byte(postfixMainCfWeak))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	// SSLv3 / TLSv1 must surface.
	assert.Contains(t, joined, "SSL 3.0")
	assert.Contains(t, joined, "TLS 1.0")
}

// --- DKIM ---

const dkimKeyTable = `default._domainkey.example.com example.com:default:/etc/dkim/default.private
mail._domainkey.corp.local corp.local:mail:/etc/dkim/corp.private
`

func TestParseDKIMKeyTable(t *testing.T) {
	m := NewMailServerModule(&config.Config{})
	findings := m.parseDKIMKeyTable("/etc/opendkim/KeyTable", []byte(dkimKeyTable))
	require.NotEmpty(t, findings)

	// Expect one finding per key entry with the signing selector
	// and domain encoded into the purpose.
	var hasExample bool
	var hasCorp bool
	for _, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}
		if strings.Contains(f.CryptoAsset.Purpose, "example.com") {
			hasExample = true
		}
		if strings.Contains(f.CryptoAsset.Purpose, "corp.local") {
			hasCorp = true
		}
	}
	assert.True(t, hasExample)
	assert.True(t, hasCorp)
}

// --- DKIM private key file detection ---

func TestParseDKIMKeyFile(t *testing.T) {
	m := NewMailServerModule(&config.Config{})
	findings := m.parseDKIMKeyFile("/etc/dkim/default.private")
	require.NotEmpty(t, findings)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "DKIM")
}

// --- End-to-end walk ---

func TestMailServerModule_ScanWalk(t *testing.T) {
	tmp := t.TempDir()
	postfixDir := filepath.Join(tmp, "etc", "postfix")
	require.NoError(t, os.MkdirAll(postfixDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(postfixDir, "main.cf"), []byte(postfixMainCfStrong), 0o644))

	m := NewMailServerModule(&config.Config{MaxDepth: 10, MaxFileSize: 1024 * 1024})
	findings := make(chan *model.Finding, 32)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: tmp, Depth: 10}, findings)
	require.NoError(t, err)
	close(findings)
	<-done

	require.NotEmpty(t, collected)
	for _, f := range collected {
		assert.Equal(t, "mail_server", f.Module)
	}
}
