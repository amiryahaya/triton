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

var _ Module = (*PasswordHashModule)(nil)

func TestPasswordHashModule_Interface(t *testing.T) {
	m := NewPasswordHashModule(&config.Config{})
	assert.Equal(t, "password_hash", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

// --- Matcher ---

func TestIsPasswordHashFile(t *testing.T) {
	cases := map[string]bool{
		"/etc/shadow":                         true,
		"/etc/gshadow":                        true,
		"/etc/pam.d/common-password":          true,
		"/etc/pam.d/passwd":                   true,
		"/etc/pam.d/system-auth":              true,
		"/etc/postgresql/15/main/pg_hba.conf": true,
		"/var/lib/pgsql/data/pg_hba.conf":     true,
		"/etc/passwd":                         false, // no hashes since ~1990
		"/etc/hosts":                          false,
		"/etc/nginx/nginx.conf":               false,
	}
	for path, want := range cases {
		got := isPasswordHashFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

// --- /etc/shadow parsing ---

const shadowFile = `root:$6$randomsalt$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ/./:19000:0:99999:7:::
admin:$y$j9T$somesalt$someyescryptdigestvalue0123456789:19000:0:99999:7:::
legacy:$1$oldsalt$md5cryptdigestwhichiscompromised:19000:0:99999:7:::
arcane:$5$salt$sha256cryptdigestvaluegoeshere:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
sshuser:!:19000:0:99999:7:::
bcrypter:$2y$10$bcryptSaltAndHashCombinedValueGoesHereXX:19000:0:99999:7:::
`

func TestParseShadowFile(t *testing.T) {
	m := NewPasswordHashModule(&config.Config{})
	findings := m.parseShadow("/etc/shadow", []byte(shadowFile))

	// Expect one finding per active user (root, admin, legacy, arcane,
	// bcrypter = 5). nobody/* and sshuser/! are locked accounts and
	// should NOT produce findings.
	require.Len(t, findings, 5)

	algos := collectAlgorithms(findings)
	// Must include both strong (SHA-512, yescrypt, bcrypt) and
	// weak (MD5-crypt) algorithms.
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "SHA-512")
	assert.Contains(t, joined, "yescrypt")
	assert.Contains(t, joined, "MD5")
	assert.Contains(t, joined, "SHA-256")
	// bcrypt shows up as-is — the crypto registry normalizes as bcrypt.
	assert.Contains(t, strings.ToLower(joined), "bcrypt")

	// The MD5 finding must be flagged as weak.
	var md5Finding *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(f.CryptoAsset.Algorithm, "MD5") {
			md5Finding = f
			break
		}
	}
	require.NotNil(t, md5Finding, "MD5-crypt finding missing")
	assert.NotEqual(t, "SAFE", md5Finding.CryptoAsset.PQCStatus)
}

func TestParseShadow_LockedAccountsSkipped(t *testing.T) {
	// Accounts with *, !, !!, or empty password fields are
	// system/locked accounts — don't emit findings for them.
	const locked = `root:*:19000:0:99999:7:::
bin:!:19000:0:99999:7:::
daemon:!!:19000:0:99999:7:::
empty::19000:0:99999:7:::
`
	m := NewPasswordHashModule(&config.Config{})
	findings := m.parseShadow("/etc/shadow", []byte(locked))
	assert.Empty(t, findings, "locked/empty accounts should not produce findings")
}

// --- PAM config parsing ---

const pamSystemAuth = `# pam.d/system-auth
auth        required      pam_unix.so
account     required      pam_unix.so
password    requisite     pam_pwquality.so
password    sufficient    pam_unix.so sha512 shadow use_authtok
session     required      pam_unix.so
`

const pamCommonPasswordWeak = `# pam.d/common-password
password [success=1 default=ignore] pam_unix.so obscure md5
`

func TestParsePAM_StrongSha512(t *testing.T) {
	m := NewPasswordHashModule(&config.Config{})
	findings := m.parsePAM("/etc/pam.d/system-auth", []byte(pamSystemAuth))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	assert.Contains(t, algos, "SHA-512-crypt")
}

func TestParsePAM_WeakMd5(t *testing.T) {
	m := NewPasswordHashModule(&config.Config{})
	findings := m.parsePAM("/etc/pam.d/common-password", []byte(pamCommonPasswordWeak))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "MD5")
}

// --- pg_hba.conf parsing ---

const pgHbaMixed = `# PostgreSQL Client Authentication Configuration File
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     scram-sha-256
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
# Legacy — insecure, should be flagged
host    legacy_app      app_user        10.0.0.0/24             md5
host    trust_zone      all             192.168.1.0/24          trust
host    replication     replicator      10.0.1.0/24             password
`

func TestParsePgHba(t *testing.T) {
	m := NewPasswordHashModule(&config.Config{})
	findings := m.parsePgHba("/etc/postgresql/15/main/pg_hba.conf", []byte(pgHbaMixed))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	// Must see at least the weak methods as findings.
	assert.Contains(t, joined, "md5")
	assert.Contains(t, joined, "trust")
	assert.Contains(t, joined, "password")
	// And the strong one.
	assert.Contains(t, strings.ToLower(joined), "scram")
}

// --- Integration walk ---

func TestPasswordHashModule_ScanWalk(t *testing.T) {
	tmp := t.TempDir()

	// Lay out a minimal tree that matches the module's path heuristics.
	etcDir := filepath.Join(tmp, "etc")
	pamDir := filepath.Join(etcDir, "pam.d")
	pgDir := filepath.Join(etcDir, "postgresql", "15", "main")
	require.NoError(t, os.MkdirAll(pamDir, 0o755))
	require.NoError(t, os.MkdirAll(pgDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(etcDir, "shadow"), []byte(shadowFile), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pamDir, "system-auth"), []byte(pamSystemAuth), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pgDir, "pg_hba.conf"), []byte(pgHbaMixed), 0o644))

	m := NewPasswordHashModule(&config.Config{MaxDepth: 10, MaxFileSize: 1024 * 1024})

	findings := make(chan *model.Finding, 100)
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
		assert.Equal(t, "password_hash", f.Module)
	}
}
