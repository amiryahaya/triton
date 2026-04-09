package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface compliance check
var _ Module = (*KeyModule)(nil)

func TestKeyModuleInterface(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})
	assert.Equal(t, "keys", m.Name())
}

func TestKeyModuleCategory(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestKeyModuleScanTargetType(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestParseRSAPrivateKey(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyContent := `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJRrMtWPmWnK/vL0s3gJTo9Lnlw
LpF4HKqkXCsM5WiB3TD7pzR8SKpN6ACmpWECAwEAAQJAS6EUQnVDIR6pkMOEDgDH
KqlREQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----`

	keyFile := filepath.Join(tmpDir, "test.key")
	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	finding := collected[0]

	assert.NotEmpty(t, finding.ID)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "rsa-private", finding.CryptoAsset.Function)
	assert.Equal(t, "RSA", finding.CryptoAsset.Algorithm)
	assert.NotEmpty(t, finding.CryptoAsset.PQCStatus, "PQC classification should be applied")
}

func TestKeyFindingShape(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyContent := `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJRrMtWPmWnK/vL0s3gJTo9Lnlw
-----END RSA PRIVATE KEY-----`

	keyFile := filepath.Join(tmpDir, "test.key")
	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(context.Background(), target, findings)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)

	assert.Equal(t, 5, finding.Category)
	assert.Equal(t, "file", finding.Source.Type)
	assert.Equal(t, "keys", finding.Module)
	assert.Equal(t, 0.90, finding.Confidence)
}

func TestDetectKeyTypeAndAlgorithm(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})

	tests := []struct {
		name          string
		content       string
		wantKeyType   string
		wantAlgorithm string
	}{
		{"RSA private", "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----", "rsa-private", "RSA"},
		{"EC private", "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----", "ec-private", "ECDSA"},
		{"PKCS8 private", "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----", "pkcs8-private", "Unknown"},
		{"Public key", "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----", "public", "Unknown"},
		{"OpenSSH private", "-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----", "openssh-private", "Unknown"},
		{"RSA public", "-----BEGIN RSA PUBLIC KEY-----\ndata\n-----END RSA PUBLIC KEY-----", "rsa-public", "RSA"},
		{"No key header", "some random data with SECTION and EC references", "", ""},
		{"Certificate PEM", "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyType, algo := m.detectKeyTypeAndAlgorithm(tt.content)
			assert.Equal(t, tt.wantKeyType, keyType)
			assert.Equal(t, tt.wantAlgorithm, algo)
		})
	}
}

func TestParseECPrivateKey(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyContent := `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODiAsKBChlFSt/C+6yxMqfBlH80IwLPqYaOEMkSgGdmoAcGBSuBBAAi
oWQDYgAE0Y/ip/T8KBxmFnlPPGGZasFzBMk3FO3iKSrkk5vWsadRXsfrFWxEIBbK
-----END EC PRIVATE KEY-----`

	keyFile := filepath.Join(tmpDir, "ec.key")
	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "ec-private", finding.CryptoAsset.Function)
	assert.Equal(t, "ECDSA", finding.CryptoAsset.Algorithm)
}

func TestParsePKCS8Key(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyContent := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdata
-----END PRIVATE KEY-----`

	keyFile := filepath.Join(tmpDir, "pkcs8.pem")
	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "pkcs8-private", finding.CryptoAsset.Function)
}

func TestParseOpenSSHKey(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyContent := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----`

	keyFile := filepath.Join(tmpDir, "id_ed25519")
	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "openssh-private", finding.CryptoAsset.Function)
}

func TestParsePublicKey(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyContent := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdata
-----END PUBLIC KEY-----`

	keyFile := filepath.Join(tmpDir, "test.pub")
	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "public", finding.CryptoAsset.Function)
}

func TestIsKeyFile(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})

	// Should match
	assert.True(t, m.isKeyFile("/path/to/server.key"))
	assert.True(t, m.isKeyFile("/path/to/cert.pem"))
	assert.True(t, m.isKeyFile("/path/to/key.priv"))
	assert.True(t, m.isKeyFile("/path/to/key.pub"))
	assert.True(t, m.isKeyFile("/home/user/.ssh/id_rsa"))
	assert.True(t, m.isKeyFile("/home/user/.ssh/id_ecdsa"))
	assert.True(t, m.isKeyFile("/home/user/.ssh/id_ed25519"))
	assert.True(t, m.isKeyFile("/home/user/.ssh/id_rsa.pub"))
	assert.True(t, m.isKeyFile("/path/to/private_key.pem"))
	assert.True(t, m.isKeyFile("/path/to/public_key.pem"))

	// SSH server host keys (Sprint A2 — gap filled). Real-world
	// servers store these in /etc/ssh/. Existing extension
	// matcher (".pub") catches the public counterparts; the
	// private host keys have NO extension and were missed before.
	assert.True(t, m.isKeyFile("/etc/ssh/ssh_host_rsa_key"))
	assert.True(t, m.isKeyFile("/etc/ssh/ssh_host_ecdsa_key"))
	assert.True(t, m.isKeyFile("/etc/ssh/ssh_host_ed25519_key"))
	assert.True(t, m.isKeyFile("/etc/ssh/ssh_host_dsa_key"))
	assert.True(t, m.isKeyFile("/etc/ssh/ssh_host_rsa_key.pub"))
	assert.True(t, m.isKeyFile("/etc/ssh/ssh_host_ed25519_key.pub"))

	// Should NOT match (previously caused false positives)
	assert.False(t, m.isKeyFile("/home/user/private_notes.txt"))
	assert.False(t, m.isKeyFile("/var/private/data.json"))
	assert.False(t, m.isKeyFile("/path/to/readme.txt"))
	assert.False(t, m.isKeyFile("/path/to/image.png"))
}

func TestNonKeyPEMFileSkipped(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Write a certificate PEM (not a key) — should be skipped
	certContent := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALbHnMO4ZY3WMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
-----END CERTIFICATE-----`

	certFile := filepath.Join(tmpDir, "cert.pem")
	err := os.WriteFile(certFile, []byte(certContent), 0644)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "certificate PEM files should not produce key findings")
}

func TestRandomTextFileSkipped(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// A file with "EC" and "SECTION" in content but no key header
	content := "This SECTION discusses EC curves and ECDSA REJECT criteria"
	textFile := filepath.Join(tmpDir, "notes.pem")
	err := os.WriteFile(textFile, []byte(content), 0644)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "files without key PEM headers should not produce findings")
}

func TestKeyScanNonExistentDir(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: "/nonexistent", Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	close(findings)
	_ = err

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestKeyScanUnreadableFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	keyFile := filepath.Join(tmpDir, "unreadable.key")
	err := os.WriteFile(keyFile, []byte("data"), 0000)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)

	os.Chmod(keyFile, 0644)
}

func TestPKCS8RSAKeyDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Generate a real RSA key and encode as PKCS#8
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	keyFile := filepath.Join(tmpDir, "rsa-pkcs8.pem")
	f, err := os.Create(keyFile)
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	require.NoError(t, err)
	f.Close()

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "pkcs8-private", finding.CryptoAsset.Function)
	assert.Equal(t, "RSA", finding.CryptoAsset.Algorithm)
	assert.Equal(t, 2048, finding.CryptoAsset.KeySize)
}

func TestPKCS8ECKeyDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	keyFile := filepath.Join(tmpDir, "ec-pkcs8.pem")
	f, err := os.Create(keyFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	f.Close()

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "pkcs8-private", finding.CryptoAsset.Function)
	assert.Equal(t, "ECDSA-P256", finding.CryptoAsset.Algorithm)
	assert.Equal(t, 256, finding.CryptoAsset.KeySize)
}

func TestPKCS8Ed25519KeyDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)

	keyFile := filepath.Join(tmpDir, "ed25519-pkcs8.pem")
	f, err := os.Create(keyFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	f.Close()

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "pkcs8-private", finding.CryptoAsset.Function)
	assert.Equal(t, "Ed25519", finding.CryptoAsset.Algorithm)
	assert.Equal(t, 256, finding.CryptoAsset.KeySize)
}

func TestSSHPublicKeyDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		content  string
		wantAlgo string
		wantSize int
	}{
		{
			name:     "ssh-rsa public key",
			filename: "id_rsa.pub",
			content:  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@host\n",
			wantAlgo: "RSA",
			wantSize: 0, // SSH public key format doesn't easily expose key size
		},
		{
			name:     "ssh-ed25519 public key",
			filename: "id_ed25519.pub",
			content:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host\n",
			wantAlgo: "Ed25519",
			wantSize: 256,
		},
		{
			name:     "ecdsa-sha2 public key",
			filename: "id_ecdsa.pub",
			content:  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTIt... user@host\n",
			wantAlgo: "ECDSA-P256",
			wantSize: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(tmpDir, tt.name)
			os.MkdirAll(dir, 0755)

			keyFile := filepath.Join(dir, tt.filename)
			err := os.WriteFile(keyFile, []byte(tt.content), 0644)
			require.NoError(t, err)

			m := NewKeyModule(&config.Config{})
			findings := make(chan *model.Finding, 10)
			target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 1}

			err = m.Scan(context.Background(), target, findings)
			require.NoError(t, err)
			close(findings)

			finding := <-findings
			require.NotNil(t, finding, "should find SSH public key: %s", tt.name)
			require.NotNil(t, finding.CryptoAsset)
			assert.Equal(t, "ssh-public", finding.CryptoAsset.Function)
			assert.Equal(t, tt.wantAlgo, finding.CryptoAsset.Algorithm)
			assert.Equal(t, tt.wantSize, finding.CryptoAsset.KeySize)
		})
	}
}

func TestAuthorizedKeysDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	content := `# SSH authorized keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@server
`
	keyFile := filepath.Join(tmpDir, "authorized_keys")
	err := os.WriteFile(keyFile, []byte(content), 0644)
	require.NoError(t, err)

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "ssh-public", finding.CryptoAsset.Function)
	assert.Equal(t, "Ed25519", finding.CryptoAsset.Algorithm)
}

func TestRSAKeySize(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	keyFile := filepath.Join(tmpDir, "rsa4096.key")
	f, err := os.Create(keyFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	f.Close()

	m := NewKeyModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "RSA", finding.CryptoAsset.Algorithm)
	assert.Equal(t, 4096, finding.CryptoAsset.KeySize)
}

func TestIsKeyFileExtended(t *testing.T) {
	t.Parallel()
	m := NewKeyModule(&config.Config{})

	// New SSH file patterns
	assert.True(t, m.isKeyFile("/home/user/.ssh/authorized_keys"))
	assert.True(t, m.isKeyFile("/home/user/.ssh/known_hosts"))
}
