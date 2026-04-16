package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestPythonAST_Name(t *testing.T) {
	m := NewPythonASTModule(testConfig())
	assert.Equal(t, "python_ast", m.Name())
}

func TestPythonAST_Category(t *testing.T) {
	m := NewPythonASTModule(testConfig())
	assert.Equal(t, model.CategoryPassiveCode, m.Category())
}

func TestPythonAST_ScanTargetType(t *testing.T) {
	m := NewPythonASTModule(testConfig())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestPythonAST_SingleFileHashlib(t *testing.T) {
	dir := t.TempDir()
	mainPy := filepath.Join(dir, "main.py")
	err := os.WriteFile(mainPy, []byte("import hashlib\nhashlib.sha256(b'test')\n"), 0o600)
	require.NoError(t, err)

	m := NewPythonASTModule(testConfig())
	findings := make(chan *model.Finding, 10)

	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir}
	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	require.NotEmpty(t, got, "expected at least one finding for hashlib.sha256")
	f := got[0]
	assert.Equal(t, "SHA-256", f.CryptoAsset.Algorithm)
	assert.Equal(t, "Python", f.CryptoAsset.Language)
	assert.Equal(t, "direct", f.CryptoAsset.Reachability)
	assert.Equal(t, "python_ast", f.Module)
	assert.Equal(t, "python-ast", f.Source.DetectionMethod)
}

func TestPythonAST_NoCrypto(t *testing.T) {
	dir := t.TempDir()
	mainPy := filepath.Join(dir, "main.py")
	err := os.WriteFile(mainPy, []byte("import os\nos.path.join('a', 'b')\n"), 0o600)
	require.NoError(t, err)

	m := NewPythonASTModule(testConfig())
	findings := make(chan *model.Finding, 10)

	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir}
	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	assert.Empty(t, got, "expected no findings for non-crypto code")
}

func TestPythonAST_Pycryptodome(t *testing.T) {
	dir := t.TempDir()
	mainPy := filepath.Join(dir, "main.py")
	src := "from Crypto.Cipher import AES\nkey = b'0' * 16\nAES.new(key, AES.MODE_ECB)\n"
	err := os.WriteFile(mainPy, []byte(src), 0o600)
	require.NoError(t, err)

	m := NewPythonASTModule(testConfig())
	findings := make(chan *model.Finding, 10)

	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir}
	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	require.NotEmpty(t, got, "expected at least one finding for Crypto.Cipher.AES")
	found := false
	for _, f := range got {
		if f.CryptoAsset.Algorithm == "AES" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected AES algorithm finding")
}

func TestPythonAST_CryptographyLibrary(t *testing.T) {
	dir := t.TempDir()
	mainPy := filepath.Join(dir, "main.py")
	src := "from cryptography.hazmat.primitives.asymmetric import ed25519\n" +
		"ed25519.Ed25519PrivateKey.generate()\n"
	err := os.WriteFile(mainPy, []byte(src), 0o600)
	require.NoError(t, err)

	m := NewPythonASTModule(testConfig())
	findings := make(chan *model.Finding, 10)

	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir}
	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	require.NotEmpty(t, got, "expected at least one finding for cryptography.hazmat.primitives.asymmetric.ed25519")
	found := false
	for _, f := range got {
		if f.CryptoAsset.Algorithm == "Ed25519" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected Ed25519 algorithm finding")
}
