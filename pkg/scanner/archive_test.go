package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// generateTestCertPEM generates a self-signed PEM certificate for testing.
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
	return buf.Bytes()
}

// buildZip builds a ZIP archive in memory with the given entries.
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestArchiveModule_Interface verifies the module metadata.
func TestArchiveModule_Interface(t *testing.T) {
	cfg := scannerconfig.Load("standard")
	m := NewArchiveModule(cfg)

	if got := m.Name(); got != "archive" {
		t.Errorf("Name() = %q, want %q", got, "archive")
	}
	if got := m.Category(); got != model.CategoryPassiveFile {
		t.Errorf("Category() = %v, want CategoryPassiveFile", got)
	}
	if got := m.ScanTargetType(); got != model.TargetFilesystem {
		t.Errorf("ScanTargetType() = %v, want TargetFilesystem", got)
	}
}

// TestArchiveModule_ZipWithCert creates a ZIP (named .jar) containing a PEM
// cert and verifies that exactly one finding is emitted with the correct path.
func TestArchiveModule_ZipWithCert(t *testing.T) {
	cfg := scannerconfig.Load("standard")
	m := NewArchiveModule(cfg)

	certPEM := generateTestCertPEM(t)
	jarData := buildZip(t, map[string][]byte{
		"META-INF/server.crt":  certPEM,
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\n"),
	})

	findings := make(chan *model.Finding, 10)
	ctx := context.Background()

	err := m.scanArchive(ctx, jarData, "app.jar", 1, findings)
	close(findings)

	if err != nil {
		t.Fatalf("scanArchive returned error: %v", err)
	}

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}

	f := got[0]
	if f.Module != "archive" {
		t.Errorf("Module = %q, want %q", f.Module, "archive")
	}
	// Path must contain the archive separator "!/"
	wantPathPrefix := "app.jar!/"
	if len(f.Source.Path) < len(wantPathPrefix) || f.Source.Path[:len(wantPathPrefix)] != wantPathPrefix {
		t.Errorf("Source.Path = %q, want prefix %q", f.Source.Path, wantPathPrefix)
	}
	if f.CryptoAsset == nil {
		t.Fatal("CryptoAsset is nil")
	}
	if f.CryptoAsset.Algorithm == "" {
		t.Error("CryptoAsset.Algorithm is empty")
	}
}

// TestArchiveModule_TwoLevelNesting creates a JAR inside a WAR and verifies
// that the certificate inside the inner JAR is found.
func TestArchiveModule_TwoLevelNesting(t *testing.T) {
	cfg := scannerconfig.Load("standard")
	m := NewArchiveModule(cfg)

	certPEM := generateTestCertPEM(t)
	// Build inner.jar containing the cert.
	innerJarData := buildZip(t, map[string][]byte{
		"META-INF/server.crt": certPEM,
	})
	// Build app.war containing inner.jar.
	outerWarData := buildZip(t, map[string][]byte{
		"WEB-INF/lib/inner.jar": innerJarData,
	})

	findings := make(chan *model.Finding, 10)
	ctx := context.Background()

	err := m.scanArchive(ctx, outerWarData, "app.war", 1, findings)
	close(findings)

	if err != nil {
		t.Fatalf("scanArchive returned error: %v", err)
	}

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}

	f := got[0]
	// Path must reference both the outer WAR and the inner JAR.
	if !contains(f.Source.Path, "app.war!/") {
		t.Errorf("Source.Path %q missing outer WAR reference", f.Source.Path)
	}
	if !contains(f.Source.Path, "inner.jar!/") {
		t.Errorf("Source.Path %q missing inner JAR reference", f.Source.Path)
	}
}

// TestArchiveModule_ZipBombProtection creates a ZIP with 100 empty entries
// (none are crypto files) and verifies no findings are produced and the scan
// completes without hanging.
func TestArchiveModule_ZipBombProtection(t *testing.T) {
	cfg := scannerconfig.Load("standard")
	m := NewArchiveModule(cfg)

	// Build 100 non-crypto entries.
	entries := make(map[string][]byte, 100)
	for i := range 100 {
		entries[byteKey(i)] = []byte("harmless content")
	}
	zipData := buildZip(t, entries)

	findings := make(chan *model.Finding, 10)
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.scanArchive(ctx, zipData, "bomb.zip", 1, findings)
		close(findings)
	}()

	select {
	case <-done:
		// good — did not hang
	case <-time.After(5 * time.Second):
		t.Fatal("scanArchive hung; zip bomb protection may be broken")
	}

	var count int
	for range findings {
		count++
	}
	if count != 0 {
		t.Errorf("want 0 findings from non-crypto ZIP, got %d", count)
	}
}

// TestIsArchiveFile verifies file extension matching.
func TestIsArchiveFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"app.jar", true},
		{"app.JAR", true},
		{"web.war", true},
		{"enterprise.ear", true},
		{"data.zip", true},
		{"archive.tar", true},
		{"archive.tar.gz", true},
		{"archive.tgz", true},
		{"archive.tar.bz2", true},
		{"file.txt", false},
		{"file.pem", false},
		{"file.class", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := isArchiveFile(tc.path); got != tc.want {
				t.Errorf("isArchiveFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestIsCryptoFile verifies crypto file extension matching.
func TestIsCryptoFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"cert.pem", true},
		{"cert.crt", true},
		{"cert.cer", true},
		{"cert.der", true},
		{"cert.p7b", true},
		{"cert.p12", true},
		{"cert.pfx", true},
		{"cert.jks", true},
		{"key.key", true},
		{"key.priv", true},
		{"key.pub", true},
		{"file.class", false},
		{"file.jar", false},
		{"file.txt", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := isCryptoFile(tc.path); got != tc.want {
				t.Errorf("isCryptoFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// helpers -------------------------------------------------------------------

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOfString(s, sub) >= 0)
}

func indexOfString(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func byteKey(i int) string {
	return "entry_" + intToStr(i) + ".txt"
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
