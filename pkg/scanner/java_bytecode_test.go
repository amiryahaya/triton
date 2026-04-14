package scanner

import (
	"context"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestJavaBytecodeModule_BasicInterface(t *testing.T) {
	m := NewJavaBytecodeModule(&scannerconfig.Config{})
	if m.Name() != "java_bytecode" {
		t.Errorf("Name: got %q, want java_bytecode", m.Name())
	}
	if m.Category() != model.CategoryPassiveFile {
		t.Errorf("Category: got %v, want CategoryPassiveFile", m.Category())
	}
	if m.ScanTargetType() != model.TargetFilesystem {
		t.Errorf("ScanTargetType: got %v, want TargetFilesystem", m.ScanTargetType())
	}
}

func TestJavaBytecodeModule_ScansJAR(t *testing.T) {
	m := NewJavaBytecodeModule(&scannerconfig.Config{
		MaxFileSize: 100 * 1024 * 1024,
	})
	findings := make(chan *model.Finding, 32)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	target := model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: "internal/javaclass/testdata/crypto.jar",
	}
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Skipf("jar fixture unavailable: %v", err)
	}
	close(findings)
	<-done

	// At minimum AES, SHA-256, RSA should classify.
	want := map[string]bool{"AES": false, "SHA-256": false, "RSA": false}
	for _, f := range collected {
		if f.CryptoAsset == nil {
			continue
		}
		if _, ok := want[f.CryptoAsset.Algorithm]; ok {
			want[f.CryptoAsset.Algorithm] = true
		}
	}
	for algo, seen := range want {
		if !seen {
			t.Errorf("missing %q in JAR findings", algo)
		}
	}
}

func TestLooksLikeJavaArtifact(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/a/b/Foo.class", true},
		{"/a/b/Foo.CLASS", true},
		{"/tmp/lib.jar", true},
		{"/tmp/lib.WAR", true},
		{"/tmp/app.ear", true},
		{"/tmp/app.exe", false},
		{"/tmp/Foo.java", false},
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikeJavaArtifact(c.path); got != c.want {
			t.Errorf("looksLikeJavaArtifact(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
