package scanner

import (
	"context"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
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

// TestJavaBytecodeModule_DedupByLiteralNotAlgorithm ensures that two literals
// resolving to the same Algorithm but different Status (e.g. AES/GCM/NoPadding
// SAFE vs AES/ECB/NoPadding DEPRECATED) both emit findings — the dedup key is
// the literal, not the resolved algorithm name.
func TestJavaBytecodeModule_DedupByLiteralNotAlgorithm(t *testing.T) {
	m := NewJavaBytecodeModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 8)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	// Both literals lookup to "AES" via LookupJavaAlgorithm but carry
	// different Status — we must see two findings, not one.
	m.classifyAndEmit(context.Background(), "/fake/app.jar", "Foo.class",
		[]string{"AES/GCM/NoPadding", "AES/ECB/NoPadding"}, findings)
	close(findings)
	<-done

	if len(collected) != 2 {
		t.Fatalf("expected 2 findings (GCM + ECB), got %d", len(collected))
	}
	seenEvidence := map[string]bool{}
	for _, f := range collected {
		seenEvidence[f.Source.Evidence] = true
	}
	if !seenEvidence["Foo.class: AES/GCM/NoPadding"] {
		t.Error("missing AES/GCM/NoPadding finding")
	}
	if !seenEvidence["Foo.class: AES/ECB/NoPadding"] {
		t.Error("missing AES/ECB/NoPadding finding")
	}
}

// TestFunctionForFamily_PQCLatticeHashBased verifies that buildFinding populates
// Function for registry Family values "Lattice" and "Hash-Based" — the names
// actually used by pkg/crypto/oid_data_pqc.go and pkg/crypto/pqc.go. Previously
// functionForFamily only checked algorithm-specific names (ML-DSA, SLH-DSA),
// which the registry never emits, so all PQC findings had Function="".
func TestFunctionForFamily_PQCLatticeHashBased(t *testing.T) {
	if got := functionForFamily("Lattice"); got == "" {
		t.Error("functionForFamily(\"Lattice\") returned empty; want non-empty PQC label")
	}
	if got := functionForFamily("Hash-Based"); got == "" {
		t.Error("functionForFamily(\"Hash-Based\") returned empty; want non-empty PQC label")
	}
	// End-to-end through buildFinding for an ML-KEM-768 OID entry (Lattice).
	oid := "2.16.840.1.101.3.4.4.2"
	entry, ok := crypto.LookupOID(oid)
	if !ok {
		t.Fatalf("registry missing ML-KEM-768 OID %s", oid)
	}
	f := buildFinding("/tmp/foo.so", ".rodata", crypto.ClassifiedOID{
		FoundOID: crypto.FoundOID{OID: oid},
		Entry:    entry,
	})
	if f.CryptoAsset == nil || f.CryptoAsset.Function == "" {
		t.Errorf("ML-KEM-768 finding Function is empty; want PQC label")
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
