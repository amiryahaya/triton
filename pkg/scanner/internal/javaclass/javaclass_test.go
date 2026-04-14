package javaclass

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalClassFile assembles a valid class file header + constant pool
// with one Utf8 entry "AES/GCM/NoPadding" and one String entry pointing to it.
// Used so tests don't need external javac.
func buildMinimalClassFile(t *testing.T, utf8Values []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	// Magic
	buf.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE})
	// Minor + major version (Java 11 = 55)
	binary.Write(&buf, binary.BigEndian, uint16(0))  // minor
	binary.Write(&buf, binary.BigEndian, uint16(55)) // major
	// constant_pool_count = utf8Values count + 1 (entries are 1-indexed, count = N+1)
	binary.Write(&buf, binary.BigEndian, uint16(len(utf8Values)+1))
	for _, s := range utf8Values {
		buf.WriteByte(1) // tag Utf8
		binary.Write(&buf, binary.BigEndian, uint16(len(s)))
		buf.WriteString(s)
	}
	// Remaining header fields — zeroed, enough for the parser to stop cleanly.
	// access_flags, this_class, super_class, interfaces_count, fields_count, methods_count, attributes_count
	for i := 0; i < 7; i++ {
		binary.Write(&buf, binary.BigEndian, uint16(0))
	}
	return buf.Bytes()
}

func TestParseClass_ExtractsUtf8Strings(t *testing.T) {
	data := buildMinimalClassFile(t, []string{"AES/GCM/NoPadding", "SHA-256", "RSA"})
	strs, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	want := map[string]bool{"AES/GCM/NoPadding": false, "SHA-256": false, "RSA": false}
	for _, s := range strs {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("missing expected string: %q", s)
		}
	}
}

func TestParseClass_RejectsBadMagic(t *testing.T) {
	_, err := ParseClass([]byte{0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("expected error on non-class magic")
	}
}

func TestParseClass_HandlesEmpty(t *testing.T) {
	_, err := ParseClass([]byte{})
	if err == nil {
		t.Error("expected error on empty input")
	}
}

func TestParseClass_RejectsTruncated(t *testing.T) {
	// Valid magic, claims 10 constant-pool entries but truncates after the header
	data := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55, 0, 10}
	_, err := ParseClass(data)
	if err == nil {
		t.Error("expected error on truncated constant pool")
	}
}

func TestScanJAR_ExtractsClassStrings(t *testing.T) {
	hits, err := ScanJAR("testdata/crypto.jar")
	if err != nil {
		t.Skipf("testdata/crypto.jar missing — run 'make javaclass-fixtures' to build: %v", err)
	}
	// Every string from every class in the JAR is returned with its class path.
	want := map[string]bool{"AES/GCM/NoPadding": false, "SHA-256": false, "RSA": false}
	for _, h := range hits {
		if _, ok := want[h.Value]; ok {
			want[h.Value] = true
		}
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("missing %q from crypto.jar scan", s)
		}
	}
}

func TestScanJAR_RejectsNonZIP(t *testing.T) {
	_, err := ScanJAR("javaclass.go") // source file, not a JAR
	if err == nil {
		t.Error("expected error scanning non-ZIP file")
	}
}

// TestScanJAR_RejectsZipBomb verifies readClassFromZip refuses a class entry
// whose declared UncompressedSize64 exceeds the per-entry cap. We temporarily
// lower maxDecompressedClass so the test doesn't have to produce a 256 MB
// fixture, then build a small JAR with a class entry slightly over the cap.
// A naive implementation would have ReadAll'd the whole thing.
func TestScanJAR_RejectsZipBomb(t *testing.T) {
	orig := maxDecompressedClass
	maxDecompressedClass = 512 // small cap for this test
	t.Cleanup(func() { maxDecompressedClass = orig })

	// Build a minimum-valid class payload larger than the test cap so the
	// UncompressedSize64 header will reflect that size when zip.Writer flushes.
	payload := buildMinimalClassFile(t, []string{"AES", "RSA"})
	// Pad with zero bytes so the uncompressed size exceeds the cap. The pad
	// lives past the constant-pool parser's reach, so ParseClass wouldn't
	// notice — but readClassFromZip should reject it before ParseClass runs.
	padded := append([]byte{}, payload...)
	padded = append(padded, bytes.Repeat([]byte{0}, 1024)...) // 1024 > 512 cap

	dir := t.TempDir()
	jarPath := filepath.Join(dir, "bomb.jar")
	jarFile, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(jarFile)
	w, err := zw.Create("Bomb.class")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(padded); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := jarFile.Close(); err != nil {
		t.Fatal(err)
	}

	// ScanJAR should succeed at the archive level (other entries still scan)
	// but return no hits — the bomb entry is skipped cleanly, not OOM'd.
	hits, err := ScanJAR(jarPath)
	if err != nil {
		t.Fatalf("ScanJAR returned error: %v", err)
	}
	for _, h := range hits {
		if h.ClassPath == "Bomb.class" {
			t.Errorf("expected Bomb.class to be rejected, got hit: %+v", h)
		}
	}
}

