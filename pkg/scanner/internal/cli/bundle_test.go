package cli

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildBundle synthesises a single-file bundle containing the given inner assemblies.
func buildBundle(t *testing.T, inner map[string][]byte) []byte {
	t.Helper()
	var bundle bytes.Buffer

	// Pad the host with some bytes so offsets are non-zero.
	bundle.Write(make([]byte, 256))

	type entry struct {
		path   string
		offset uint64
		size   uint64
	}
	entries := make([]entry, 0, len(inner))
	for path, data := range inner {
		entries = append(entries, entry{
			path:   path,
			offset: uint64(bundle.Len()),
			size:   uint64(len(data)),
		})
		bundle.Write(data)
	}

	// Manifest entries: offset(u64), size(u64), compressedSize(u64), type(u8), pathLen(u8), path[pathLen]
	manifestOff := uint64(bundle.Len())
	for _, e := range entries {
		binary.Write(&bundle, binary.LittleEndian, e.offset)
		binary.Write(&bundle, binary.LittleEndian, e.size)
		binary.Write(&bundle, binary.LittleEndian, uint64(0)) // compressedSize = 0
		bundle.WriteByte(1)                                   // type 1 = Assembly
		bundle.WriteByte(byte(len(e.path)))
		bundle.WriteString(e.path)
	}

	// BundleHeader
	hdrOff := uint64(bundle.Len())
	binary.Write(&bundle, binary.LittleEndian, uint32(6))           // major
	binary.Write(&bundle, binary.LittleEndian, uint32(0))           // minor
	binary.Write(&bundle, binary.LittleEndian, int32(len(entries))) // fileCount
	bundleID := "test-bundle"
	bundle.WriteByte(byte(len(bundleID)))
	bundle.WriteString(bundleID)
	bundle.Write(make([]byte, 32))
	binary.Write(&bundle, binary.LittleEndian, uint64(0))

	binary.Write(&bundle, binary.LittleEndian, hdrOff)

	// 16-byte SHA-256 prefix marker
	marker := []byte{
		0x8B, 0x17, 0xFF, 0x58, 0x9D, 0x19, 0xFA, 0x3A,
		0x4D, 0x2E, 0x6E, 0x7E, 0xCB, 0x55, 0x77, 0x59,
	}
	bundle.Write(marker)
	_ = manifestOff
	return bundle.Bytes()
}

func TestScanBundle_ExtractsInnerAssemblies(t *testing.T) {
	innerA := buildAssembly(t, fixtureAssembly{
		TypeRefs: []TypeRef{{Namespace: "Foo", Name: "Bar"}},
	})
	innerB := buildAssembly(t, fixtureAssembly{
		UserStrings: []string{"AES"},
	})
	bundle := buildBundle(t, map[string][]byte{
		"A.dll": innerA,
		"B.dll": innerB,
	})

	tmp := filepath.Join(t.TempDir(), "host.exe")
	if err := os.WriteFile(tmp, bundle, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ScanBundle(tmp)
	if err != nil {
		t.Fatalf("ScanBundle: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	pathsSeen := map[string]bool{}
	for _, ba := range got {
		pathsSeen[ba.Path] = true
	}
	for _, want := range []string{"A.dll", "B.dll"} {
		if !pathsSeen[want] {
			t.Errorf("missing inner assembly %q", want)
		}
	}
}

func TestScanBundle_ReturnsEmptyOnNonBundle(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(tmp, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ScanBundle(tmp)
	if err != nil {
		t.Errorf("ScanBundle on non-bundle: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0", len(got))
	}
}
