package cli

import (
	"bytes"
	"testing"
)

func TestLocateCLIMetadata_FindsHeaderInBuiltAssembly(t *testing.T) {
	asm := buildAssembly(t, fixtureAssembly{
		TypeRefs:    []TypeRef{{Namespace: "Foo", Name: "Bar"}},
		UserStrings: []string{"Hello"},
	})
	off, size, err := LocateCLIMetadata(bytes.NewReader(asm))
	if err != nil {
		t.Fatalf("LocateCLIMetadata: %v", err)
	}
	if size == 0 {
		t.Error("metadata size = 0")
	}
	if int(off)+4 > len(asm) {
		t.Fatal("metadata offset out of bounds")
	}
	if string(asm[off:off+4]) != "BSJB" {
		t.Errorf("metadata at offset %d does not start with BSJB", off)
	}
}

func TestLocateCLIMetadata_RejectsNonPE(t *testing.T) {
	if _, _, err := LocateCLIMetadata(bytes.NewReader([]byte("not a PE"))); err == nil {
		t.Error("expected error on non-PE input")
	}
}

func TestLocateCLIMetadata_RejectsPEWithoutCLI(t *testing.T) {
	asm := buildAssembly(t, fixtureAssembly{TypeRefs: []TypeRef{{Name: "X"}}})
	// CLI directory is at offset 64 + 4 + 20 + 96 + 14*8 = 296
	for i := 296; i < 304; i++ {
		asm[i] = 0
	}
	if _, _, err := LocateCLIMetadata(bytes.NewReader(asm)); err == nil {
		t.Error("expected error on PE without CLI directory")
	}
}
