package cli

import (
	"bytes"
	"testing"
)

func TestReadAssembly_ExtractsTypeRefsAndUserStrings(t *testing.T) {
	asm := buildAssembly(t, fixtureAssembly{
		TypeRefs: []TypeRef{
			{Namespace: "System.Security.Cryptography", Name: "RSACryptoServiceProvider"},
			{Namespace: "System.Security.Cryptography", Name: "AesManaged"},
		},
		UserStrings: []string{"AES-256-CBC", "BCRYPT_RSA_ALGORITHM"},
	})
	a, err := ReadAssembly(bytes.NewReader(asm))
	if err != nil {
		t.Fatalf("ReadAssembly: %v", err)
	}
	wantTypes := map[string]bool{
		"System.Security.Cryptography.RSACryptoServiceProvider": false,
		"System.Security.Cryptography.AesManaged":               false,
	}
	for _, tr := range a.TypeRefs {
		if _, ok := wantTypes[tr]; ok {
			wantTypes[tr] = true
		}
	}
	for tr, seen := range wantTypes {
		if !seen {
			t.Errorf("missing TypeRef %q", tr)
		}
	}
	wantStrings := map[string]bool{"AES-256-CBC": false, "BCRYPT_RSA_ALGORITHM": false}
	for _, s := range a.UserStrings {
		if _, ok := wantStrings[s]; ok {
			wantStrings[s] = true
		}
	}
	for s, seen := range wantStrings {
		if !seen {
			t.Errorf("missing UserString %q", s)
		}
	}
}

func TestReadAssembly_RejectsNonPE(t *testing.T) {
	if _, err := ReadAssembly(bytes.NewReader([]byte("definitely not a PE file"))); err == nil {
		t.Error("expected error on non-PE input")
	}
}

func TestReadAssembly_RejectsMalformedBSJB(t *testing.T) {
	asm := buildAssembly(t, fixtureAssembly{TypeRefs: []TypeRef{{Name: "X"}}})
	// Locate the BSJB signature and corrupt it.
	idx := bytes.Index(asm, []byte("BSJB"))
	if idx < 0 {
		t.Fatal("test fixture has no BSJB signature")
	}
	asm[idx] = 'X'
	if _, err := ReadAssembly(bytes.NewReader(asm)); err == nil {
		t.Error("expected error on corrupted BSJB signature")
	}
}
