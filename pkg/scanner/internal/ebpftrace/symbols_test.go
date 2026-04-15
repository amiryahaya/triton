package ebpftrace

import "testing"

func TestResolveNID_CommonNIDs(t *testing.T) {
	cases := map[int32]struct {
		algo   string
		family string
	}{
		672: {"SHA-256", "SHA"}, // NID_sha256
		673: {"SHA-384", "SHA"},
		674: {"SHA-512", "SHA"},
		418: {"AES", "AES"},     // NID_aes_128_cbc
		419: {"AES", "AES"},     // NID_aes_192_cbc
		420: {"AES", "AES"},     // NID_aes_256_cbc
		6:   {"RSA", "RSA"},     // NID_rsaEncryption
		116: {"DSA", "DSA"},     // NID_dsa
		408: {"ECDSA", "ECDSA"}, // NID_X9_62_prime256v1
		4:   {"MD5", "MD5"},
		64:  {"SHA-1", "SHA"},
	}
	for nid, want := range cases {
		info, ok := ResolveNID(nid)
		if !ok {
			t.Errorf("ResolveNID(%d) returned !ok", nid)
			continue
		}
		if info.Algorithm != want.algo {
			t.Errorf("nid %d: Algorithm = %q, want %q", nid, info.Algorithm, want.algo)
		}
		if info.Family != want.family {
			t.Errorf("nid %d: Family = %q, want %q", nid, info.Family, want.family)
		}
	}
}

func TestResolveNID_UnknownReturnsFalse(t *testing.T) {
	if _, ok := ResolveNID(999999); ok {
		t.Error("expected unknown NID to return !ok")
	}
}

func TestResolveKernelAlgo_Names(t *testing.T) {
	cases := map[string]struct {
		algo   string
		family string
	}{
		"sha256":       {"SHA-256", "SHA"},
		"sha1":         {"SHA-1", "SHA"},
		"md5":          {"MD5", "MD5"},
		"aes-cbc(aes)": {"AES", "AES"},
		"cbc(aes)":     {"AES", "AES"},
		"rsa":          {"RSA", "RSA"},
		"ecdsa":        {"ECDSA", "ECDSA"},
	}
	for name, want := range cases {
		info, ok := ResolveKernelAlgo(name)
		if !ok {
			t.Errorf("ResolveKernelAlgo(%q) returned !ok", name)
			continue
		}
		if info.Algorithm != want.algo {
			t.Errorf("%q: Algorithm = %q, want %q", name, info.Algorithm, want.algo)
		}
		if info.Family != want.family {
			t.Errorf("%q: Family = %q, want %q", name, info.Family, want.family)
		}
	}
}

func TestUprobeTargets_HasCoreSymbols(t *testing.T) {
	targets := UprobeTargets()
	want := []string{
		"RSA_generate_key_ex",
		"RSA_sign",
		"EC_KEY_generate_key",
		"SSL_CTX_new",
		"gnutls_cipher_init",
		"gnutls_hash_init",
		"PK11_CipherOp",
		"PK11_Digest",
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		seen[tg.SymbolName] = true
	}
	for _, s := range want {
		if !seen[s] {
			t.Errorf("missing uprobe target %q", s)
		}
	}
}
