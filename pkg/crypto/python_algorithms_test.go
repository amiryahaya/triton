package crypto

import "testing"

func TestLookupPythonCrypto_StdlibHashlib(t *testing.T) {
	entry, ok := LookupPythonCrypto("hashlib.sha256")
	if !ok {
		t.Fatal("hashlib.sha256 not found in registry")
	}
	if entry.Algorithm != "SHA-256" {
		t.Errorf("got algorithm %q, want SHA-256", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_StdlibMD5(t *testing.T) {
	entry, ok := LookupPythonCrypto("hashlib.md5")
	if !ok {
		t.Fatal("hashlib.md5 not found in registry")
	}
	if entry.Algorithm != "MD5" {
		t.Errorf("got algorithm %q, want MD5", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_CryptographyAES(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.ciphers.algorithms.AES")
	if !ok {
		t.Fatal("cryptography AES not found in registry")
	}
	if entry.Algorithm != "AES" {
		t.Errorf("got algorithm %q, want AES", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_CryptographyRSA(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.asymmetric.rsa")
	if !ok {
		t.Fatal("cryptography RSA not found in registry")
	}
	if entry.Algorithm != "RSA" {
		t.Errorf("got algorithm %q, want RSA", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_CryptographyFernet(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.fernet.Fernet")
	if !ok {
		t.Fatal("cryptography Fernet not found in registry")
	}
	if entry.Algorithm != "AES-128-CBC" {
		t.Errorf("got algorithm %q, want AES-128-CBC", entry.Algorithm)
	}
	if entry.KeySize != 128 {
		t.Errorf("got key size %d, want 128", entry.KeySize)
	}
}

func TestLookupPythonCrypto_PycryptodomeAES(t *testing.T) {
	entry, ok := LookupPythonCrypto("Crypto.Cipher.AES")
	if !ok {
		t.Fatal("Crypto.Cipher.AES not found in registry")
	}
	if entry.Algorithm != "AES" {
		t.Errorf("got algorithm %q, want AES", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_CryptodomeNamespace(t *testing.T) {
	entry, ok := LookupPythonCrypto("Cryptodome.Cipher.AES")
	if !ok {
		t.Fatal("Cryptodome.Cipher.AES not found in registry (mirror namespace)")
	}
	if entry.Algorithm != "AES" {
		t.Errorf("got algorithm %q, want AES", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_PrefixMatch(t *testing.T) {
	// Importing the ec module itself — prefix match should return ECDSA.
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.asymmetric.ec")
	if !ok {
		t.Fatal("ec module prefix match not found")
	}
	if entry.Algorithm != "ECDSA" {
		t.Errorf("got algorithm %q, want ECDSA", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_Unknown(t *testing.T) {
	if _, ok := LookupPythonCrypto("flask.Flask"); ok {
		t.Error("expected lookup miss on flask.Flask")
	}
}

func TestLookupPythonCrypto_HmacNew(t *testing.T) {
	entry, ok := LookupPythonCrypto("hmac.new")
	if !ok {
		t.Fatal("hmac.new not found in registry")
	}
	if entry.Algorithm != "HMAC" {
		t.Errorf("got algorithm %q, want HMAC", entry.Algorithm)
	}
}

func TestLookupPythonCrypto_Ed25519(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.asymmetric.ed25519")
	if !ok {
		t.Fatal("ed25519 not found in registry")
	}
	if entry.Algorithm != "Ed25519" {
		t.Errorf("got algorithm %q, want Ed25519", entry.Algorithm)
	}
}
