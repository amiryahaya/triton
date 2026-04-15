package crypto

import "testing"

func TestLookupDotNetAlgorithm_BCLTypes(t *testing.T) {
	cases := map[string]struct {
		algo   string
		status PQCStatus
	}{
		"System.Security.Cryptography.RSACryptoServiceProvider": {"RSA", TRANSITIONAL},
		"System.Security.Cryptography.AesManaged":               {"AES", TRANSITIONAL},
		"System.Security.Cryptography.MD5CryptoServiceProvider": {"MD5", UNSAFE},
		"System.Security.Cryptography.DSACryptoServiceProvider": {"DSA", DEPRECATED},
		"System.Security.Cryptography.SHA256Managed":            {"SHA-256", TRANSITIONAL},
		"System.Security.Cryptography.TripleDES":                {"3DES", DEPRECATED},
		"System.Security.Cryptography.RC2CryptoServiceProvider": {"RC2", UNSAFE},
	}
	for input, want := range cases {
		got, ok := LookupDotNetAlgorithm(input)
		if !ok {
			t.Errorf("LookupDotNetAlgorithm(%q) returned !ok", input)
			continue
		}
		if got.Algorithm != want.algo {
			t.Errorf("Algorithm(%q) = %q, want %q", input, got.Algorithm, want.algo)
		}
		if got.Status != want.status {
			t.Errorf("Status(%q) = %v, want %v", input, got.Status, want.status)
		}
	}
}

func TestLookupDotNetAlgorithm_CAPIStrings(t *testing.T) {
	cases := []string{"BCRYPT_RSA_ALGORITHM", "BCRYPT_KYBER_ALGORITHM", "CALG_MD5"}
	for _, c := range cases {
		if _, ok := LookupDotNetAlgorithm(c); !ok {
			t.Errorf("missing CAPI/CNG entry %q", c)
		}
	}
}

func TestLookupDotNetAlgorithm_BouncyCastleNETPQC(t *testing.T) {
	cases := []string{
		"Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemKeyPairGenerator",
		"Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyPairGenerator",
	}
	for _, c := range cases {
		got, ok := LookupDotNetAlgorithm(c)
		if !ok {
			t.Errorf("missing BC.NET entry %q", c)
			continue
		}
		if got.Status != SAFE {
			t.Errorf("BC.NET PQC %q status = %v, want SAFE", c, got.Status)
		}
	}
}

func TestLookupDotNetAlgorithm_UnknownReturnsFalse(t *testing.T) {
	if _, ok := LookupDotNetAlgorithm("System.IO.File"); ok {
		t.Error("expected non-crypto type to return !ok")
	}
}
