package crypto

import "strings"

// DotNetAlgEntry is a classified .NET crypto API token.
type DotNetAlgEntry struct {
	Token     string
	Algorithm string
	Family    string
	Status    PQCStatus
}

// LookupDotNetAlgorithm classifies a token from a .NET assembly. The token may
// be a fully-qualified TypeRef name ("System.Security.Cryptography.X") or a
// CAPI/CNG / BCrypt string literal ("BCRYPT_RSA_ALGORITHM"). Lookup is
// case-sensitive for type names (matches CLR spec) and case-insensitive for
// constant strings.
func LookupDotNetAlgorithm(token string) (DotNetAlgEntry, bool) {
	if e, ok := dotnetRegistry[token]; ok {
		return e, true
	}
	if e, ok := dotnetRegistry[strings.ToUpper(token)]; ok {
		return e, true
	}
	return DotNetAlgEntry{}, false
}

var dotnetRegistry = buildDotNetRegistry()

func buildDotNetRegistry() map[string]DotNetAlgEntry {
	m := map[string]DotNetAlgEntry{}
	add := func(tokens []string, algo, family string, status PQCStatus) {
		for _, tk := range tokens {
			m[tk] = DotNetAlgEntry{Token: tk, Algorithm: algo, Family: family, Status: status}
		}
	}

	// --- BCL: System.Security.Cryptography.* (with common type-name variants) ---
	add([]string{
		"System.Security.Cryptography.RSACryptoServiceProvider",
		"System.Security.Cryptography.RSACng",
		"System.Security.Cryptography.RSA",
	}, "RSA", "RSA", TRANSITIONAL)
	add([]string{
		"System.Security.Cryptography.DSACryptoServiceProvider",
		"System.Security.Cryptography.DSACng",
		"System.Security.Cryptography.DSA",
	}, "DSA", "DSA", DEPRECATED)
	add([]string{
		"System.Security.Cryptography.ECDsa",
		"System.Security.Cryptography.ECDsaCng",
	}, "ECDSA", "ECDSA", TRANSITIONAL)
	add([]string{
		"System.Security.Cryptography.ECDiffieHellman",
		"System.Security.Cryptography.ECDiffieHellmanCng",
	}, "ECDH", "ECDH", TRANSITIONAL)
	add([]string{
		"System.Security.Cryptography.AesManaged",
		"System.Security.Cryptography.AesCryptoServiceProvider",
		"System.Security.Cryptography.AesCng",
		"System.Security.Cryptography.Aes",
	}, "AES", "AES", TRANSITIONAL)
	add([]string{
		"System.Security.Cryptography.AesGcm",
	}, "AES-GCM", "AES", SAFE)
	add([]string{
		"System.Security.Cryptography.AesCcm",
	}, "AES-CCM", "AES", SAFE)
	add([]string{
		"System.Security.Cryptography.ChaCha20Poly1305",
	}, "ChaCha20-Poly1305", "ChaCha", SAFE)
	add([]string{
		"System.Security.Cryptography.TripleDES",
		"System.Security.Cryptography.TripleDESCryptoServiceProvider",
		"System.Security.Cryptography.TripleDESCng",
	}, "3DES", "3DES", DEPRECATED)
	add([]string{
		"System.Security.Cryptography.DESCryptoServiceProvider",
	}, "DES", "DES", UNSAFE)
	add([]string{
		"System.Security.Cryptography.RC2CryptoServiceProvider",
	}, "RC2", "RC2", UNSAFE)

	// Hashes
	add([]string{
		"System.Security.Cryptography.MD5",
		"System.Security.Cryptography.MD5CryptoServiceProvider",
	}, "MD5", "MD5", UNSAFE)
	add([]string{
		"System.Security.Cryptography.SHA1",
		"System.Security.Cryptography.SHA1Managed",
		"System.Security.Cryptography.SHA1CryptoServiceProvider",
	}, "SHA-1", "SHA", DEPRECATED)
	add([]string{
		"System.Security.Cryptography.SHA256",
		"System.Security.Cryptography.SHA256Managed",
		"System.Security.Cryptography.SHA256CryptoServiceProvider",
	}, "SHA-256", "SHA", TRANSITIONAL)
	add([]string{
		"System.Security.Cryptography.SHA384",
		"System.Security.Cryptography.SHA384Managed",
		"System.Security.Cryptography.SHA384CryptoServiceProvider",
	}, "SHA-384", "SHA", SAFE)
	add([]string{
		"System.Security.Cryptography.SHA512",
		"System.Security.Cryptography.SHA512Managed",
		"System.Security.Cryptography.SHA512CryptoServiceProvider",
	}, "SHA-512", "SHA", SAFE)

	// HMAC / KDF
	add([]string{"System.Security.Cryptography.HMACMD5"}, "HMAC-MD5", "HMAC", UNSAFE)
	add([]string{"System.Security.Cryptography.HMACSHA1"}, "HMAC-SHA1", "HMAC", DEPRECATED)
	add([]string{"System.Security.Cryptography.HMACSHA256"}, "HMAC-SHA256", "HMAC", TRANSITIONAL)
	add([]string{"System.Security.Cryptography.HMACSHA384"}, "HMAC-SHA384", "HMAC", SAFE)
	add([]string{"System.Security.Cryptography.HMACSHA512"}, "HMAC-SHA512", "HMAC", SAFE)
	add([]string{"System.Security.Cryptography.Rfc2898DeriveBytes"}, "PBKDF2", "KDF", TRANSITIONAL)
	add([]string{"System.Security.Cryptography.PasswordDeriveBytes"}, "PBKDF1", "KDF", DEPRECATED)

	// RNG
	add([]string{
		"System.Security.Cryptography.RNGCryptoServiceProvider",
		"System.Security.Cryptography.RandomNumberGenerator",
	}, "RNG", "RNG", SAFE)

	// .NET 10 preview PQC types
	add([]string{
		"System.Security.Cryptography.MLKem",
		"System.Security.Cryptography.MLKem512",
		"System.Security.Cryptography.MLKem768",
		"System.Security.Cryptography.MLKem1024",
	}, "ML-KEM", "Lattice", SAFE)
	add([]string{
		"System.Security.Cryptography.MLDsa",
		"System.Security.Cryptography.MLDsa44",
		"System.Security.Cryptography.MLDsa65",
		"System.Security.Cryptography.MLDsa87",
	}, "ML-DSA", "Lattice", SAFE)
	add([]string{
		"System.Security.Cryptography.SlhDsa",
	}, "SLH-DSA", "Hash-Based", SAFE)

	// --- CAPI / CNG / BCrypt constants (string literals) ---
	add([]string{"BCRYPT_RSA_ALGORITHM"}, "RSA", "RSA", TRANSITIONAL)
	add([]string{"BCRYPT_RSA_SIGN_ALGORITHM"}, "RSA", "RSA", TRANSITIONAL)
	add([]string{"BCRYPT_DSA_ALGORITHM"}, "DSA", "DSA", DEPRECATED)
	add([]string{"BCRYPT_ECDSA_P256_ALGORITHM"}, "ECDSA-P256", "ECDSA", TRANSITIONAL)
	add([]string{"BCRYPT_ECDSA_P384_ALGORITHM"}, "ECDSA-P384", "ECDSA", SAFE)
	add([]string{"BCRYPT_ECDSA_P521_ALGORITHM"}, "ECDSA-P521", "ECDSA", SAFE)
	add([]string{"BCRYPT_ECDH_P256_ALGORITHM"}, "ECDH-P256", "ECDH", TRANSITIONAL)
	add([]string{"BCRYPT_ECDH_P384_ALGORITHM"}, "ECDH-P384", "ECDH", SAFE)
	add([]string{"BCRYPT_AES_ALGORITHM"}, "AES", "AES", TRANSITIONAL)
	add([]string{"BCRYPT_3DES_ALGORITHM"}, "3DES", "3DES", DEPRECATED)
	add([]string{"BCRYPT_DES_ALGORITHM"}, "DES", "DES", UNSAFE)
	add([]string{"BCRYPT_MD2_ALGORITHM"}, "MD2", "MD2", UNSAFE)
	add([]string{"BCRYPT_MD4_ALGORITHM"}, "MD4", "MD4", UNSAFE)
	add([]string{"BCRYPT_MD5_ALGORITHM"}, "MD5", "MD5", UNSAFE)
	add([]string{"BCRYPT_SHA1_ALGORITHM"}, "SHA-1", "SHA", DEPRECATED)
	add([]string{"BCRYPT_SHA256_ALGORITHM"}, "SHA-256", "SHA", TRANSITIONAL)
	add([]string{"BCRYPT_SHA384_ALGORITHM"}, "SHA-384", "SHA", SAFE)
	add([]string{"BCRYPT_SHA512_ALGORITHM"}, "SHA-512", "SHA", SAFE)
	add([]string{"BCRYPT_KYBER_ALGORITHM"}, "ML-KEM", "Lattice", SAFE)
	add([]string{"BCRYPT_MLDSA_ALGORITHM"}, "ML-DSA", "Lattice", SAFE)
	add([]string{"CALG_MD5"}, "MD5", "MD5", UNSAFE)
	add([]string{"CALG_SHA1"}, "SHA-1", "SHA", DEPRECATED)
	add([]string{"CALG_SHA_256"}, "SHA-256", "SHA", TRANSITIONAL)
	add([]string{"CALG_3DES"}, "3DES", "3DES", DEPRECATED)
	add([]string{"CALG_DES"}, "DES", "DES", UNSAFE)
	add([]string{"CALG_RC2"}, "RC2", "RC2", UNSAFE)
	add([]string{"CALG_RC4"}, "RC4", "RC4", UNSAFE)

	// --- BouncyCastle.NET PQC types ---
	add([]string{
		"Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemKeyPairGenerator",
		"Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemEngine",
	}, "ML-KEM", "Lattice", SAFE)
	add([]string{
		"Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyPairGenerator",
		"Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner",
	}, "ML-DSA", "Lattice", SAFE)
	add([]string{
		"Org.BouncyCastle.Pqc.Crypto.Falcon.FalconKeyPairGenerator",
	}, "FN-DSA", "Lattice", SAFE)
	add([]string{
		"Org.BouncyCastle.Pqc.Crypto.SphincsPlus.SphincsPlusKeyPairGenerator",
	}, "SLH-DSA", "Hash-Based", SAFE)

	return m
}
