package crypto

import "strings"

// JavaAlgEntry is a classified Java crypto API literal.
type JavaAlgEntry struct {
	Literal   string // Original string as it appears in the constant pool
	Algorithm string // Canonical algorithm name (matches crypto registry conventions)
	Family    string
	Status    PQCStatus
}

// javaAlgorithmRegistry maps literal strings found in Java constant pools
// (JCA standard names + common BouncyCastle / PQC provider names) to
// classified metadata. The key is lowercased + whitespace-trimmed for
// case-insensitive match semantics.
//
// Reference: Oracle JCA Standard Algorithm Names
// (https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html)
// and BouncyCastle / BC-FIPS / BC-PQC provider documentation.
var javaAlgorithmRegistry = buildJavaAlgRegistry()

// LookupJavaAlgorithm does a case-insensitive lookup of a Java crypto
// literal. Returns the classified entry + ok=true when the literal is
// recognized. Literals that start with "AES/", "RSA/", etc. are matched
// against their prefix to capture cipher-transformation strings.
func LookupJavaAlgorithm(literal string) (JavaAlgEntry, bool) {
	key := strings.ToLower(strings.TrimSpace(literal))
	if e, ok := javaAlgorithmRegistry[key]; ok {
		return e, true
	}
	// Prefix match for cipher transformations: "AES/GCM/NoPadding" etc.
	if slash := strings.Index(key, "/"); slash > 0 {
		prefix := key[:slash]
		if e, ok := javaAlgorithmRegistry[prefix]; ok {
			// Preserve original literal in the returned entry for attribution.
			e.Literal = literal
			// Promote mode/padding hint to Status refinement where appropriate.
			if strings.Contains(key, "/gcm/") || strings.Contains(key, "/ccm/") {
				if e.Status == TRANSITIONAL {
					e.Status = SAFE
				}
			}
			// ECB downgrade applies to block ciphers only; RSA/ECB in JCA is
			// a nomenclature artifact and does not carry the ECB block-mode risk.
			if strings.Contains(key, "/ecb/") && prefix != "rsa" {
				if e.Status == TRANSITIONAL {
					e.Status = DEPRECATED
				}
			}
			return e, true
		}
	}
	return JavaAlgEntry{}, false
}

func buildJavaAlgRegistry() map[string]JavaAlgEntry {
	m := map[string]JavaAlgEntry{}
	add := func(literals []string, algo, family string, status PQCStatus) {
		for _, l := range literals {
			key := strings.ToLower(l)
			m[key] = JavaAlgEntry{
				Literal: l, Algorithm: algo, Family: family, Status: status,
			}
		}
	}

	// --- Symmetric ciphers (Cipher.getInstance keys) ---
	add([]string{"AES", "AES_128", "AES_192", "AES_256"}, "AES", "AES", TRANSITIONAL)
	add([]string{"DES"}, "DES", "DES", UNSAFE)
	add([]string{"DESede", "TripleDES"}, "3DES", "3DES", DEPRECATED)
	add([]string{"Blowfish"}, "Blowfish", "Blowfish", DEPRECATED)
	add([]string{"ChaCha20", "ChaCha20-Poly1305"}, "ChaCha20", "ChaCha", SAFE)
	add([]string{"RC2"}, "RC2", "RC2", UNSAFE)
	add([]string{"RC4", "ARCFOUR"}, "RC4", "RC4", UNSAFE)
	add([]string{"IDEA"}, "IDEA", "IDEA", DEPRECATED)

	// --- Asymmetric ---
	add([]string{"RSA"}, "RSA", "RSA", TRANSITIONAL)
	add([]string{"DSA"}, "DSA", "DSA", DEPRECATED)
	add([]string{"EC", "ECDSA", "ECDH"}, "ECDSA", "ECDSA", TRANSITIONAL)
	add([]string{"Ed25519", "EdDSA"}, "Ed25519", "EdDSA", TRANSITIONAL)
	add([]string{"Ed448"}, "Ed448", "EdDSA", TRANSITIONAL)
	add([]string{"DH", "DiffieHellman"}, "DH", "DH", TRANSITIONAL)
	add([]string{"X25519"}, "X25519", "ECDH", TRANSITIONAL)
	add([]string{"X448"}, "X448", "ECDH", TRANSITIONAL)

	// --- Hash functions ---
	add([]string{"MD2"}, "MD2", "MD2", UNSAFE)
	add([]string{"MD4"}, "MD4", "MD4", UNSAFE)
	add([]string{"MD5"}, "MD5", "MD5", DEPRECATED)
	add([]string{"SHA", "SHA-1", "SHA1"}, "SHA-1", "SHA", DEPRECATED)
	add([]string{"SHA-224", "SHA224"}, "SHA-224", "SHA", TRANSITIONAL)
	add([]string{"SHA-256", "SHA256"}, "SHA-256", "SHA", TRANSITIONAL)
	add([]string{"SHA-384", "SHA384"}, "SHA-384", "SHA", SAFE)
	add([]string{"SHA-512", "SHA512"}, "SHA-512", "SHA", SAFE)
	add([]string{"SHA3-224"}, "SHA3-224", "SHA3", TRANSITIONAL)
	add([]string{"SHA3-256"}, "SHA3-256", "SHA3", SAFE)
	add([]string{"SHA3-384"}, "SHA3-384", "SHA3", SAFE)
	add([]string{"SHA3-512"}, "SHA3-512", "SHA3", SAFE)

	// --- Signature algorithms (JCA naming: <digest>with<key>) ---
	add([]string{"MD5withRSA"}, "MD5withRSA", "RSA", UNSAFE)
	add([]string{"SHA1withRSA"}, "SHA1withRSA", "RSA", DEPRECATED)
	add([]string{"SHA224withRSA"}, "SHA224withRSA", "RSA", TRANSITIONAL)
	add([]string{"SHA256withRSA"}, "SHA256withRSA", "RSA", TRANSITIONAL)
	add([]string{"SHA384withRSA"}, "SHA384withRSA", "RSA", SAFE)
	add([]string{"SHA512withRSA"}, "SHA512withRSA", "RSA", SAFE)
	add([]string{"SHA256withRSAandMGF1"}, "SHA256withRSA-PSS", "RSA", TRANSITIONAL)
	add([]string{"SHA1withDSA"}, "SHA1withDSA", "DSA", DEPRECATED)
	add([]string{"SHA256withDSA"}, "SHA256withDSA", "DSA", DEPRECATED)
	add([]string{"SHA1withECDSA"}, "SHA1withECDSA", "ECDSA", DEPRECATED)
	add([]string{"SHA256withECDSA"}, "SHA256withECDSA", "ECDSA", TRANSITIONAL)
	add([]string{"SHA384withECDSA"}, "SHA384withECDSA", "ECDSA", SAFE)
	add([]string{"SHA512withECDSA"}, "SHA512withECDSA", "ECDSA", SAFE)

	// --- MAC / KDF ---
	add([]string{"HmacMD5"}, "HMAC-MD5", "HMAC", UNSAFE)
	add([]string{"HmacSHA1"}, "HMAC-SHA1", "HMAC", DEPRECATED)
	add([]string{"HmacSHA256"}, "HMAC-SHA256", "HMAC", TRANSITIONAL)
	add([]string{"HmacSHA384"}, "HMAC-SHA384", "HMAC", SAFE)
	add([]string{"HmacSHA512"}, "HMAC-SHA512", "HMAC", SAFE)
	add([]string{"PBKDF2WithHmacSHA1"}, "PBKDF2-SHA1", "KDF", DEPRECATED)
	add([]string{"PBKDF2WithHmacSHA256"}, "PBKDF2-SHA256", "KDF", TRANSITIONAL)
	add([]string{"PBKDF2WithHmacSHA512"}, "PBKDF2-SHA512", "KDF", SAFE)

	// --- NIST PQC (BouncyCastle BCPQC provider names) ---
	add([]string{"ML-KEM-512", "MLKEM512", "KYBER512"}, "ML-KEM-512", "Lattice", SAFE)
	add([]string{"ML-KEM-768", "MLKEM768", "KYBER768"}, "ML-KEM-768", "Lattice", SAFE)
	add([]string{"ML-KEM-1024", "MLKEM1024", "KYBER1024"}, "ML-KEM-1024", "Lattice", SAFE)
	add([]string{"ML-DSA-44", "MLDSA44", "DILITHIUM2"}, "ML-DSA-44", "Lattice", SAFE)
	add([]string{"ML-DSA-65", "MLDSA65", "DILITHIUM3"}, "ML-DSA-65", "Lattice", SAFE)
	add([]string{"ML-DSA-87", "MLDSA87", "DILITHIUM5"}, "ML-DSA-87", "Lattice", SAFE)
	add([]string{"SLH-DSA-SHA2-128S", "SPHINCS+-SHA2-128S"}, "SLH-DSA-SHA2-128s", "Hash-Based", SAFE)
	add([]string{"SLH-DSA-SHA2-192S"}, "SLH-DSA-SHA2-192s", "Hash-Based", SAFE)
	add([]string{"SLH-DSA-SHA2-256S"}, "SLH-DSA-SHA2-256s", "Hash-Based", SAFE)
	add([]string{"FN-DSA-512", "FALCON-512"}, "FN-DSA-512", "Lattice", SAFE)
	add([]string{"FN-DSA-1024", "FALCON-1024"}, "FN-DSA-1024", "Lattice", SAFE)

	// --- BouncyCastle provider identification ---
	add([]string{"BC", "BouncyCastleProvider"}, "BouncyCastle", "Provider", TRANSITIONAL)
	add([]string{"BCFIPS", "BouncyCastleFipsProvider"}, "BouncyCastle-FIPS", "Provider", SAFE)
	add([]string{"BCPQC", "BouncyCastlePQCProvider"}, "BouncyCastle-PQC", "Provider", SAFE)

	return m
}
