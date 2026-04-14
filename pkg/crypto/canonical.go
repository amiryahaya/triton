package crypto

// coreAlgorithmNames enumerates algorithm names whose PQC classification
// (Status) MUST be consistent across every registry that mentions them.
// Format-specific registry entries that reference names outside this set
// are NOT required to match algorithmRegistry — their Status is a
// registry-local concern (e.g. PKCS7 content types, PBE modes, SPNEGO).
//
// The intent is to catch bugs like "demoted ML-KEM-512 in pqc.go but
// forgot to update the Java registry's alias table" — a real drift risk
// on algorithms under active cryptanalysis — without demanding that every
// protocol OID also be classified as an algorithm.
var coreAlgorithmNames = []string{
	// NIST PQC (FIPS 203/204/205/206)
	"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
	"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
	"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s",
	"SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256f",
	"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256s",
	"SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256f",
	"FN-DSA-512", "FN-DSA-1024",

	// Hash-based stateful signatures
	"XMSS", "LMS",

	// Classical asymmetric
	"RSA", "DSA", "ECDSA", "Ed25519", "Ed448",
	"ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
	"X25519", "X448",

	// Classical symmetric
	"AES", "AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC",
	"ChaCha20-Poly1305",
	"3DES", "DES",

	// Hashes
	"SHA-256", "SHA-384", "SHA-512", "SHA-224",
	"SHA3-256", "SHA3-384", "SHA3-512", "SHA3-224",
	"SHA-1", "MD5", "MD4",
}
