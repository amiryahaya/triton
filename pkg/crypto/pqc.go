package crypto

import (
	"fmt"
	"sort"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// PQCStatus represents the post-quantum cryptography readiness level
type PQCStatus string

const (
	SAFE         PQCStatus = "SAFE"
	TRANSITIONAL PQCStatus = "TRANSITIONAL"
	DEPRECATED   PQCStatus = "DEPRECATED"
	UNSAFE       PQCStatus = "UNSAFE"
)

// AlgorithmInfo holds PQC classification for an algorithm
type AlgorithmInfo struct {
	Name         string
	Family       string
	KeySize      int
	Status       PQCStatus
	BreakYear    int  // Estimated year quantum computer could break it
	NISTStandard bool // Is this a NIST-approved PQC algorithm
}

// GetAlgorithmInfo returns the AlgorithmInfo for a named algorithm and whether it was found.
func GetAlgorithmInfo(name string) (AlgorithmInfo, bool) {
	info, ok := algorithmRegistry[name]
	return info, ok
}

// algorithmRegistry maps algorithm names to their PQC status.
var algorithmRegistry = map[string]AlgorithmInfo{
	// ===== SAFE algorithms (quantum-resistant) =====

	// AES-256 variants (Grover's halves to 128-bit — still safe)
	"AES-256-GCM": {Name: "AES-256-GCM", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},
	"AES-256-CBC": {Name: "AES-256-CBC", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},
	"AES-256-CTR": {Name: "AES-256-CTR", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},
	"AES-256-CCM": {Name: "AES-256-CCM", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},

	// AES-192 variants (Grover's halves to 96-bit — still safe)
	"AES-192-GCM": {Name: "AES-192-GCM", Family: "AES", KeySize: 192, Status: SAFE, NISTStandard: true},
	"AES-192-CBC": {Name: "AES-192-CBC", Family: "AES", KeySize: 192, Status: SAFE, NISTStandard: true},
	"AES-192-CTR": {Name: "AES-192-CTR", Family: "AES", KeySize: 192, Status: SAFE, NISTStandard: true},

	// Other symmetric ciphers (256-bit key — quantum safe)
	"ChaCha20-Poly1305": {Name: "ChaCha20-Poly1305", Family: "ChaCha20", KeySize: 256, Status: SAFE},
	"Camellia-256":      {Name: "Camellia-256", Family: "Camellia", KeySize: 256, Status: SAFE},
	"Twofish":           {Name: "Twofish", Family: "Twofish", KeySize: 256, Status: SAFE},
	"Serpent":           {Name: "Serpent", Family: "Serpent", KeySize: 256, Status: SAFE},
	"ARIA-256":          {Name: "ARIA-256", Family: "ARIA", KeySize: 256, Status: SAFE},

	// Large hashes (>256-bit output — quantum safe)
	"SHA-384":  {Name: "SHA-384", Family: "SHA2", KeySize: 384, Status: SAFE, NISTStandard: true},
	"SHA-512":  {Name: "SHA-512", Family: "SHA2", KeySize: 512, Status: SAFE, NISTStandard: true},
	"SHA3-256": {Name: "SHA3-256", Family: "SHA3", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SHA3-384": {Name: "SHA3-384", Family: "SHA3", KeySize: 384, Status: SAFE, NISTStandard: true},
	"SHA3-512": {Name: "SHA3-512", Family: "SHA3", KeySize: 512, Status: SAFE, NISTStandard: true},
	"BLAKE2b":  {Name: "BLAKE2b", Family: "BLAKE2", KeySize: 512, Status: SAFE},
	"BLAKE2s":  {Name: "BLAKE2s", Family: "BLAKE2", KeySize: 256, Status: SAFE},

	// MACs with >=256-bit key
	"HMAC-SHA256": {Name: "HMAC-SHA256", Family: "HMAC", KeySize: 256, Status: SAFE},
	"HMAC-SHA384": {Name: "HMAC-SHA384", Family: "HMAC", KeySize: 384, Status: SAFE},
	"HMAC-SHA512": {Name: "HMAC-SHA512", Family: "HMAC", KeySize: 512, Status: SAFE},
	"Poly1305":    {Name: "Poly1305", Family: "MAC", KeySize: 256, Status: SAFE},

	// Password hashing (symmetric — quantum safe)
	"Bcrypt": {Name: "Bcrypt", Family: "Password-Hash", KeySize: 0, Status: SAFE},
	"scrypt": {Name: "scrypt", Family: "KDF", KeySize: 0, Status: SAFE},
	"Argon2": {Name: "Argon2", Family: "KDF", KeySize: 0, Status: SAFE},
	"PBKDF2": {Name: "PBKDF2", Family: "KDF", KeySize: 0, Status: SAFE},
	"HKDF":   {Name: "HKDF", Family: "KDF", KeySize: 0, Status: SAFE},

	// NIST PQC standards
	"ML-KEM":  {Name: "ML-KEM", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"ML-DSA":  {Name: "ML-DSA", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"SLH-DSA": {Name: "SLH-DSA", Family: "Hash-Based", KeySize: 0, Status: SAFE, NISTStandard: true},

	// ML-KEM variants (FIPS 203)
	"ML-KEM-512":  {Name: "ML-KEM-512", Family: "Lattice", KeySize: 512, Status: SAFE, NISTStandard: true},
	"ML-KEM-768":  {Name: "ML-KEM-768", Family: "Lattice", KeySize: 768, Status: SAFE, NISTStandard: true},
	"ML-KEM-1024": {Name: "ML-KEM-1024", Family: "Lattice", KeySize: 1024, Status: SAFE, NISTStandard: true},

	// ML-DSA variants (FIPS 204)
	"ML-DSA-44": {Name: "ML-DSA-44", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"ML-DSA-65": {Name: "ML-DSA-65", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"ML-DSA-87": {Name: "ML-DSA-87", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},

	// SLH-DSA variants (FIPS 205) — sha2/shake x 128/192/256 x s/f
	"SLH-DSA-SHA2-128s":  {Name: "SLH-DSA-SHA2-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHA2-128f":  {Name: "SLH-DSA-SHA2-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHA2-192s":  {Name: "SLH-DSA-SHA2-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHA2-192f":  {Name: "SLH-DSA-SHA2-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHA2-256s":  {Name: "SLH-DSA-SHA2-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHA2-256f":  {Name: "SLH-DSA-SHA2-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHAKE-128s": {Name: "SLH-DSA-SHAKE-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHAKE-128f": {Name: "SLH-DSA-SHAKE-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHAKE-192s": {Name: "SLH-DSA-SHAKE-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHAKE-192f": {Name: "SLH-DSA-SHAKE-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHAKE-256s": {Name: "SLH-DSA-SHAKE-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SLH-DSA-SHAKE-256f": {Name: "SLH-DSA-SHAKE-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE, NISTStandard: true},

	// Hash-based signatures (stateful)
	"LMS":  {Name: "LMS", Family: "Hash-Based", KeySize: 0, Status: SAFE, NISTStandard: true},
	"XMSS": {Name: "XMSS", Family: "Hash-Based", KeySize: 0, Status: SAFE, NISTStandard: true},

	// Composite/Hybrid signatures (IETF LAMPS)
	"ML-DSA-44-RSA-2048":     {Name: "ML-DSA-44-RSA-2048", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-44-RSA-2048-PSS": {Name: "ML-DSA-44-RSA-2048-PSS", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-44-Ed25519":      {Name: "ML-DSA-44-Ed25519", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-44-ECDSA-P256":   {Name: "ML-DSA-44-ECDSA-P256", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-65-RSA-3072":     {Name: "ML-DSA-65-RSA-3072", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-65-RSA-3072-PSS": {Name: "ML-DSA-65-RSA-3072-PSS", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-65-RSA-4096":     {Name: "ML-DSA-65-RSA-4096", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-65-RSA-4096-PSS": {Name: "ML-DSA-65-RSA-4096-PSS", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-65-ECDSA-P384":   {Name: "ML-DSA-65-ECDSA-P384", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-65-Ed25519":      {Name: "ML-DSA-65-Ed25519", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-87-ECDSA-P384":   {Name: "ML-DSA-87-ECDSA-P384", Family: "Composite", KeySize: 0, Status: SAFE},
	"ML-DSA-87-Ed448":        {Name: "ML-DSA-87-Ed448", Family: "Composite", KeySize: 0, Status: SAFE},

	// Hybrid TLS key-exchange groups (classical ECDHE + PQ KEM).
	// Keyed by the canonical name emitted by LookupTLSGroup so ClassifyCryptoAsset
	// preserves SAFE status after protocol-scanner emission. IsHybrid/ComponentAlgorithms
	// are set upstream by tlsGroupToAsset and survive classification.
	"X25519MLKEM768":           {Name: "X25519MLKEM768", Family: "Composite", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SecP256r1MLKEM768":        {Name: "SecP256r1MLKEM768", Family: "Composite", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SecP384r1MLKEM1024":       {Name: "SecP384r1MLKEM1024", Family: "Composite", KeySize: 384, Status: SAFE, NISTStandard: true},
	"X25519Kyber768Draft00":    {Name: "X25519Kyber768Draft00", Family: "Composite", KeySize: 256, Status: SAFE},
	"SecP256r1Kyber768Draft00": {Name: "SecP256r1Kyber768Draft00", Family: "Composite", KeySize: 256, Status: SAFE},
	"X25519Kyber512Draft00":    {Name: "X25519Kyber512Draft00", Family: "Composite", KeySize: 256, Status: SAFE},
	"X25519Kyber768Draft00Old": {Name: "X25519Kyber768Draft00Old", Family: "Composite", KeySize: 256, Status: SAFE},
	"MLKEM512":                 {Name: "MLKEM512", Family: "Lattice", KeySize: 512, Status: SAFE, NISTStandard: true},
	"MLKEM768":                 {Name: "MLKEM768", Family: "Lattice", KeySize: 768, Status: SAFE, NISTStandard: true},
	"MLKEM1024":                {Name: "MLKEM1024", Family: "Lattice", KeySize: 1024, Status: SAFE, NISTStandard: true},

	// FN-DSA (FIPS 206)
	"FN-DSA":      {Name: "FN-DSA", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"FN-DSA-512":  {Name: "FN-DSA-512", Family: "Lattice", KeySize: 512, Status: SAFE, NISTStandard: true},
	"FN-DSA-1024": {Name: "FN-DSA-1024", Family: "Lattice", KeySize: 1024, Status: SAFE, NISTStandard: true},

	// Other PQC candidates
	"SPHINCS+":         {Name: "SPHINCS+", Family: "Hash-Based", KeySize: 0, Status: SAFE, NISTStandard: true},
	"FALCON":           {Name: "FN-DSA", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"FrodoKEM":         {Name: "FrodoKEM", Family: "Lattice", KeySize: 0, Status: SAFE},
	"BIKE":             {Name: "BIKE", Family: "Code-Based", KeySize: 0, Status: SAFE},
	"HQC":              {Name: "HQC", Family: "Code-Based", KeySize: 0, Status: SAFE},
	"Classic McEliece": {Name: "Classic McEliece", Family: "Code-Based", KeySize: 0, Status: SAFE},
	"NTRU":             {Name: "NTRU", Family: "Lattice", KeySize: 0, Status: SAFE},
	"SABER":            {Name: "SABER", Family: "Lattice", KeySize: 0, Status: SAFE},

	// Quantum-safe protocols
	"TLS 1.3":   {Name: "TLS 1.3", Family: "TLS", KeySize: 0, Status: SAFE},
	"WireGuard": {Name: "WireGuard", Family: "VPN", KeySize: 0, Status: SAFE},
	"QUIC":      {Name: "QUIC", Family: "Transport", KeySize: 0, Status: SAFE},

	// ===== TRANSITIONAL algorithms (need migration plan) =====

	// AES (generic, no key size specified — conservative classification)
	"AES": {Name: "AES", Family: "AES", KeySize: 0, Status: TRANSITIONAL, NISTStandard: true},

	// AES-128 (Grover's halves to 64-bit — borderline)
	"AES-128-GCM": {Name: "AES-128-GCM", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},
	"AES-128-CBC": {Name: "AES-128-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},
	"AES-128-CTR": {Name: "AES-128-CTR", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},
	"AES-128-CCM": {Name: "AES-128-CCM", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},

	// Hashes (128-bit collision resistance under Grover's)
	"SHA-256":  {Name: "SHA-256", Family: "SHA2", KeySize: 256, Status: TRANSITIONAL, NISTStandard: true},
	"SHA-224":  {Name: "SHA-224", Family: "SHA2", KeySize: 224, Status: TRANSITIONAL, NISTStandard: true},
	"SHA3-224": {Name: "SHA3-224", Family: "SHA3", KeySize: 224, Status: TRANSITIONAL, NISTStandard: true},

	// MACs with <256-bit security under quantum
	"HMAC-SHA1": {Name: "HMAC-SHA1", Family: "HMAC", KeySize: 160, Status: TRANSITIONAL},
	"CMAC":      {Name: "CMAC", Family: "MAC", KeySize: 128, Status: TRANSITIONAL},
	"SipHash":   {Name: "SipHash", Family: "MAC", KeySize: 128, Status: TRANSITIONAL},

	// RSA (all sizes Shor-vulnerable — CNSA 2.0)
	"RSA-2048": {Name: "RSA-2048", Family: "RSA", KeySize: 2048, Status: TRANSITIONAL, BreakYear: 2035},
	"RSA-3072": {Name: "RSA-3072", Family: "RSA", KeySize: 3072, Status: TRANSITIONAL, BreakYear: 2040},
	"RSA-4096": {Name: "RSA-4096", Family: "RSA", KeySize: 4096, Status: TRANSITIONAL, BreakYear: 2045},
	"RSA-8192": {Name: "RSA-8192", Family: "RSA", KeySize: 8192, Status: TRANSITIONAL, BreakYear: 2050},

	// ECC (Shor-vulnerable)
	"ECDSA-P256": {Name: "ECDSA-P256", Family: "ECDSA", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2030},
	"ECDSA-P384": {Name: "ECDSA-P384", Family: "ECDSA", KeySize: 384, Status: TRANSITIONAL, BreakYear: 2035},
	"ECDSA-P521": {Name: "ECDSA-P521", Family: "ECDSA", KeySize: 521, Status: TRANSITIONAL, BreakYear: 2040},
	"Ed25519":    {Name: "Ed25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2035},
	"Ed448":      {Name: "Ed448", Family: "EdDSA", KeySize: 448, Status: TRANSITIONAL, BreakYear: 2040},
	"X25519":     {Name: "X25519", Family: "ECDH", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2035},
	"X448":       {Name: "X448", Family: "ECDH", KeySize: 448, Status: TRANSITIONAL, BreakYear: 2040},

	// Lowercase-IANA aliases for tlsGroupRegistry entries X25519 / X448.
	// These let ClassifyCryptoAsset and downstream consumers resolve the
	// IANA-form name (as emitted by LookupTLSGroup / nginx ssl_ecdh_curve
	// directives) to the same Status as the canonical uppercase name above.
	// Status intentionally mirrors the uppercase entry (Shor-vulnerable);
	// the tlsGroupRegistry entries share this classification.
	"x25519": {Name: "X25519", Family: "ECDH", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2035},
	"x448":   {Name: "X448", Family: "ECDH", KeySize: 448, Status: TRANSITIONAL, BreakYear: 2040},

	// ECDSA (generic, no curve specified)
	"ECDSA": {Name: "ECDSA", Family: "ECDSA", KeySize: 0, Status: TRANSITIONAL, BreakYear: 2030},
	// RSA (generic, no key size specified)
	"RSA": {Name: "RSA", Family: "RSA", KeySize: 0, Status: TRANSITIONAL, BreakYear: 2035},

	// DH (Shor-vulnerable)
	"DH":      {Name: "DH", Family: "DH", KeySize: 0, Status: TRANSITIONAL, BreakYear: 2035},
	"ElGamal": {Name: "ElGamal", Family: "ElGamal", KeySize: 0, Status: TRANSITIONAL, BreakYear: 2035},

	// 128-bit symmetric ciphers
	"Camellia-128": {Name: "Camellia-128", Family: "Camellia", KeySize: 128, Status: TRANSITIONAL},
	"ARIA-128":     {Name: "ARIA-128", Family: "ARIA", KeySize: 128, Status: TRANSITIONAL},
	"SM4":          {Name: "SM4", Family: "SM4", KeySize: 128, Status: TRANSITIONAL},
	"SEED":         {Name: "SEED", Family: "SEED", KeySize: 128, Status: TRANSITIONAL},
	"Salsa20":      {Name: "Salsa20", Family: "Salsa20", KeySize: 256, Status: TRANSITIONAL}, // Conservative: superseded by ChaCha20, less analysis

	// Transitional protocols
	"TLS 1.2": {Name: "TLS 1.2", Family: "TLS", KeySize: 0, Status: TRANSITIONAL},
	"SSH":     {Name: "SSH", Family: "SSH", KeySize: 0, Status: TRANSITIONAL},
	"DTLS":    {Name: "DTLS", Family: "TLS", KeySize: 0, Status: TRANSITIONAL},
	"IPsec":   {Name: "IPsec", Family: "VPN", KeySize: 0, Status: TRANSITIONAL},

	// SM3 (Chinese standard hash)
	"SM3": {Name: "SM3", Family: "SM3", KeySize: 256, Status: TRANSITIONAL},

	// ===== DEPRECATED algorithms (replace soon) =====

	"RSA-1024":   {Name: "RSA-1024", Family: "RSA", KeySize: 1024, Status: DEPRECATED, BreakYear: 2025},
	"DSA":        {Name: "DSA", Family: "DSA", KeySize: 0, Status: DEPRECATED, BreakYear: 2025},
	"ECDSA-P192": {Name: "ECDSA-P192", Family: "ECDSA", KeySize: 192, Status: DEPRECATED, BreakYear: 2025},
	"SHA-1":      {Name: "SHA-1", Family: "SHA1", KeySize: 160, Status: DEPRECATED, BreakYear: 2025},
	"MD5":        {Name: "MD5", Family: "MD5", KeySize: 128, Status: DEPRECATED, BreakYear: 2020},
	"3DES":       {Name: "3DES", Family: "DES", KeySize: 168, Status: DEPRECATED, BreakYear: 2025},
	"Blowfish":   {Name: "Blowfish", Family: "Blowfish", KeySize: 128, Status: DEPRECATED, BreakYear: 2025},
	"CAST5":      {Name: "CAST5", Family: "CAST5", KeySize: 128, Status: DEPRECATED, BreakYear: 2025},
	"IDEA":       {Name: "IDEA", Family: "IDEA", KeySize: 128, Status: DEPRECATED, BreakYear: 2025},
	"RIPEMD-160": {Name: "RIPEMD-160", Family: "RIPEMD", KeySize: 160, Status: DEPRECATED, BreakYear: 2025},
	"Whirlpool":  {Name: "Whirlpool", Family: "Whirlpool", KeySize: 512, Status: DEPRECATED},
	"Tiger":      {Name: "Tiger", Family: "Tiger", KeySize: 192, Status: DEPRECATED},
	"HMAC-MD5":   {Name: "HMAC-MD5", Family: "HMAC", KeySize: 128, Status: DEPRECATED, BreakYear: 2020},

	// Deprecated protocols
	"TLS 1.1": {Name: "TLS 1.1", Family: "TLS", KeySize: 0, Status: DEPRECATED},
	"TLS 1.0": {Name: "TLS 1.0", Family: "TLS", KeySize: 0, Status: DEPRECATED},

	// ===== UNSAFE algorithms (immediate action required) =====

	"DES":  {Name: "DES", Family: "DES", KeySize: 56, Status: UNSAFE, BreakYear: 2000},
	"RC4":  {Name: "RC4", Family: "RC4", KeySize: 0, Status: UNSAFE, BreakYear: 2015},
	"RC2":  {Name: "RC2", Family: "RC2", KeySize: 0, Status: UNSAFE, BreakYear: 2010},
	"MD4":  {Name: "MD4", Family: "MD4", KeySize: 128, Status: UNSAFE, BreakYear: 2005},
	"MD2":  {Name: "MD2", Family: "MD2", KeySize: 128, Status: UNSAFE, BreakYear: 2005},
	"NULL": {Name: "NULL", Family: "NULL", KeySize: 0, Status: UNSAFE, BreakYear: 0},

	// Sub-1024 RSA — factorable
	"RSA-512":  {Name: "RSA-512", Family: "RSA", KeySize: 512, Status: UNSAFE, BreakYear: 2010},
	"RSA-768":  {Name: "RSA-768", Family: "RSA", KeySize: 768, Status: UNSAFE, BreakYear: 2015},
	"RSA-1000": {Name: "RSA-1000", Family: "RSA", KeySize: 1000, Status: DEPRECATED, BreakYear: 2025},

	// Unsafe protocols
	"SSL 2.0": {Name: "SSL 2.0", Family: "SSL", KeySize: 0, Status: UNSAFE, BreakYear: 2010},
	"SSL 3.0": {Name: "SSL 3.0", Family: "SSL", KeySize: 0, Status: UNSAFE, BreakYear: 2015},
}

// normalizedMap provides O(1) lookup by normalized algorithm name.
var normalizedMap map[string]AlgorithmInfo

// normalizedRegistry is a sorted lookup table for substring matching.
// Sorted by normalized name length descending so longer (more specific) names match first.
var normalizedRegistry []normalizedEntry

type normalizedEntry struct {
	normalized string
	info       AlgorithmInfo
}

// familyRule maps a normalized prefix to a classification.
// Checked after normalizedMap but before substring scan.
type familyRule struct {
	prefix string
	info   AlgorithmInfo
}

// familyRules catch algorithm variants by prefix (e.g., "AES256" → SAFE).
// Order matters: longer prefixes should come first.
var familyRules []familyRule

func init() {
	// Build O(1) normalized map
	normalizedMap = make(map[string]AlgorithmInfo, len(algorithmRegistry))
	for name, info := range algorithmRegistry {
		norm := normalizeAlgo(name)
		normalizedMap[norm] = info
	}

	// Build sorted list for substring matching
	for name, info := range algorithmRegistry {
		norm := normalizeAlgo(name)
		normalizedRegistry = append(normalizedRegistry, normalizedEntry{
			normalized: norm,
			info:       info,
		})
	}
	// Sort by length descending — longer patterns are more specific and should match first.
	// Secondary sort alphabetically for deterministic ordering among same-length entries.
	sort.Slice(normalizedRegistry, func(i, j int) bool {
		li, lj := len(normalizedRegistry[i].normalized), len(normalizedRegistry[j].normalized)
		if li != lj {
			return li > lj
		}
		return normalizedRegistry[i].normalized < normalizedRegistry[j].normalized
	})

	// Build family prefix rules — catch hundreds of variants with ~30 rules.
	// Sorted longest-first so "AES256GCM" matches before "AES256".
	familyRules = []familyRule{
		// AES-256 modes → SAFE
		{prefix: "AES256GCM", info: AlgorithmInfo{Name: "AES-256-GCM", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true}},
		{prefix: "AES256CBC", info: AlgorithmInfo{Name: "AES-256-CBC", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true}},
		{prefix: "AES256CTR", info: AlgorithmInfo{Name: "AES-256-CTR", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true}},
		{prefix: "AES256CCM", info: AlgorithmInfo{Name: "AES-256-CCM", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true}},
		{prefix: "AES256", info: AlgorithmInfo{Name: "AES-256", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true}},

		// AES-192 modes → SAFE
		{prefix: "AES192", info: AlgorithmInfo{Name: "AES-192", Family: "AES", KeySize: 192, Status: SAFE, NISTStandard: true}},

		// AES-128 modes → TRANSITIONAL
		{prefix: "AES128GCM", info: AlgorithmInfo{Name: "AES-128-GCM", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true}},
		{prefix: "AES128CBC", info: AlgorithmInfo{Name: "AES-128-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true}},
		{prefix: "AES128CTR", info: AlgorithmInfo{Name: "AES-128-CTR", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true}},
		{prefix: "AES128", info: AlgorithmInfo{Name: "AES-128", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true}},

		// RSA variants
		{prefix: "RSA8192", info: AlgorithmInfo{Name: "RSA-8192", Family: "RSA", KeySize: 8192, Status: TRANSITIONAL, BreakYear: 2050}},
		{prefix: "RSA4096", info: AlgorithmInfo{Name: "RSA-4096", Family: "RSA", KeySize: 4096, Status: TRANSITIONAL, BreakYear: 2045}},
		{prefix: "RSA3072", info: AlgorithmInfo{Name: "RSA-3072", Family: "RSA", KeySize: 3072, Status: TRANSITIONAL, BreakYear: 2040}},
		{prefix: "RSA2048", info: AlgorithmInfo{Name: "RSA-2048", Family: "RSA", KeySize: 2048, Status: TRANSITIONAL, BreakYear: 2035}},
		{prefix: "RSA1024", info: AlgorithmInfo{Name: "RSA-1024", Family: "RSA", KeySize: 1024, Status: DEPRECATED, BreakYear: 2025}},
		{prefix: "RSA1000", info: AlgorithmInfo{Name: "RSA-1000", Family: "RSA", KeySize: 1000, Status: DEPRECATED, BreakYear: 2025}},
		{prefix: "RSA768", info: AlgorithmInfo{Name: "RSA-768", Family: "RSA", KeySize: 768, Status: UNSAFE, BreakYear: 2015}},
		{prefix: "RSA512", info: AlgorithmInfo{Name: "RSA-512", Family: "RSA", KeySize: 512, Status: UNSAFE, BreakYear: 2010}},

		// ECDSA variants
		{prefix: "ECDSAP521", info: AlgorithmInfo{Name: "ECDSA-P521", Family: "ECDSA", KeySize: 521, Status: TRANSITIONAL, BreakYear: 2040}},
		{prefix: "ECDSAP384", info: AlgorithmInfo{Name: "ECDSA-P384", Family: "ECDSA", KeySize: 384, Status: TRANSITIONAL, BreakYear: 2035}},
		{prefix: "ECDSAP256", info: AlgorithmInfo{Name: "ECDSA-P256", Family: "ECDSA", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2030}},
		{prefix: "ECDSAP192", info: AlgorithmInfo{Name: "ECDSA-P192", Family: "ECDSA", KeySize: 192, Status: DEPRECATED, BreakYear: 2025}},

		// SHA variants
		{prefix: "SHA3512", info: AlgorithmInfo{Name: "SHA3-512", Family: "SHA3", KeySize: 512, Status: SAFE, NISTStandard: true}},
		{prefix: "SHA3384", info: AlgorithmInfo{Name: "SHA3-384", Family: "SHA3", KeySize: 384, Status: SAFE, NISTStandard: true}},
		{prefix: "SHA3256", info: AlgorithmInfo{Name: "SHA3-256", Family: "SHA3", KeySize: 256, Status: SAFE, NISTStandard: true}},
		{prefix: "SHA3224", info: AlgorithmInfo{Name: "SHA3-224", Family: "SHA3", KeySize: 224, Status: TRANSITIONAL, NISTStandard: true}},
		{prefix: "SHA512", info: AlgorithmInfo{Name: "SHA-512", Family: "SHA2", KeySize: 512, Status: SAFE, NISTStandard: true}},
		{prefix: "SHA384", info: AlgorithmInfo{Name: "SHA-384", Family: "SHA2", KeySize: 384, Status: SAFE, NISTStandard: true}},
		{prefix: "SHA256", info: AlgorithmInfo{Name: "SHA-256", Family: "SHA2", KeySize: 256, Status: TRANSITIONAL, NISTStandard: true}},
		{prefix: "SHA224", info: AlgorithmInfo{Name: "SHA-224", Family: "SHA2", KeySize: 224, Status: TRANSITIONAL, NISTStandard: true}},

		// HMAC variants
		{prefix: "HMACSHA512", info: AlgorithmInfo{Name: "HMAC-SHA512", Family: "HMAC", KeySize: 512, Status: SAFE}},
		{prefix: "HMACSHA384", info: AlgorithmInfo{Name: "HMAC-SHA384", Family: "HMAC", KeySize: 384, Status: SAFE}},
		{prefix: "HMACSHA256", info: AlgorithmInfo{Name: "HMAC-SHA256", Family: "HMAC", KeySize: 256, Status: SAFE}},
		{prefix: "HMACSHA1", info: AlgorithmInfo{Name: "HMAC-SHA1", Family: "HMAC", KeySize: 160, Status: TRANSITIONAL}},
		{prefix: "HMACMD5", info: AlgorithmInfo{Name: "HMAC-MD5", Family: "HMAC", KeySize: 128, Status: DEPRECATED, BreakYear: 2020}},

		// DES/3DES variants
		{prefix: "TRIPLEDES", info: AlgorithmInfo{Name: "3DES", Family: "DES", KeySize: 168, Status: DEPRECATED, BreakYear: 2025}},
		{prefix: "DESEDE3", info: AlgorithmInfo{Name: "3DES", Family: "DES", KeySize: 168, Status: DEPRECATED, BreakYear: 2025}},
		{prefix: "DESCBC", info: AlgorithmInfo{Name: "DES", Family: "DES", KeySize: 56, Status: UNSAFE, BreakYear: 2000}},
		{prefix: "DESECB", info: AlgorithmInfo{Name: "DES", Family: "DES", KeySize: 56, Status: UNSAFE, BreakYear: 2000}},
	}
}

// normalizeAlgo uppercases and strips hyphens/underscores/spaces for fuzzy matching.
func normalizeAlgo(s string) string {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// ClassifyAlgorithm determines the PQC status of a cryptographic algorithm.
// 5-tier lookup: exact map → key-size variant → normalized map → family prefix → substring.
func ClassifyAlgorithm(algorithm string, keySize int) AlgorithmInfo {
	// Tier 1: Exact match (fastest path)
	if info, ok := algorithmRegistry[algorithm]; ok {
		return info
	}

	// Tier 1b: Try family-keySize variant when exact match fails and keySize is provided
	if keySize > 0 {
		variant := fmt.Sprintf("%s-%d", algorithm, keySize)
		if info, ok := algorithmRegistry[variant]; ok {
			return info
		}
	}

	// Tier 2: Normalized exact match (e.g., "aes_256_gcm" → "AES256GCM")
	alg := normalizeAlgo(algorithm)
	if info, ok := normalizedMap[alg]; ok {
		return info
	}

	// Tier 3: Family prefix rules (e.g., "AES256WRAP" → AES-256 SAFE)
	for _, rule := range familyRules {
		if strings.HasPrefix(alg, rule.prefix) {
			return rule.info
		}
	}

	// Tier 4: Substring match — longest match first (deterministic, sorted order)
	for _, entry := range normalizedRegistry {
		if strings.Contains(alg, entry.normalized) {
			return entry.info
		}
	}

	// Unknown algorithm — mark as transitional (conservative)
	return AlgorithmInfo{
		Name:   algorithm,
		Status: TRANSITIONAL,
	}
}

// GetMigrationPriority returns a priority score for migration (higher = more urgent)
func GetMigrationPriority(info AlgorithmInfo) int {
	switch info.Status {
	case UNSAFE:
		return 100
	case DEPRECATED:
		return 75
	case TRANSITIONAL:
		return 50
	case SAFE:
		return 0
	default:
		return 25
	}
}

// ClassifyCryptoAsset fills PQCStatus, MigrationPriority, BreakYear, and compliance fields on a CryptoAsset.
func ClassifyCryptoAsset(asset *model.CryptoAsset) {
	info := ClassifyAlgorithm(asset.Algorithm, asset.KeySize)
	// Normalize to canonical name when confidently matched (Family != "" means it's not an unknown fallback)
	if info.Name != "" && info.Family != "" {
		asset.Algorithm = info.Name
	}
	asset.PQCStatus = string(info.Status)
	asset.MigrationPriority = GetMigrationPriority(info)
	asset.BreakYear = info.BreakYear

	// Compliance — reuse already-computed AlgorithmInfo to avoid double ClassifyAlgorithm
	ci := getComplianceWithInfo(asset.Algorithm, info)
	asset.CNSA2Status = ci.CNSA2Status
	asset.NISTDeprecatedYear = ci.NISTDeprecatedYear
	asset.NISTDisallowedYear = ci.NISTDisallowedYear
	asset.ComplianceWarning = ci.Warning

	// NACSA label — reuse compliance info to avoid double GetCompliance call
	nacsa := AssessNACSAWithCompliance(asset, ci)
	asset.NACSALabel = string(nacsa.Label)
}
