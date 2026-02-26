package crypto

import (
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

// AlgorithmRegistry maps algorithm names to their PQC status
var AlgorithmRegistry = map[string]AlgorithmInfo{
	// SAFE algorithms (quantum-resistant)
	"AES-256-GCM":      {Name: "AES-256-GCM", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},
	"AES-256-CBC":      {Name: "AES-256-CBC", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},
	"AES-256-CTR":      {Name: "AES-256-CTR", Family: "AES", KeySize: 256, Status: SAFE, NISTStandard: true},
	"ChaCha20-Poly1305": {Name: "ChaCha20-Poly1305", Family: "ChaCha20", KeySize: 256, Status: SAFE},
	"Bcrypt":           {Name: "Bcrypt", Family: "Password-Hash", KeySize: 0, Status: SAFE},
	"SHA-384":     {Name: "SHA-384", Family: "SHA2", KeySize: 384, Status: SAFE, NISTStandard: true},
	"SHA-512":     {Name: "SHA-512", Family: "SHA2", KeySize: 512, Status: SAFE, NISTStandard: true},
	"SHA3-256":    {Name: "SHA3-256", Family: "SHA3", KeySize: 256, Status: SAFE, NISTStandard: true},
	"SHA3-384":    {Name: "SHA3-384", Family: "SHA3", KeySize: 384, Status: SAFE, NISTStandard: true},
	"RSA-4096":    {Name: "RSA-4096", Family: "RSA", KeySize: 4096, Status: SAFE, BreakYear: 2045},
	"ML-KEM":      {Name: "ML-KEM", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},
	"ML-DSA":      {Name: "ML-DSA", Family: "Lattice", KeySize: 0, Status: SAFE, NISTStandard: true},

	// TRANSITIONAL algorithms (need migration plan)
	"AES-128-GCM": {Name: "AES-128-GCM", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},
	"AES-128-CBC": {Name: "AES-128-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},
	"AES-128-CTR": {Name: "AES-128-CTR", Family: "AES", KeySize: 128, Status: TRANSITIONAL, NISTStandard: true},
	"SHA-256":     {Name: "SHA-256", Family: "SHA2", KeySize: 256, Status: TRANSITIONAL, NISTStandard: true},
	"RSA-2048":    {Name: "RSA-2048", Family: "RSA", KeySize: 2048, Status: TRANSITIONAL, BreakYear: 2035},
	"ECDSA-P256":  {Name: "ECDSA-P256", Family: "ECDSA", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2030},
	"ECDSA-P384":  {Name: "ECDSA-P384", Family: "ECDSA", KeySize: 384, Status: TRANSITIONAL, BreakYear: 2035},
	"Ed25519":     {Name: "Ed25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL, BreakYear: 2035},

	// DEPRECATED algorithms (replace soon)
	"RSA-1024":   {Name: "RSA-1024", Family: "RSA", KeySize: 1024, Status: DEPRECATED, BreakYear: 2025},
	"DSA":        {Name: "DSA", Family: "DSA", KeySize: 0, Status: DEPRECATED, BreakYear: 2025},
	"ECDSA-P192": {Name: "ECDSA-P192", Family: "ECDSA", KeySize: 192, Status: DEPRECATED, BreakYear: 2025},
	"SHA-1":      {Name: "SHA-1", Family: "SHA1", KeySize: 160, Status: DEPRECATED, BreakYear: 2025},
	"MD5":        {Name: "MD5", Family: "MD5", KeySize: 128, Status: DEPRECATED, BreakYear: 2020},
	"3DES":       {Name: "3DES", Family: "DES", KeySize: 168, Status: DEPRECATED, BreakYear: 2025},

	// UNSAFE algorithms (immediate action required)
	"DES":  {Name: "DES", Family: "DES", KeySize: 56, Status: UNSAFE, BreakYear: 2000},
	"RC4":  {Name: "RC4", Family: "RC4", KeySize: 0, Status: UNSAFE, BreakYear: 2015},
	"MD4":  {Name: "MD4", Family: "MD4", KeySize: 128, Status: UNSAFE, BreakYear: 2005},
	"NULL": {Name: "NULL", Family: "NULL", KeySize: 0, Status: UNSAFE, BreakYear: 0},
}

// normalizedRegistry is a sorted lookup table built from AlgorithmRegistry.
// Sorted by normalized name length descending so longer (more specific) names match first.
var normalizedRegistry []normalizedEntry

type normalizedEntry struct {
	normalized string
	info       AlgorithmInfo
}

func init() {
	for name, info := range AlgorithmRegistry {
		norm := normalizeAlgo(name)
		normalizedRegistry = append(normalizedRegistry, normalizedEntry{
			normalized: norm,
			info:       info,
		})
	}
	// Sort by length descending — longer patterns are more specific and should match first.
	sort.Slice(normalizedRegistry, func(i, j int) bool {
		return len(normalizedRegistry[i].normalized) > len(normalizedRegistry[j].normalized)
	})
}

// normalizeAlgo uppercases and strips hyphens/underscores for fuzzy matching.
func normalizeAlgo(s string) string {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}

// ClassifyAlgorithm determines the PQC status of a cryptographic algorithm.
func ClassifyAlgorithm(algorithm string, keySize int) AlgorithmInfo {
	// Try exact match first (fastest path)
	if info, ok := AlgorithmRegistry[algorithm]; ok {
		return info
	}

	// Try normalized exact match (e.g., "aes_256_gcm" → "AES256GCM")
	alg := normalizeAlgo(algorithm)
	for _, entry := range normalizedRegistry {
		if entry.normalized == alg {
			return entry.info
		}
	}

	// Try substring match — longest match first (deterministic, sorted order)
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

// ClassifyCryptoAsset fills PQCStatus, MigrationPriority, and BreakYear on a CryptoAsset.
func ClassifyCryptoAsset(asset *model.CryptoAsset) {
	info := ClassifyAlgorithm(asset.Algorithm, asset.KeySize)
	asset.PQCStatus = string(info.Status)
	asset.MigrationPriority = GetMigrationPriority(info)
	asset.BreakYear = info.BreakYear
}
