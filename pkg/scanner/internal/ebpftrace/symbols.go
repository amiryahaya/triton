package ebpftrace

import "strings"

// ResolveNID maps an OpenSSL NID (from obj_mac.h) to an AlgoInfo.
// Only NIDs that appear as cipher/digest arguments to probed uprobes are listed.
func ResolveNID(nid int32) (AlgoInfo, bool) {
	info, ok := nidRegistry[nid]
	return info, ok
}

// ResolveKernelAlgo maps a Linux kernel crypto allocator name to an AlgoInfo.
// Names like "sha256", "cbc(aes)", "gcm(aes)" are common.
func ResolveKernelAlgo(name string) (AlgoInfo, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	// Exact-match first.
	if info, ok := kernelRegistry[n]; ok {
		return info, true
	}
	// Substring scan for compound names like "cbc(aes)" or "hmac(sha256)".
	for key, info := range kernelRegistry {
		if strings.Contains(n, key) {
			return info, true
		}
	}
	return AlgoInfo{}, false
}

// UprobeTargets returns the list of uprobe attach requests. Ordering is stable
// (tests rely on `SymbolName` presence, not index).
func UprobeTargets() []UprobeTarget {
	return uprobeTargets
}

var nidRegistry = map[int32]AlgoInfo{
	// Hashes (obj_mac.h NID_*)
	4:    {"MD5", "MD5", "libcrypto"},
	64:   {"SHA-1", "SHA", "libcrypto"},
	672:  {"SHA-256", "SHA", "libcrypto"},
	673:  {"SHA-384", "SHA", "libcrypto"},
	674:  {"SHA-512", "SHA", "libcrypto"},
	675:  {"SHA-224", "SHA", "libcrypto"},
	1096: {"SHA3-256", "SHA3", "libcrypto"},
	1097: {"SHA3-384", "SHA3", "libcrypto"},
	1098: {"SHA3-512", "SHA3", "libcrypto"},
	// Ciphers
	418:  {"AES", "AES", "libcrypto"}, // aes-128-cbc
	419:  {"AES", "AES", "libcrypto"},
	420:  {"AES", "AES", "libcrypto"},
	421:  {"AES", "AES", "libcrypto"},
	422:  {"AES", "AES", "libcrypto"},
	423:  {"AES", "AES", "libcrypto"},
	424:  {"AES", "AES", "libcrypto"}, // aes-128-ecb
	425:  {"AES", "AES", "libcrypto"},
	426:  {"AES", "AES", "libcrypto"},
	427:  {"AES", "AES", "libcrypto"}, // aes-128-cfb1
	428:  {"AES", "AES", "libcrypto"},
	429:  {"AES", "AES", "libcrypto"},
	901:  {"AES-GCM", "AES", "libcrypto"},
	902:  {"AES-GCM", "AES", "libcrypto"},
	903:  {"AES-GCM", "AES", "libcrypto"},
	31:   {"DES", "DES", "libcrypto"},
	44:   {"3DES", "3DES", "libcrypto"},
	5:    {"RC4", "RC4", "libcrypto"},
	37:   {"RC2", "RC2", "libcrypto"},
	1016: {"ChaCha20", "ChaCha", "libcrypto"},
	1018: {"ChaCha20-Poly1305", "ChaCha", "libcrypto"},
	// Asymmetric
	6:    {"RSA", "RSA", "libcrypto"},
	116:  {"DSA", "DSA", "libcrypto"},
	408:  {"ECDSA", "ECDSA", "libcrypto"}, // X9_62_prime256v1
	715:  {"ECDSA", "ECDSA", "libcrypto"}, // secp384r1
	716:  {"ECDSA", "ECDSA", "libcrypto"}, // secp521r1
	1087: {"Ed25519", "EdDSA", "libcrypto"},
	1088: {"Ed448", "EdDSA", "libcrypto"},
	1034: {"X25519", "ECDH", "libcrypto"},
	1035: {"X448", "ECDH", "libcrypto"},
}

// kernelRegistry covers Linux kernel crypto allocator names. Keys are
// lowercase substrings; ResolveKernelAlgo does both exact + contains matches.
var kernelRegistry = map[string]AlgoInfo{
	"md5":      {"MD5", "MD5", "kernel"},
	"sha1":     {"SHA-1", "SHA", "kernel"},
	"sha224":   {"SHA-224", "SHA", "kernel"},
	"sha256":   {"SHA-256", "SHA", "kernel"},
	"sha384":   {"SHA-384", "SHA", "kernel"},
	"sha512":   {"SHA-512", "SHA", "kernel"},
	"sha3-256": {"SHA3-256", "SHA3", "kernel"},
	"sha3-384": {"SHA3-384", "SHA3", "kernel"},
	"sha3-512": {"SHA3-512", "SHA3", "kernel"},
	"aes":      {"AES", "AES", "kernel"},
	"des":      {"DES", "DES", "kernel"},
	"3des":     {"3DES", "3DES", "kernel"},
	"chacha20": {"ChaCha20", "ChaCha", "kernel"},
	"poly1305": {"Poly1305", "MAC", "kernel"},
	"rsa":      {"RSA", "RSA", "kernel"},
	"dsa":      {"DSA", "DSA", "kernel"},
	"ecdsa":    {"ECDSA", "ECDSA", "kernel"},
	"ecdh":     {"ECDH", "ECDH", "kernel"},
	"ed25519":  {"Ed25519", "EdDSA", "kernel"},
	"hmac":     {"HMAC", "HMAC", "kernel"},
}

var uprobeTargets = []UprobeTarget{
	// libcrypto — constant-inferred
	// NOTE: EVP_CipherInit_ex/EVP_EncryptInit_ex/EVP_DigestInit_ex were removed —
	// arg2 is a struct pointer (EVP_CIPHER*/EVP_MD*), not an integer NID. Reading
	// the struct's nid field via CO-RE is deferred to a follow-up PR.
	{LibID: LibLibcrypto, SymbolName: "RSA_generate_key_ex", ProgName: "uprobe__RSA_generate_key_ex", ArgIdx: 0, ConstAlgo: "RSA", ConstFamily: "RSA"},
	{LibID: LibLibcrypto, SymbolName: "RSA_sign", ProgName: "uprobe__RSA_sign", ArgIdx: 0, ConstAlgo: "RSA", ConstFamily: "RSA"},
	{LibID: LibLibcrypto, SymbolName: "RSA_verify", ProgName: "uprobe__RSA_verify", ArgIdx: 0, ConstAlgo: "RSA", ConstFamily: "RSA"},
	{LibID: LibLibcrypto, SymbolName: "EC_KEY_generate_key", ProgName: "uprobe__EC_KEY_generate_key", ArgIdx: 0, ConstAlgo: "ECDSA", ConstFamily: "ECDSA"},
	{LibID: LibLibcrypto, SymbolName: "ECDSA_sign", ProgName: "uprobe__ECDSA_sign", ArgIdx: 0, ConstAlgo: "ECDSA", ConstFamily: "ECDSA"},
	{LibID: LibLibcrypto, SymbolName: "EVP_PKEY_derive", ProgName: "uprobe__EVP_PKEY_derive", ArgIdx: 0, ConstAlgo: "KEX", ConstFamily: "ECDH"},
	{LibID: LibLibcrypto, SymbolName: "SSL_CTX_new", ProgName: "uprobe__SSL_CTX_new", ArgIdx: 0, ConstAlgo: "TLS", ConstFamily: "TLS"},
	// GnuTLS
	{LibID: LibGnuTLS, SymbolName: "gnutls_cipher_init", ProgName: "uprobe__gnutls_cipher_init", ArgIdx: 2},
	{LibID: LibGnuTLS, SymbolName: "gnutls_hash_init", ProgName: "uprobe__gnutls_hash_init", ArgIdx: 2},
	{LibID: LibGnuTLS, SymbolName: "gnutls_pubkey_verify_data2", ProgName: "uprobe__gnutls_pubkey_verify_data2", ArgIdx: 0, ConstAlgo: "Verify", ConstFamily: "Signature"},
	// NSS
	{LibID: LibNSS, SymbolName: "PK11_CipherOp", ProgName: "uprobe__PK11_CipherOp", ArgIdx: 0, ConstAlgo: "Cipher", ConstFamily: "Cipher"},
	{LibID: LibNSS, SymbolName: "PK11_Digest", ProgName: "uprobe__PK11_Digest", ArgIdx: 0, ConstAlgo: "Digest", ConstFamily: "Hash"},
}
