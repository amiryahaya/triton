package crypto

import "strings"

// PythonCryptoEntry is a classified Python crypto import path.
type PythonCryptoEntry struct {
	Algorithm string // Canonical algorithm name
	Function  string // Specific function or class name (e.g. "sha256", "AES")
	KeySize   int    // Key size in bits where applicable (0 = not specified)
}

// pythonCryptoRegistry maps Python import paths to classified metadata.
// Keys are the fully-qualified dotted import paths as they appear in
// Python source (e.g. "hashlib.sha256", "Crypto.Cipher.AES").
// Lookup uses exact match first, then prefix match.
var pythonCryptoRegistry = map[string]PythonCryptoEntry{}

func init() {
	add := func(paths []string, algo, function string, keySize int) {
		for _, p := range paths {
			pythonCryptoRegistry[p] = PythonCryptoEntry{
				Algorithm: algo,
				Function:  function,
				KeySize:   keySize,
			}
		}
	}

	// --- stdlib: hashlib ---
	add([]string{"hashlib.md5"}, "MD5", "md5", 0)
	add([]string{"hashlib.sha1"}, "SHA-1", "sha1", 0)
	add([]string{"hashlib.sha256"}, "SHA-256", "sha256", 0)
	add([]string{"hashlib.sha384"}, "SHA-384", "sha384", 0)
	add([]string{"hashlib.sha512"}, "SHA-512", "sha512", 0)
	add([]string{"hashlib.sha3_256"}, "SHA3-256", "sha3_256", 0)
	add([]string{"hashlib.sha3_512"}, "SHA3-512", "sha3_512", 0)
	add([]string{"hashlib.blake2b"}, "BLAKE2b", "blake2b", 0)
	add([]string{"hashlib.blake2s"}, "BLAKE2s", "blake2s", 0)

	// --- stdlib: hmac ---
	add([]string{"hmac.new"}, "HMAC", "new", 0)

	// --- stdlib: ssl ---
	add([]string{"ssl.create_default_context"}, "TLS", "create_default_context", 0)

	// --- stdlib: secrets ---
	add([]string{"secrets.token_bytes"}, "CSPRNG", "token_bytes", 0)

	// --- cryptography: symmetric ciphers ---
	add([]string{"cryptography.hazmat.primitives.ciphers.algorithms.AES"}, "AES", "AES", 0)
	add([]string{"cryptography.hazmat.primitives.ciphers.algorithms.TripleDES"}, "3DES", "TripleDES", 0)
	add([]string{"cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20"}, "ChaCha20", "ChaCha20", 0)
	add([]string{"cryptography.hazmat.primitives.ciphers.algorithms.Blowfish"}, "Blowfish", "Blowfish", 0)

	// --- cryptography: hash functions ---
	add([]string{"cryptography.hazmat.primitives.hashes.SHA256"}, "SHA-256", "SHA256", 0)
	add([]string{"cryptography.hazmat.primitives.hashes.SHA384"}, "SHA-384", "SHA384", 0)
	add([]string{"cryptography.hazmat.primitives.hashes.SHA512"}, "SHA-512", "SHA512", 0)
	add([]string{"cryptography.hazmat.primitives.hashes.SHA1"}, "SHA-1", "SHA1", 0)
	add([]string{"cryptography.hazmat.primitives.hashes.MD5"}, "MD5", "MD5", 0)

	// --- cryptography: asymmetric ---
	add([]string{"cryptography.hazmat.primitives.asymmetric.rsa"}, "RSA", "rsa", 0)
	add([]string{"cryptography.hazmat.primitives.asymmetric.ec"}, "ECDSA", "ec", 0)
	add([]string{"cryptography.hazmat.primitives.asymmetric.ec.SECP256R1"}, "ECDSA-P256", "SECP256R1", 256)
	add([]string{"cryptography.hazmat.primitives.asymmetric.ec.SECP384R1"}, "ECDSA-P384", "SECP384R1", 384)
	add([]string{"cryptography.hazmat.primitives.asymmetric.ec.SECP521R1"}, "ECDSA-P521", "SECP521R1", 521)
	add([]string{"cryptography.hazmat.primitives.asymmetric.ed25519"}, "Ed25519", "ed25519", 0)
	add([]string{"cryptography.hazmat.primitives.asymmetric.ed448"}, "Ed448", "ed448", 0)

	// --- cryptography: KDF ---
	add([]string{"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC"}, "PBKDF2", "PBKDF2HMAC", 0)
	add([]string{"cryptography.hazmat.primitives.kdf.scrypt.Scrypt"}, "scrypt", "Scrypt", 0)
	add([]string{"cryptography.hazmat.primitives.kdf.hkdf.HKDF"}, "HKDF", "HKDF", 0)

	// --- cryptography: Fernet (AES-128-CBC + HMAC-SHA256) ---
	add([]string{"cryptography.fernet.Fernet"}, "AES-128-CBC", "Fernet", 128)

	// --- cryptography: x509 ---
	add([]string{"cryptography.x509"}, "X.509", "x509", 0)

	// --- pycryptodome: Crypto.* ---
	add([]string{"Crypto.Cipher.AES"}, "AES", "AES", 0)
	add([]string{"Crypto.Cipher.DES3"}, "3DES", "DES3", 0)
	add([]string{"Crypto.Cipher.DES"}, "DES", "DES", 0)
	add([]string{"Crypto.Cipher.Blowfish"}, "Blowfish", "Blowfish", 0)
	add([]string{"Crypto.Cipher.ChaCha20"}, "ChaCha20", "ChaCha20", 0)
	add([]string{"Crypto.Hash.SHA256"}, "SHA-256", "SHA256", 0)
	add([]string{"Crypto.Hash.SHA1"}, "SHA-1", "SHA1", 0)
	add([]string{"Crypto.Hash.MD5"}, "MD5", "MD5", 0)
	add([]string{"Crypto.PublicKey.RSA"}, "RSA", "RSA", 0)
	add([]string{"Crypto.PublicKey.ECC"}, "ECDSA", "ECC", 0)
	add([]string{"Crypto.PublicKey.DSA"}, "DSA", "DSA", 0)

	// Mirror all Crypto.* entries under Cryptodome.* namespace.
	cryptoPrefix := "Crypto."
	for k, v := range pythonCryptoRegistry {
		if strings.HasPrefix(k, cryptoPrefix) {
			mirrored := "Cryptodome." + k[len(cryptoPrefix):]
			if _, exists := pythonCryptoRegistry[mirrored]; !exists {
				pythonCryptoRegistry[mirrored] = v
			}
		}
	}
}

// LookupPythonCrypto classifies a Python import path. It first tries an exact
// match, then a prefix match (any registered key that begins with
// importPath+"."), returning the first hit. Returns the entry and true when
// the path is recognised.
func LookupPythonCrypto(importPath string) (PythonCryptoEntry, bool) {
	// Exact match.
	if e, ok := pythonCryptoRegistry[importPath]; ok {
		return e, true
	}
	// Prefix match: the caller imported a parent module whose sub-paths are
	// registered (e.g. "cryptography.hazmat.primitives.asymmetric.ec" covers
	// ".ec.SECP256R1", ".ec.SECP384R1", etc.).
	prefix := importPath + "."
	for k, v := range pythonCryptoRegistry {
		if strings.HasPrefix(k, prefix) {
			return v, true
		}
	}
	return PythonCryptoEntry{}, false
}
