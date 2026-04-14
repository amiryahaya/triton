package crypto

// classicalOIDs returns the pre-PQC OIDs recognized by Triton: hash functions,
// HMAC, symmetric ciphers, RSA/ECDSA/DSA/DH signature & key agreement algorithms,
// EC named curves, Kerberos, PKCS#7/CMS content types, KDFs, and stateful hash-based
// signatures (LMS/XMSS).
//
// OIDs are sourced from: NIST CSRC (`2.16.840.1.101.3.4.*`), RFC 3279, RFC 4055,
// RFC 5280, RFC 5480, RFC 5754, RFC 5758, RFC 5990, RFC 8017, RFC 8018, RFC 8103,
// RFC 8410, RFC 8692, SECG SEC 2, ANSI X9.42, ANSI X9.62/63, BSI TR-03111, and
// IETF draft-ietf-cose-hash-sig.
//
// Status values follow the project's PQC readiness classifier semantics (pqc.go):
//
//	UNSAFE       — broken or <80-bit security (MD2/MD4/MD5, DES, RC2, RC4, ECDSA-P192)
//	DEPRECATED   — pre-quantum weak but still seen (SHA-1, 3DES, DSA, RIPEMD, P-224, brainpool)
//	TRANSITIONAL — acceptable today but not quantum-safe (RSA, ECDSA-P256, SHA-256, DH)
//	SAFE         — long-term acceptable (AES-192/256, SHA-384+, SHA3-*, P-384/P-521, Ed*, HSS-LMS/XMSS)
func classicalOIDs() map[string]OIDEntry {
	return map[string]OIDEntry{
		// ─── RSA encryption + signature variants (PKCS#1, RFC 8017) ───
		"1.2.840.113549.1.1.1":  {OID: "1.2.840.113549.1.1.1", Algorithm: "RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.2":  {OID: "1.2.840.113549.1.1.2", Algorithm: "MD2-RSA", Family: "RSA", Status: UNSAFE},
		"1.2.840.113549.1.1.3":  {OID: "1.2.840.113549.1.1.3", Algorithm: "MD4-RSA", Family: "RSA", Status: UNSAFE},
		"1.2.840.113549.1.1.4":  {OID: "1.2.840.113549.1.1.4", Algorithm: "MD5-RSA", Family: "RSA", Status: UNSAFE},
		"1.2.840.113549.1.1.5":  {OID: "1.2.840.113549.1.1.5", Algorithm: "SHA1-RSA", Family: "RSA", Status: DEPRECATED},
		"1.2.840.113549.1.1.7":  {OID: "1.2.840.113549.1.1.7", Algorithm: "RSA-OAEP", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.8":  {OID: "1.2.840.113549.1.1.8", Algorithm: "RSA-MGF1", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.9":  {OID: "1.2.840.113549.1.1.9", Algorithm: "RSA-OAEP-pSpecified", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.10": {OID: "1.2.840.113549.1.1.10", Algorithm: "RSA-PSS", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.11": {OID: "1.2.840.113549.1.1.11", Algorithm: "SHA256-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.12": {OID: "1.2.840.113549.1.1.12", Algorithm: "SHA384-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.13": {OID: "1.2.840.113549.1.1.13", Algorithm: "SHA512-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.14": {OID: "1.2.840.113549.1.1.14", Algorithm: "SHA224-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.15": {OID: "1.2.840.113549.1.1.15", Algorithm: "SHA512-224-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.16": {OID: "1.2.840.113549.1.1.16", Algorithm: "SHA512-256-RSA", Family: "RSA", Status: TRANSITIONAL},

		// ─── RSA SHA-3 signatures (RFC 8702) ───
		"2.16.840.1.101.3.4.3.13": {OID: "2.16.840.1.101.3.4.3.13", Algorithm: "SHA3-224-RSA", Family: "RSA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.3.14": {OID: "2.16.840.1.101.3.4.3.14", Algorithm: "SHA3-256-RSA", Family: "RSA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.3.15": {OID: "2.16.840.1.101.3.4.3.15", Algorithm: "SHA3-384-RSA", Family: "RSA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.3.16": {OID: "2.16.840.1.101.3.4.3.16", Algorithm: "SHA3-512-RSA", Family: "RSA", Status: TRANSITIONAL},

		// ─── Hash functions (RFC 3370, RFC 4231, FIPS 180-4, FIPS 202) ───
		"1.2.840.113549.2.2":      {OID: "1.2.840.113549.2.2", Algorithm: "MD2", Family: "MD5", Status: UNSAFE},
		"1.2.840.113549.2.4":      {OID: "1.2.840.113549.2.4", Algorithm: "MD4", Family: "MD4", Status: UNSAFE},
		"1.2.840.113549.2.5":      {OID: "1.2.840.113549.2.5", Algorithm: "MD5", Family: "MD5", Status: UNSAFE},
		"1.3.14.3.2.26":           {OID: "1.3.14.3.2.26", Algorithm: "SHA-1", Family: "SHA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.2.1":  {OID: "2.16.840.1.101.3.4.2.1", Algorithm: "SHA-256", Family: "SHA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.2.2":  {OID: "2.16.840.1.101.3.4.2.2", Algorithm: "SHA-384", Family: "SHA", Status: SAFE},
		"2.16.840.1.101.3.4.2.3":  {OID: "2.16.840.1.101.3.4.2.3", Algorithm: "SHA-512", Family: "SHA", Status: SAFE},
		"2.16.840.1.101.3.4.2.4":  {OID: "2.16.840.1.101.3.4.2.4", Algorithm: "SHA-224", Family: "SHA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.2.5":  {OID: "2.16.840.1.101.3.4.2.5", Algorithm: "SHA-512/224", Family: "SHA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.2.6":  {OID: "2.16.840.1.101.3.4.2.6", Algorithm: "SHA-512/256", Family: "SHA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.2.7":  {OID: "2.16.840.1.101.3.4.2.7", Algorithm: "SHA3-224", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.8":  {OID: "2.16.840.1.101.3.4.2.8", Algorithm: "SHA3-256", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.9":  {OID: "2.16.840.1.101.3.4.2.9", Algorithm: "SHA3-384", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.10": {OID: "2.16.840.1.101.3.4.2.10", Algorithm: "SHA3-512", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.11": {OID: "2.16.840.1.101.3.4.2.11", Algorithm: "SHAKE128", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.12": {OID: "2.16.840.1.101.3.4.2.12", Algorithm: "SHAKE256", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.17": {OID: "2.16.840.1.101.3.4.2.17", Algorithm: "SHAKE128-LEN", Family: "SHA3", Status: SAFE},
		"2.16.840.1.101.3.4.2.18": {OID: "2.16.840.1.101.3.4.2.18", Algorithm: "SHAKE256-LEN", Family: "SHA3", Status: SAFE},
		"1.3.36.3.2.1":            {OID: "1.3.36.3.2.1", Algorithm: "RIPEMD-160", Family: "RIPEMD", Status: DEPRECATED},
		"1.3.36.3.2.2":            {OID: "1.3.36.3.2.2", Algorithm: "RIPEMD-128", Family: "RIPEMD", Status: DEPRECATED},
		"1.3.36.3.2.3":            {OID: "1.3.36.3.2.3", Algorithm: "RIPEMD-256", Family: "RIPEMD", Status: DEPRECATED},
		"1.0.10118.3.0.55":        {OID: "1.0.10118.3.0.55", Algorithm: "Whirlpool", Family: "SHA", Status: DEPRECATED},

		// ─── HMAC (RFC 4231, RFC 8018) ───
		"1.2.840.113549.2.7":      {OID: "1.2.840.113549.2.7", Algorithm: "HMAC-SHA1", Family: "HMAC", Status: DEPRECATED},
		"1.2.840.113549.2.8":      {OID: "1.2.840.113549.2.8", Algorithm: "HMAC-SHA224", Family: "HMAC", Status: TRANSITIONAL},
		"1.2.840.113549.2.9":      {OID: "1.2.840.113549.2.9", Algorithm: "HMAC-SHA256", Family: "HMAC", Status: TRANSITIONAL},
		"1.2.840.113549.2.10":     {OID: "1.2.840.113549.2.10", Algorithm: "HMAC-SHA384", Family: "HMAC", Status: SAFE},
		"1.2.840.113549.2.11":     {OID: "1.2.840.113549.2.11", Algorithm: "HMAC-SHA512", Family: "HMAC", Status: SAFE},
		"1.2.840.113549.2.12":     {OID: "1.2.840.113549.2.12", Algorithm: "HMAC-SHA512-224", Family: "HMAC", Status: TRANSITIONAL},
		"1.2.840.113549.2.13":     {OID: "1.2.840.113549.2.13", Algorithm: "HMAC-SHA512-256", Family: "HMAC", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.2.13": {OID: "2.16.840.1.101.3.4.2.13", Algorithm: "HMAC-SHA3-224", Family: "HMAC", Status: SAFE},
		"2.16.840.1.101.3.4.2.14": {OID: "2.16.840.1.101.3.4.2.14", Algorithm: "HMAC-SHA3-256", Family: "HMAC", Status: SAFE},
		"2.16.840.1.101.3.4.2.15": {OID: "2.16.840.1.101.3.4.2.15", Algorithm: "HMAC-SHA3-384", Family: "HMAC", Status: SAFE},
		"2.16.840.1.101.3.4.2.16": {OID: "2.16.840.1.101.3.4.2.16", Algorithm: "HMAC-SHA3-512", Family: "HMAC", Status: SAFE},

		// ─── AES (NIST CSOR 2.16.840.1.101.3.4.1.*, RFC 3565/5084/6188) ───
		// AES-128
		"2.16.840.1.101.3.4.1.1": {OID: "2.16.840.1.101.3.4.1.1", Algorithm: "AES-128-ECB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.2": {OID: "2.16.840.1.101.3.4.1.2", Algorithm: "AES-128-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.3": {OID: "2.16.840.1.101.3.4.1.3", Algorithm: "AES-128-OFB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.4": {OID: "2.16.840.1.101.3.4.1.4", Algorithm: "AES-128-CFB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.5": {OID: "2.16.840.1.101.3.4.1.5", Algorithm: "AES-128-wrap", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.6": {OID: "2.16.840.1.101.3.4.1.6", Algorithm: "AES-128-GCM", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.7": {OID: "2.16.840.1.101.3.4.1.7", Algorithm: "AES-128-CCM", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.1.8": {OID: "2.16.840.1.101.3.4.1.8", Algorithm: "AES-128-wrap-pad", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		// AES-192
		"2.16.840.1.101.3.4.1.21": {OID: "2.16.840.1.101.3.4.1.21", Algorithm: "AES-192-ECB", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.22": {OID: "2.16.840.1.101.3.4.1.22", Algorithm: "AES-192-CBC", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.23": {OID: "2.16.840.1.101.3.4.1.23", Algorithm: "AES-192-OFB", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.24": {OID: "2.16.840.1.101.3.4.1.24", Algorithm: "AES-192-CFB", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.25": {OID: "2.16.840.1.101.3.4.1.25", Algorithm: "AES-192-wrap", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.26": {OID: "2.16.840.1.101.3.4.1.26", Algorithm: "AES-192-GCM", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.27": {OID: "2.16.840.1.101.3.4.1.27", Algorithm: "AES-192-CCM", Family: "AES", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.1.28": {OID: "2.16.840.1.101.3.4.1.28", Algorithm: "AES-192-wrap-pad", Family: "AES", KeySize: 192, Status: SAFE},
		// AES-256
		"2.16.840.1.101.3.4.1.41": {OID: "2.16.840.1.101.3.4.1.41", Algorithm: "AES-256-ECB", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.42": {OID: "2.16.840.1.101.3.4.1.42", Algorithm: "AES-256-CBC", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.43": {OID: "2.16.840.1.101.3.4.1.43", Algorithm: "AES-256-OFB", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.44": {OID: "2.16.840.1.101.3.4.1.44", Algorithm: "AES-256-CFB", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.45": {OID: "2.16.840.1.101.3.4.1.45", Algorithm: "AES-256-wrap", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.46": {OID: "2.16.840.1.101.3.4.1.46", Algorithm: "AES-256-GCM", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.47": {OID: "2.16.840.1.101.3.4.1.47", Algorithm: "AES-256-CCM", Family: "AES", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.1.48": {OID: "2.16.840.1.101.3.4.1.48", Algorithm: "AES-256-wrap-pad", Family: "AES", KeySize: 256, Status: SAFE},

		// ─── Legacy symmetric (DEPRECATED/UNSAFE) ───
		"1.2.840.113549.3.7":        {OID: "1.2.840.113549.3.7", Algorithm: "3DES-CBC", Family: "3DES", KeySize: 168, Status: DEPRECATED},
		"1.2.840.113549.3.2":        {OID: "1.2.840.113549.3.2", Algorithm: "RC2-CBC", Family: "RC2", Status: UNSAFE},
		"1.2.840.113549.3.4":        {OID: "1.2.840.113549.3.4", Algorithm: "RC4", Family: "RC4", Status: UNSAFE},
		"1.2.840.113549.1.9.16.3.6": {OID: "1.2.840.113549.1.9.16.3.6", Algorithm: "CMS-3DES-wrap", Family: "3DES", KeySize: 168, Status: DEPRECATED},
		"1.2.840.113549.1.9.16.3.7": {OID: "1.2.840.113549.1.9.16.3.7", Algorithm: "CMS-RC2-wrap", Family: "RC2", Status: UNSAFE},
		"1.3.14.3.2.7":              {OID: "1.3.14.3.2.7", Algorithm: "DES-CBC", Family: "DES", KeySize: 56, Status: UNSAFE},
		"1.3.14.3.2.6":              {OID: "1.3.14.3.2.6", Algorithm: "DES-ECB", Family: "DES", KeySize: 56, Status: UNSAFE},
		"1.3.14.3.2.8":              {OID: "1.3.14.3.2.8", Algorithm: "DES-OFB", Family: "DES", KeySize: 56, Status: UNSAFE},
		"1.3.14.3.2.9":              {OID: "1.3.14.3.2.9", Algorithm: "DES-CFB", Family: "DES", KeySize: 56, Status: UNSAFE},
		"1.3.14.3.2.17":             {OID: "1.3.14.3.2.17", Algorithm: "DES-EDE", Family: "3DES", KeySize: 168, Status: DEPRECATED},

		// ─── Camellia (RFC 3657, RFC 5990) ───
		"1.2.392.200011.61.1.1.1.2": {OID: "1.2.392.200011.61.1.1.1.2", Algorithm: "Camellia-128-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.392.200011.61.1.1.1.3": {OID: "1.2.392.200011.61.1.1.1.3", Algorithm: "Camellia-192-CBC", Family: "AES", KeySize: 192, Status: SAFE},
		"1.2.392.200011.61.1.1.1.4": {OID: "1.2.392.200011.61.1.1.1.4", Algorithm: "Camellia-256-CBC", Family: "AES", KeySize: 256, Status: SAFE},
		"1.2.392.200011.61.1.1.3.2": {OID: "1.2.392.200011.61.1.1.3.2", Algorithm: "Camellia-128-wrap", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.392.200011.61.1.1.3.3": {OID: "1.2.392.200011.61.1.1.3.3", Algorithm: "Camellia-192-wrap", Family: "AES", KeySize: 192, Status: SAFE},
		"1.2.392.200011.61.1.1.3.4": {OID: "1.2.392.200011.61.1.1.3.4", Algorithm: "Camellia-256-wrap", Family: "AES", KeySize: 256, Status: SAFE},

		// ─── SEED (RFC 4010) ───
		"1.2.410.200004.1.3":     {OID: "1.2.410.200004.1.3", Algorithm: "SEED-ECB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.410.200004.1.4":     {OID: "1.2.410.200004.1.4", Algorithm: "SEED-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.410.200004.1.5":     {OID: "1.2.410.200004.1.5", Algorithm: "SEED-CFB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.410.200004.1.6":     {OID: "1.2.410.200004.1.6", Algorithm: "SEED-OFB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.410.200004.7.1.1.1": {OID: "1.2.410.200004.7.1.1.1", Algorithm: "SEED-wrap", Family: "AES", KeySize: 128, Status: TRANSITIONAL},

		// ─── ARIA (RFC 5794) ───
		"1.2.410.200046.1.1.1":  {OID: "1.2.410.200046.1.1.1", Algorithm: "ARIA-128-ECB", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.410.200046.1.1.2":  {OID: "1.2.410.200046.1.1.2", Algorithm: "ARIA-128-CBC", Family: "AES", KeySize: 128, Status: TRANSITIONAL},
		"1.2.410.200046.1.1.6":  {OID: "1.2.410.200046.1.1.6", Algorithm: "ARIA-192-ECB", Family: "AES", KeySize: 192, Status: SAFE},
		"1.2.410.200046.1.1.7":  {OID: "1.2.410.200046.1.1.7", Algorithm: "ARIA-192-CBC", Family: "AES", KeySize: 192, Status: SAFE},
		"1.2.410.200046.1.1.11": {OID: "1.2.410.200046.1.1.11", Algorithm: "ARIA-256-ECB", Family: "AES", KeySize: 256, Status: SAFE},
		"1.2.410.200046.1.1.12": {OID: "1.2.410.200046.1.1.12", Algorithm: "ARIA-256-CBC", Family: "AES", KeySize: 256, Status: SAFE},

		// ─── ECDSA / EC keys (RFC 5480, RFC 5758, SEC 2) ───
		"1.2.840.10045.2.1":   {OID: "1.2.840.10045.2.1", Algorithm: "EC", Family: "ECDSA", Status: TRANSITIONAL},
		"1.2.840.10045.4.1":   {OID: "1.2.840.10045.4.1", Algorithm: "ECDSA-SHA1", Family: "ECDSA", Status: DEPRECATED},
		"1.2.840.10045.4.3.1": {OID: "1.2.840.10045.4.3.1", Algorithm: "ECDSA-SHA224", Family: "ECDSA", Status: TRANSITIONAL},
		"1.2.840.10045.4.3.2": {OID: "1.2.840.10045.4.3.2", Algorithm: "ECDSA-SHA256", Family: "ECDSA", Status: TRANSITIONAL},
		"1.2.840.10045.4.3.3": {OID: "1.2.840.10045.4.3.3", Algorithm: "ECDSA-SHA384", Family: "ECDSA", Status: SAFE},
		"1.2.840.10045.4.3.4": {OID: "1.2.840.10045.4.3.4", Algorithm: "ECDSA-SHA512", Family: "ECDSA", Status: SAFE},
		// ECDSA SHA-3 (RFC 8692)
		"2.16.840.1.101.3.4.3.9":  {OID: "2.16.840.1.101.3.4.3.9", Algorithm: "ECDSA-SHA3-224", Family: "ECDSA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.3.10": {OID: "2.16.840.1.101.3.4.3.10", Algorithm: "ECDSA-SHA3-256", Family: "ECDSA", Status: TRANSITIONAL},
		"2.16.840.1.101.3.4.3.11": {OID: "2.16.840.1.101.3.4.3.11", Algorithm: "ECDSA-SHA3-384", Family: "ECDSA", Status: SAFE},
		"2.16.840.1.101.3.4.3.12": {OID: "2.16.840.1.101.3.4.3.12", Algorithm: "ECDSA-SHA3-512", Family: "ECDSA", Status: SAFE},

		// ─── Named EC curves: NIST/ANSI prime (1.2.840.10045.3.1.*) + SECG (1.3.132.0.*) ───
		"1.2.840.10045.3.1.1": {OID: "1.2.840.10045.3.1.1", Algorithm: "ECDSA-P192", Family: "ECDSA", KeySize: 192, Status: UNSAFE},
		"1.2.840.10045.3.1.7": {OID: "1.2.840.10045.3.1.7", Algorithm: "ECDSA-P256", Family: "ECDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.132.0.1":         {OID: "1.3.132.0.1", Algorithm: "sect163k1", Family: "ECDSA", KeySize: 163, Status: DEPRECATED},
		"1.3.132.0.15":        {OID: "1.3.132.0.15", Algorithm: "sect163r2", Family: "ECDSA", KeySize: 163, Status: DEPRECATED},
		"1.3.132.0.26":        {OID: "1.3.132.0.26", Algorithm: "sect233k1", Family: "ECDSA", KeySize: 233, Status: DEPRECATED},
		"1.3.132.0.27":        {OID: "1.3.132.0.27", Algorithm: "sect233r1", Family: "ECDSA", KeySize: 233, Status: DEPRECATED},
		"1.3.132.0.10":        {OID: "1.3.132.0.10", Algorithm: "secp256k1", Family: "ECDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.132.0.16":        {OID: "1.3.132.0.16", Algorithm: "sect283k1", Family: "ECDSA", KeySize: 283, Status: TRANSITIONAL},
		"1.3.132.0.17":        {OID: "1.3.132.0.17", Algorithm: "sect283r1", Family: "ECDSA", KeySize: 283, Status: TRANSITIONAL},
		"1.3.132.0.33":        {OID: "1.3.132.0.33", Algorithm: "ECDSA-P224", Family: "ECDSA", KeySize: 224, Status: DEPRECATED},
		"1.3.132.0.34":        {OID: "1.3.132.0.34", Algorithm: "ECDSA-P384", Family: "ECDSA", KeySize: 384, Status: SAFE},
		"1.3.132.0.35":        {OID: "1.3.132.0.35", Algorithm: "ECDSA-P521", Family: "ECDSA", KeySize: 521, Status: SAFE},
		"1.3.132.0.36":        {OID: "1.3.132.0.36", Algorithm: "sect409k1", Family: "ECDSA", KeySize: 409, Status: SAFE},
		"1.3.132.0.37":        {OID: "1.3.132.0.37", Algorithm: "sect409r1", Family: "ECDSA", KeySize: 409, Status: SAFE},
		"1.3.132.0.38":        {OID: "1.3.132.0.38", Algorithm: "sect571k1", Family: "ECDSA", KeySize: 571, Status: SAFE},
		"1.3.132.0.39":        {OID: "1.3.132.0.39", Algorithm: "sect571r1", Family: "ECDSA", KeySize: 571, Status: SAFE},

		// ─── Brainpool curves (RFC 5639) ───
		"1.3.36.3.3.2.8.1.1.1":  {OID: "1.3.36.3.3.2.8.1.1.1", Algorithm: "brainpoolP160r1", Family: "ECDSA", KeySize: 160, Status: DEPRECATED},
		"1.3.36.3.3.2.8.1.1.3":  {OID: "1.3.36.3.3.2.8.1.1.3", Algorithm: "brainpoolP192r1", Family: "ECDSA", KeySize: 192, Status: DEPRECATED},
		"1.3.36.3.3.2.8.1.1.5":  {OID: "1.3.36.3.3.2.8.1.1.5", Algorithm: "brainpoolP224r1", Family: "ECDSA", KeySize: 224, Status: DEPRECATED},
		"1.3.36.3.3.2.8.1.1.7":  {OID: "1.3.36.3.3.2.8.1.1.7", Algorithm: "brainpoolP256r1", Family: "ECDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.36.3.3.2.8.1.1.9":  {OID: "1.3.36.3.3.2.8.1.1.9", Algorithm: "brainpoolP320r1", Family: "ECDSA", KeySize: 320, Status: TRANSITIONAL},
		"1.3.36.3.3.2.8.1.1.11": {OID: "1.3.36.3.3.2.8.1.1.11", Algorithm: "brainpoolP384r1", Family: "ECDSA", KeySize: 384, Status: TRANSITIONAL},
		"1.3.36.3.3.2.8.1.1.13": {OID: "1.3.36.3.3.2.8.1.1.13", Algorithm: "brainpoolP512r1", Family: "ECDSA", KeySize: 512, Status: TRANSITIONAL},

		// ─── Edwards curves (RFC 8410) ───
		"1.3.101.110": {OID: "1.3.101.110", Algorithm: "X25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.101.111": {OID: "1.3.101.111", Algorithm: "X448", Family: "EdDSA", KeySize: 448, Status: TRANSITIONAL},
		"1.3.101.112": {OID: "1.3.101.112", Algorithm: "Ed25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.101.113": {OID: "1.3.101.113", Algorithm: "Ed448", Family: "EdDSA", KeySize: 448, Status: TRANSITIONAL},

		// ─── DSA (FIPS 186, RFC 3279) ───
		"1.2.840.10040.4.1":      {OID: "1.2.840.10040.4.1", Algorithm: "DSA", Family: "DSA", Status: DEPRECATED},
		"1.2.840.10040.4.3":      {OID: "1.2.840.10040.4.3", Algorithm: "DSA-SHA1", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.1": {OID: "2.16.840.1.101.3.4.3.1", Algorithm: "DSA-SHA224", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.2": {OID: "2.16.840.1.101.3.4.3.2", Algorithm: "DSA-SHA256", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.3": {OID: "2.16.840.1.101.3.4.3.3", Algorithm: "DSA-SHA384", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.4": {OID: "2.16.840.1.101.3.4.3.4", Algorithm: "DSA-SHA512", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.5": {OID: "2.16.840.1.101.3.4.3.5", Algorithm: "DSA-SHA3-224", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.6": {OID: "2.16.840.1.101.3.4.3.6", Algorithm: "DSA-SHA3-256", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.7": {OID: "2.16.840.1.101.3.4.3.7", Algorithm: "DSA-SHA3-384", Family: "DSA", Status: DEPRECATED},
		"2.16.840.1.101.3.4.3.8": {OID: "2.16.840.1.101.3.4.3.8", Algorithm: "DSA-SHA3-512", Family: "DSA", Status: DEPRECATED},

		// ─── Diffie-Hellman (RFC 2631, RFC 3279, ANSI X9.42) ───
		"1.2.840.113549.1.3.1":  {OID: "1.2.840.113549.1.3.1", Algorithm: "DH", Family: "DH", Status: TRANSITIONAL},
		"1.2.840.10046.2.1":     {OID: "1.2.840.10046.2.1", Algorithm: "DH-ANSIX9.42", Family: "DH", Status: TRANSITIONAL},
		"1.3.133.16.840.63.0.2": {OID: "1.3.133.16.840.63.0.2", Algorithm: "ECDH-stdDH-SHA1", Family: "DH", Status: DEPRECATED},
		"1.3.132.1.11.0":        {OID: "1.3.132.1.11.0", Algorithm: "ECDH-SHA224", Family: "DH", Status: TRANSITIONAL},
		"1.3.132.1.11.1":        {OID: "1.3.132.1.11.1", Algorithm: "ECDH-SHA256", Family: "DH", Status: TRANSITIONAL},
		"1.3.132.1.11.2":        {OID: "1.3.132.1.11.2", Algorithm: "ECDH-SHA384", Family: "DH", Status: SAFE},
		"1.3.132.1.11.3":        {OID: "1.3.132.1.11.3", Algorithm: "ECDH-SHA512", Family: "DH", Status: SAFE},
		"1.3.132.1.12":          {OID: "1.3.132.1.12", Algorithm: "ECDH", Family: "DH", Status: TRANSITIONAL},

		// ─── Kerberos (RFC 1964, RFC 4121) ───
		"1.2.840.113554.1.2.2":   {OID: "1.2.840.113554.1.2.2", Algorithm: "Kerberos", Family: "Kerberos", Status: TRANSITIONAL},
		"1.2.840.113554.1.2.2.3": {OID: "1.2.840.113554.1.2.2.3", Algorithm: "Kerberos-UserToUser", Family: "Kerberos", Status: TRANSITIONAL},
		"1.3.6.1.5.2.5":          {OID: "1.3.6.1.5.2.5", Algorithm: "Kerberos-PKINIT", Family: "Kerberos", Status: TRANSITIONAL},
		"1.3.6.1.5.5.2":          {OID: "1.3.6.1.5.5.2", Algorithm: "SPNEGO", Family: "Kerberos", Status: TRANSITIONAL},

		// ─── PKCS#7 / CMS content types (RFC 5652) ───
		"1.2.840.113549.1.7.1":       {OID: "1.2.840.113549.1.7.1", Algorithm: "PKCS7-Data", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.7.2":       {OID: "1.2.840.113549.1.7.2", Algorithm: "PKCS7-SignedData", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.7.3":       {OID: "1.2.840.113549.1.7.3", Algorithm: "PKCS7-EnvelopedData", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.7.4":       {OID: "1.2.840.113549.1.7.4", Algorithm: "PKCS7-SignedAndEnvelopedData", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.7.5":       {OID: "1.2.840.113549.1.7.5", Algorithm: "PKCS7-DigestedData", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.7.6":       {OID: "1.2.840.113549.1.7.6", Algorithm: "PKCS7-EncryptedData", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.9.16.1.9":  {OID: "1.2.840.113549.1.9.16.1.9", Algorithm: "CMS-CompressedData", Family: "PKCS7", Status: TRANSITIONAL},
		"1.2.840.113549.1.9.16.1.23": {OID: "1.2.840.113549.1.9.16.1.23", Algorithm: "CMS-AuthEnvelopedData", Family: "PKCS7", Status: TRANSITIONAL},

		// ─── KDF (RFC 8018, RFC 5869) ───
		"1.2.840.113549.1.5.12":      {OID: "1.2.840.113549.1.5.12", Algorithm: "PBKDF2", Family: "KDF", Status: TRANSITIONAL},
		"1.2.840.113549.1.5.13":      {OID: "1.2.840.113549.1.5.13", Algorithm: "PBES2", Family: "KDF", Status: TRANSITIONAL},
		"1.2.840.113549.1.5.1":       {OID: "1.2.840.113549.1.5.1", Algorithm: "PBE-MD2-DES", Family: "KDF", Status: UNSAFE},
		"1.2.840.113549.1.5.3":       {OID: "1.2.840.113549.1.5.3", Algorithm: "PBE-MD5-DES", Family: "KDF", Status: UNSAFE},
		"1.2.840.113549.1.5.10":      {OID: "1.2.840.113549.1.5.10", Algorithm: "PBE-SHA1-DES", Family: "KDF", Status: UNSAFE},
		"1.2.840.113549.1.5.11":      {OID: "1.2.840.113549.1.5.11", Algorithm: "PBE-SHA1-RC2", Family: "KDF", Status: UNSAFE},
		"1.2.840.113549.1.9.16.3.9":  {OID: "1.2.840.113549.1.9.16.3.9", Algorithm: "PWRI-KEK", Family: "KeyWrap", Status: TRANSITIONAL},
		"1.2.840.113549.1.9.16.3.28": {OID: "1.2.840.113549.1.9.16.3.28", Algorithm: "HKDF-SHA256", Family: "KDF", Status: TRANSITIONAL},
		"1.2.840.113549.1.9.16.3.29": {OID: "1.2.840.113549.1.9.16.3.29", Algorithm: "HKDF-SHA384", Family: "KDF", Status: SAFE},
		"1.2.840.113549.1.9.16.3.30": {OID: "1.2.840.113549.1.9.16.3.30", Algorithm: "HKDF-SHA512", Family: "KDF", Status: SAFE},

		// ─── Stateful hash-based signatures (LMS/XMSS, RFC 8554/8391) ───
		"1.2.840.113549.1.9.16.3.17": {OID: "1.2.840.113549.1.9.16.3.17", Algorithm: "HSS-LMS", Family: "Hash-Based", Status: SAFE},
		"0.4.0.127.0.15.1.1.13.0":    {OID: "0.4.0.127.0.15.1.1.13.0", Algorithm: "XMSS", Family: "Hash-Based", Status: SAFE},
		"0.4.0.127.0.15.1.1.14.0":    {OID: "0.4.0.127.0.15.1.1.14.0", Algorithm: "XMSS-MT", Family: "Hash-Based", Status: SAFE},

		// ─── PKCS#12 (RFC 7292) password-based encryption ───
		"1.2.840.113549.1.12.1.1": {OID: "1.2.840.113549.1.12.1.1", Algorithm: "PBE-SHA1-128RC4", Family: "RC4", Status: UNSAFE},
		"1.2.840.113549.1.12.1.2": {OID: "1.2.840.113549.1.12.1.2", Algorithm: "PBE-SHA1-40RC4", Family: "RC4", Status: UNSAFE},
		"1.2.840.113549.1.12.1.3": {OID: "1.2.840.113549.1.12.1.3", Algorithm: "PBE-SHA1-3DES", Family: "3DES", KeySize: 168, Status: DEPRECATED},
		"1.2.840.113549.1.12.1.4": {OID: "1.2.840.113549.1.12.1.4", Algorithm: "PBE-SHA1-2DES", Family: "3DES", KeySize: 112, Status: DEPRECATED},
		"1.2.840.113549.1.12.1.5": {OID: "1.2.840.113549.1.12.1.5", Algorithm: "PBE-SHA1-128RC2", Family: "RC2", Status: UNSAFE},
		"1.2.840.113549.1.12.1.6": {OID: "1.2.840.113549.1.12.1.6", Algorithm: "PBE-SHA1-40RC2", Family: "RC2", Status: UNSAFE},

		// ─── GOST (RFC 4357, RFC 4491) — regional but appears in wild ───
		"1.2.643.2.2.3":     {OID: "1.2.643.2.2.3", Algorithm: "GOST-R3411-94-R3410-2001", Family: "DSA", Status: DEPRECATED},
		"1.2.643.2.2.19":    {OID: "1.2.643.2.2.19", Algorithm: "GOST-R3410-2001", Family: "DSA", Status: DEPRECATED},
		"1.2.643.2.2.20":    {OID: "1.2.643.2.2.20", Algorithm: "GOST-R3410-94", Family: "DSA", Status: DEPRECATED},
		"1.2.643.2.2.21":    {OID: "1.2.643.2.2.21", Algorithm: "GOST-28147-89", Family: "AES", Status: DEPRECATED},
		"1.2.643.2.2.9":     {OID: "1.2.643.2.2.9", Algorithm: "GOST-R3411-94", Family: "SHA", Status: DEPRECATED},
		"1.2.643.7.1.1.1.1": {OID: "1.2.643.7.1.1.1.1", Algorithm: "GOST-R3410-2012-256", Family: "DSA", KeySize: 256, Status: TRANSITIONAL},
		"1.2.643.7.1.1.1.2": {OID: "1.2.643.7.1.1.1.2", Algorithm: "GOST-R3410-2012-512", Family: "DSA", KeySize: 512, Status: SAFE},
		"1.2.643.7.1.1.2.2": {OID: "1.2.643.7.1.1.2.2", Algorithm: "GOST-R3411-2012-256", Family: "SHA", Status: TRANSITIONAL},
		"1.2.643.7.1.1.2.3": {OID: "1.2.643.7.1.1.2.3", Algorithm: "GOST-R3411-2012-512", Family: "SHA", Status: SAFE},
	}
}
