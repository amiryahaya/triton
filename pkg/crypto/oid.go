package crypto

// OIDEntry maps an ASN.1 OID to its algorithm name, family, and PQC status.
type OIDEntry struct {
	OID       string
	Algorithm string
	Family    string
	KeySize   int
	Status    PQCStatus
}

// oidRegistry maps OID strings to algorithm information.
var oidRegistry map[string]OIDEntry

// reverseOIDMap maps canonical algorithm names back to their OID strings.
var reverseOIDMap map[string]string

func init() {
	oidRegistry = map[string]OIDEntry{
		// === ML-KEM (FIPS 203) ===
		"2.16.840.1.101.3.4.4.1": {OID: "2.16.840.1.101.3.4.4.1", Algorithm: "ML-KEM-512", Family: "Lattice", KeySize: 512, Status: SAFE},
		"2.16.840.1.101.3.4.4.2": {OID: "2.16.840.1.101.3.4.4.2", Algorithm: "ML-KEM-768", Family: "Lattice", KeySize: 768, Status: SAFE},
		"2.16.840.1.101.3.4.4.3": {OID: "2.16.840.1.101.3.4.4.3", Algorithm: "ML-KEM-1024", Family: "Lattice", KeySize: 1024, Status: SAFE},

		// === ML-DSA (FIPS 204) ===
		"2.16.840.1.101.3.4.3.17": {OID: "2.16.840.1.101.3.4.3.17", Algorithm: "ML-DSA-44", Family: "Lattice", KeySize: 0, Status: SAFE},
		"2.16.840.1.101.3.4.3.18": {OID: "2.16.840.1.101.3.4.3.18", Algorithm: "ML-DSA-65", Family: "Lattice", KeySize: 0, Status: SAFE},
		"2.16.840.1.101.3.4.3.19": {OID: "2.16.840.1.101.3.4.3.19", Algorithm: "ML-DSA-87", Family: "Lattice", KeySize: 0, Status: SAFE},

		// === SLH-DSA (FIPS 205) — 12 variants: sha2/shake x 128/192/256 x s/f ===
		"2.16.840.1.101.3.4.3.20": {OID: "2.16.840.1.101.3.4.3.20", Algorithm: "SLH-DSA-SHA2-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.21": {OID: "2.16.840.1.101.3.4.3.21", Algorithm: "SLH-DSA-SHA2-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.22": {OID: "2.16.840.1.101.3.4.3.22", Algorithm: "SLH-DSA-SHA2-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.23": {OID: "2.16.840.1.101.3.4.3.23", Algorithm: "SLH-DSA-SHA2-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.24": {OID: "2.16.840.1.101.3.4.3.24", Algorithm: "SLH-DSA-SHA2-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.3.25": {OID: "2.16.840.1.101.3.4.3.25", Algorithm: "SLH-DSA-SHA2-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.3.26": {OID: "2.16.840.1.101.3.4.3.26", Algorithm: "SLH-DSA-SHAKE-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.27": {OID: "2.16.840.1.101.3.4.3.27", Algorithm: "SLH-DSA-SHAKE-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.28": {OID: "2.16.840.1.101.3.4.3.28", Algorithm: "SLH-DSA-SHAKE-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.29": {OID: "2.16.840.1.101.3.4.3.29", Algorithm: "SLH-DSA-SHAKE-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.30": {OID: "2.16.840.1.101.3.4.3.30", Algorithm: "SLH-DSA-SHAKE-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.3.31": {OID: "2.16.840.1.101.3.4.3.31", Algorithm: "SLH-DSA-SHAKE-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE},

		// === Composite Signature OIDs (IETF LAMPS draft-ietf-lamps-pq-composite-sigs) ===
		"2.16.840.1.114027.80.8.1.1":  {OID: "2.16.840.1.114027.80.8.1.1", Algorithm: "ML-DSA-44-RSA-2048", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.2":  {OID: "2.16.840.1.114027.80.8.1.2", Algorithm: "ML-DSA-44-RSA-2048-PSS", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.3":  {OID: "2.16.840.1.114027.80.8.1.3", Algorithm: "ML-DSA-44-Ed25519", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.4":  {OID: "2.16.840.1.114027.80.8.1.4", Algorithm: "ML-DSA-44-ECDSA-P256", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.5":  {OID: "2.16.840.1.114027.80.8.1.5", Algorithm: "ML-DSA-65-RSA-3072", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.6":  {OID: "2.16.840.1.114027.80.8.1.6", Algorithm: "ML-DSA-65-RSA-3072-PSS", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.7":  {OID: "2.16.840.1.114027.80.8.1.7", Algorithm: "ML-DSA-65-RSA-4096", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.8":  {OID: "2.16.840.1.114027.80.8.1.8", Algorithm: "ML-DSA-65-RSA-4096-PSS", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.9":  {OID: "2.16.840.1.114027.80.8.1.9", Algorithm: "ML-DSA-65-ECDSA-P384", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.10": {OID: "2.16.840.1.114027.80.8.1.10", Algorithm: "ML-DSA-65-Ed25519", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.11": {OID: "2.16.840.1.114027.80.8.1.11", Algorithm: "ML-DSA-87-ECDSA-P384", Family: "Composite", KeySize: 0, Status: SAFE},
		"2.16.840.1.114027.80.8.1.12": {OID: "2.16.840.1.114027.80.8.1.12", Algorithm: "ML-DSA-87-Ed448", Family: "Composite", KeySize: 0, Status: SAFE},

		// === Classical algorithms (for reference/cross-lookup) ===
		"1.2.840.113549.1.1.1":  {OID: "1.2.840.113549.1.1.1", Algorithm: "RSA", Family: "RSA", KeySize: 0, Status: TRANSITIONAL},
		"1.2.840.113549.1.1.11": {OID: "1.2.840.113549.1.1.11", Algorithm: "SHA256-RSA", Family: "RSA", KeySize: 0, Status: TRANSITIONAL},
		"1.2.840.113549.1.1.12": {OID: "1.2.840.113549.1.1.12", Algorithm: "SHA384-RSA", Family: "RSA", KeySize: 0, Status: TRANSITIONAL},
		"1.2.840.113549.1.1.13": {OID: "1.2.840.113549.1.1.13", Algorithm: "SHA512-RSA", Family: "RSA", KeySize: 0, Status: TRANSITIONAL},
		"1.2.840.10045.2.1":     {OID: "1.2.840.10045.2.1", Algorithm: "EC", Family: "ECDSA", KeySize: 0, Status: TRANSITIONAL},
		"1.3.101.112":           {OID: "1.3.101.112", Algorithm: "Ed25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.101.113":           {OID: "1.3.101.113", Algorithm: "Ed448", Family: "EdDSA", KeySize: 448, Status: TRANSITIONAL},
	}

	// Build reverse map: algorithm name → OID
	reverseOIDMap = make(map[string]string, len(oidRegistry))
	for oid, entry := range oidRegistry {
		reverseOIDMap[entry.Algorithm] = oid
	}
}

// OIDForAlgorithm returns the OID string for a given canonical algorithm name, or "" if not found.
func OIDForAlgorithm(algorithm string) string {
	return reverseOIDMap[algorithm]
}

// LookupOID returns the OID entry for a given OID string. O(1) map lookup.
func LookupOID(oid string) (OIDEntry, bool) {
	entry, ok := oidRegistry[oid]
	return entry, ok
}

// IsCompositeOID returns true if the OID represents a composite/hybrid algorithm.
func IsCompositeOID(oid string) bool {
	entry, ok := oidRegistry[oid]
	return ok && entry.Family == "Composite"
}

// compositeMap maps composite algorithm names to their two component algorithms.
var compositeMap = map[string][2]string{
	"ML-DSA-44-RSA-2048":     {"ML-DSA-44", "RSA-2048"},
	"ML-DSA-44-RSA-2048-PSS": {"ML-DSA-44", "RSA-2048"},
	"ML-DSA-44-Ed25519":      {"ML-DSA-44", "Ed25519"},
	"ML-DSA-44-ECDSA-P256":   {"ML-DSA-44", "ECDSA-P256"},
	"ML-DSA-65-RSA-3072":     {"ML-DSA-65", "RSA-3072"},
	"ML-DSA-65-RSA-3072-PSS": {"ML-DSA-65", "RSA-3072"},
	"ML-DSA-65-RSA-4096":     {"ML-DSA-65", "RSA-4096"},
	"ML-DSA-65-RSA-4096-PSS": {"ML-DSA-65", "RSA-4096"},
	"ML-DSA-65-ECDSA-P384":   {"ML-DSA-65", "ECDSA-P384"},
	"ML-DSA-65-Ed25519":      {"ML-DSA-65", "Ed25519"},
	"ML-DSA-87-ECDSA-P384":   {"ML-DSA-87", "ECDSA-P384"},
	"ML-DSA-87-Ed448":        {"ML-DSA-87", "Ed448"},
}

// CompositeComponents returns the two component algorithm names from a composite OID.
// For example, "ML-DSA-65-ECDSA-P384" → ["ML-DSA-65", "ECDSA-P384"].
func CompositeComponents(algorithm string) []string {
	if components, ok := compositeMap[algorithm]; ok {
		return components[:]
	}
	return nil
}

// extractSignatureOID extracts the signature algorithm OID from a DER-encoded X.509 certificate.
// It parses the outermost SEQUENCE → first inner SEQUENCE (TBSCertificate) → skip version →
// skip serialNumber → signature AlgorithmIdentifier → OID.
func ExtractSignatureOID(rawDER []byte) string {
	// Parse outer SEQUENCE
	rest, ok := parseSequence(rawDER)
	if !ok {
		return ""
	}

	// Parse TBSCertificate SEQUENCE
	tbsContent, ok := parseSequence(rest)
	if !ok {
		return ""
	}

	// Skip optional version [0] EXPLICIT
	pos := 0
	if pos < len(tbsContent) && tbsContent[pos] == 0xA0 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Skip serialNumber (INTEGER)
	if pos < len(tbsContent) && tbsContent[pos] == 0x02 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Parse signature AlgorithmIdentifier SEQUENCE
	if pos >= len(tbsContent) {
		return ""
	}
	sigAlgContent, ok := parseSequence(tbsContent[pos:])
	if !ok {
		return ""
	}

	// Parse OID within AlgorithmIdentifier
	return parseOID(sigAlgContent)
}

// extractPublicKeyOID extracts the public key algorithm OID from a DER-encoded X.509 certificate.
// Navigates: outer SEQUENCE → TBSCertificate → skip to SubjectPublicKeyInfo → AlgorithmIdentifier → OID.
func ExtractPublicKeyOID(rawDER []byte) string {
	// Parse outer SEQUENCE
	rest, ok := parseSequence(rawDER)
	if !ok {
		return ""
	}

	// Parse TBSCertificate SEQUENCE
	tbsContent, ok := parseSequence(rest)
	if !ok {
		return ""
	}

	pos := 0
	// Skip optional version [0] EXPLICIT
	if pos < len(tbsContent) && tbsContent[pos] == 0xA0 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Skip serialNumber (INTEGER)
	if pos < len(tbsContent) && tbsContent[pos] == 0x02 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Skip signature AlgorithmIdentifier (SEQUENCE)
	if pos < len(tbsContent) && tbsContent[pos] == 0x30 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Skip issuer (SEQUENCE)
	if pos < len(tbsContent) && tbsContent[pos] == 0x30 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Skip validity (SEQUENCE)
	if pos < len(tbsContent) && tbsContent[pos] == 0x30 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Skip subject (SEQUENCE)
	if pos < len(tbsContent) && tbsContent[pos] == 0x30 {
		_, consumed := parseTagLength(tbsContent[pos:])
		pos += consumed
	}

	// Parse SubjectPublicKeyInfo (SEQUENCE)
	if pos >= len(tbsContent) {
		return ""
	}
	spkiContent, ok := parseSequence(tbsContent[pos:])
	if !ok {
		return ""
	}

	// Parse AlgorithmIdentifier within SPKI (first SEQUENCE)
	algIdContent, ok := parseSequence(spkiContent)
	if !ok {
		return ""
	}

	return parseOID(algIdContent)
}

// parseSequence parses a SEQUENCE tag at the start of data, returns the content bytes.
func parseSequence(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != 0x30 {
		return nil, false
	}
	content, consumed := parseTagLength(data)
	if consumed == 0 {
		return nil, false
	}
	return content, true
}

// parseTagLength parses an ASN.1 tag + length, returns content bytes and total consumed bytes.
func parseTagLength(data []byte) (content []byte, consumed int) {
	if len(data) < 2 {
		return nil, 0
	}

	// Skip tag byte
	pos := 1

	// Parse length
	length := 0
	if data[pos]&0x80 == 0 {
		// Short form
		length = int(data[pos])
		pos++
	} else {
		// Long form
		numBytes := int(data[pos] & 0x7F)
		pos++
		if numBytes == 0 || numBytes > 4 || pos+numBytes > len(data) {
			return nil, 0
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[pos])
			pos++
		}
	}

	if pos+length > len(data) {
		return nil, 0
	}

	return data[pos : pos+length], pos + length
}

// parseOID parses an OID from the start of data (expects tag 0x06).
// Returns the OID as a dotted string, e.g. "2.16.840.1.101.3.4.3.17".
func parseOID(data []byte) string {
	if len(data) < 2 || data[0] != 0x06 {
		return ""
	}

	length := int(data[1])
	if 2+length > len(data) {
		return ""
	}

	oidBytes := data[2 : 2+length]
	return decodeOID(oidBytes)
}

// decodeOID decodes raw OID bytes into a dotted string.
func decodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// First byte encodes first two components
	result := make([]byte, 0, 64)
	first := int(data[0]) / 40
	second := int(data[0]) % 40
	result = appendInt(result, first)
	result = append(result, '.')
	result = appendInt(result, second)

	// Subsequent bytes encode remaining components in base-128
	value := 0
	for i := 1; i < len(data); i++ {
		value = (value << 7) | int(data[i]&0x7F)
		if data[i]&0x80 == 0 {
			result = append(result, '.')
			result = appendInt(result, value)
			value = 0
		}
	}

	return string(result)
}

// appendInt appends an integer as decimal string to a byte slice.
func appendInt(b []byte, v int) []byte {
	if v == 0 {
		return append(b, '0')
	}

	// Calculate number of digits
	tmp := v
	digits := 0
	for tmp > 0 {
		digits++
		tmp /= 10
	}

	start := len(b)
	for i := 0; i < digits; i++ {
		b = append(b, 0)
	}

	for i := digits - 1; i >= 0; i-- {
		b[start+i] = byte('0' + v%10)
		v /= 10
	}

	return b
}
