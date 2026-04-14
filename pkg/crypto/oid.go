package crypto

import "strconv"

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
	oidRegistry = make(map[string]OIDEntry)
	for oid, entry := range classicalOIDs() {
		oidRegistry[oid] = entry
	}
	for oid, entry := range pqcOIDs() {
		oidRegistry[oid] = entry
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

	// Parse length (supports short and long form)
	pos := 1
	length := 0
	if data[pos]&0x80 == 0 {
		length = int(data[pos])
		pos++
	} else {
		numBytes := int(data[pos] & 0x7F)
		pos++
		if numBytes == 0 || numBytes > 4 || pos+numBytes > len(data) {
			return ""
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[pos])
			pos++
		}
	}

	if pos+length > len(data) {
		return ""
	}

	oidBytes := data[pos : pos+length]
	return decodeOID(oidBytes)
}

// decodeOID decodes raw OID bytes into a dotted string.
func decodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// Reject truncated arc encoding: last byte must not have continuation bit set.
	// Matches the validity rule in asn1.go's tryDecodeOIDAt.
	if data[len(data)-1]&0x80 != 0 {
		return ""
	}

	// Decode first component. If data[0] has the continuation bit set, the
	// first ASN.1 component uses multi-byte base-128 encoding — valid only for
	// firstArc==2 with secondArc >= 48 (combined value >= 128).
	var combined int
	i := 0
	for i < len(data) {
		// Guard: bound combined so that combined << 7 on the next iteration cannot overflow int.
		// Max safe pre-shift value is (1<<56); after << 7 this yields (1<<63) which still fits in int64.
		if combined > 1<<56 {
			return ""
		}
		b := data[i]
		combined = (combined << 7) | int(b&0x7F)
		i++
		if b&0x80 == 0 {
			break
		}
	}
	if i == 0 {
		return ""
	}

	// Split combined value into first and second arc per X.690 §8.19.4.
	var firstArc, secondArc int
	switch {
	case combined < 40:
		firstArc, secondArc = 0, combined
	case combined < 80:
		firstArc, secondArc = 1, combined-40
	default:
		firstArc, secondArc = 2, combined-80
	}

	result := make([]byte, 0, 64)
	result = appendInt(result, firstArc)
	result = append(result, '.')
	result = appendInt(result, secondArc)

	// Remaining bytes encode remaining components in base-128
	value := 0
	for ; i < len(data); i++ {
		// Guard: bound value so that value << 7 on the next iteration cannot overflow int.
		// Max safe pre-shift value is (1<<56); after << 7 this yields (1<<63) which still fits in int64.
		if value > 1<<56 {
			return ""
		}
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
	return strconv.AppendInt(b, int64(v), 10)
}
