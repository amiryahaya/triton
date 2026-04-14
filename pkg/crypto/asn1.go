package crypto

import (
	"strconv"
	"strings"
)

// FoundOID represents a single OID discovered in a byte buffer.
type FoundOID struct {
	OID    string // Dotted decimal form, e.g. "1.2.840.113549.1.1.11"
	Offset int    // Byte offset in the source buffer where the OID DER tag began
	Length int    // Total DER byte length (tag + length + content)
}

// Validity limits for DER OID filtering. Tuned to reject obvious false positives
// without excluding real crypto OIDs. OIDs in the crypto domain have
// 3-20 arcs with content length 3-30 bytes.
const (
	minOIDContentLen = 3
	maxOIDContentLen = 30
	minArcCount      = 3
	maxArcCount      = 20
)

// FindOIDsInBuffer scans buf for DER-encoded OBJECT IDENTIFIER tags (0x06)
// and returns every hit whose decoded form passes false-positive filters.
// The scanner is byte-offset-based — it does not assume structural ASN.1
// context around the tag, which is what makes it useful for walking .rodata
// sections of stripped binaries where OIDs are embedded as table entries.
func FindOIDsInBuffer(buf []byte) []FoundOID {
	var out []FoundOID
	n := len(buf)
	for i := 0; i < n-1; i++ {
		if buf[i] != 0x06 {
			continue
		}
		oid, total, ok := tryDecodeOIDAt(buf, i)
		if !ok {
			continue
		}
		out = append(out, FoundOID{OID: oid, Offset: i, Length: total})
		// Do NOT skip to i+total — overlapping valid OIDs are rare, but
		// advancing by 1 makes the scan strictly inclusive at the cost of a
		// few wasted cycles on 9-byte buffers. That's fine.
	}
	return out
}

// tryDecodeOIDAt attempts to decode a DER OID starting at offset. Returns
// the OID, total bytes consumed (tag+len+content), and ok=false if any
// validity rule fails.
func tryDecodeOIDAt(buf []byte, offset int) (string, int, bool) {
	if offset+2 > len(buf) || buf[offset] != 0x06 {
		return "", 0, false
	}

	// Length parsing — only short form accepted. Long form is legal DER but
	// rare for OIDs (all real crypto OIDs fit in <128 content bytes) and
	// accepting it would widen the false-positive surface dramatically.
	lenByte := buf[offset+1]
	if lenByte&0x80 != 0 {
		return "", 0, false
	}
	contentLen := int(lenByte)
	if contentLen < minOIDContentLen || contentLen > maxOIDContentLen {
		return "", 0, false
	}
	if offset+2+contentLen > len(buf) {
		return "", 0, false
	}

	content := buf[offset+2 : offset+2+contentLen]

	// Continuation-bit sanity: last byte of content MUST have high bit clear
	// (it terminates the last arc). If not, this isn't a valid OID.
	if content[len(content)-1]&0x80 != 0 {
		return "", 0, false
	}

	// First-arc validation: X.690 restricts first arc to {0, 1, 2}.
	first := int(content[0])
	firstArc := first / 40
	secondArc := first % 40
	if firstArc > 2 {
		return "", 0, false
	}
	if firstArc < 2 && secondArc >= 40 {
		return "", 0, false
	}

	// Decode arcs
	arcs := make([]string, 0, 8)
	arcs = append(arcs, strconv.Itoa(firstArc), strconv.Itoa(secondArc))
	var v uint64
	for i := 1; i < len(content); i++ {
		if v > (1 << 56) { // overflow guard
			return "", 0, false
		}
		v = (v << 7) | uint64(content[i]&0x7F)
		if content[i]&0x80 == 0 {
			arcs = append(arcs, strconv.FormatUint(v, 10))
			v = 0
		}
	}

	if len(arcs) < minArcCount || len(arcs) > maxArcCount {
		return "", 0, false
	}

	return strings.Join(arcs, "."), 2 + contentLen, true
}
