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
func tryDecodeOIDAt(buf []byte, offset int) (oid string, consumed int, ok bool) {
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

	// Decode first component. If content[0] has the continuation bit set, the
	// first ASN.1 component uses multi-byte base-128 encoding — valid only for
	// firstArc==2 with secondArc >= 48 (combined value >= 128).
	var combined uint64
	i := 0
	for i < len(content) {
		// Guard: bound combined so that combined << 7 on the next iteration cannot overflow uint64.
		// Max safe pre-shift value is (1<<56); after << 7 this yields (1<<63) which fits.
		if combined > (1 << 56) {
			return "", 0, false
		}
		b := content[i]
		combined = (combined << 7) | uint64(b&0x7F)
		i++
		if b&0x80 == 0 {
			break
		}
	}
	if i == 0 {
		return "", 0, false
	}

	// Split combined value into first and second arc per X.690 §8.19.4.
	var firstArc, secondArc uint64
	switch {
	case combined < 40:
		firstArc, secondArc = 0, combined
	case combined < 80:
		firstArc, secondArc = 1, combined-40
	default:
		firstArc, secondArc = 2, combined-80
	}

	arcs := make([]string, 0, 8)
	arcs = append(arcs, strconv.FormatUint(firstArc, 10), strconv.FormatUint(secondArc, 10))

	// Remaining arcs from offset i onward
	var v uint64
	for ; i < len(content); i++ {
		// Guard: bound v so that v << 7 on the next iteration cannot overflow uint64.
		// Max safe pre-shift value is (1<<56); after << 7 this yields (1<<63) which fits.
		if v > (1 << 56) {
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

// ClassifiedOID pairs a byte-scanner hit with its registry metadata.
type ClassifiedOID struct {
	FoundOID
	Entry OIDEntry
}

// ClassifyFoundOIDs filters a slice of FoundOID down to entries present in
// the OID registry and attaches their metadata. Unknown OIDs are dropped —
// emitting them would create unclassifiable findings that can't be acted on.
func ClassifyFoundOIDs(found []FoundOID) []ClassifiedOID {
	out := make([]ClassifiedOID, 0, len(found))
	for _, f := range found {
		entry, ok := oidRegistry[f.OID]
		if !ok {
			continue
		}
		out = append(out, ClassifiedOID{FoundOID: f, Entry: entry})
	}
	return out
}
