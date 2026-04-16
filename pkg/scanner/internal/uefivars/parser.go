package uefivars

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// EFI_SIGNATURE_LIST header is 28 bytes: 16 (GUID) + 4 + 4 + 4.
const sigListHeaderSize = 28

// ParseSignatureList walks a concatenated chain of EFI_SIGNATURE_LIST records
// and returns each signature entry. Returns empty + nil on empty/nil input.
func ParseSignatureList(data []byte) ([]SignatureEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var entries []SignatureEntry
	off := 0
	listIdx := 0
	for off < len(data) {
		if off+sigListHeaderSize > len(data) {
			return nil, fmt.Errorf("uefivars: truncated signature list header at offset %d", off)
		}
		sigTypeGUID := guidToString(data[off : off+16])
		listSize := binary.LittleEndian.Uint32(data[off+16 : off+20])
		headerSize := binary.LittleEndian.Uint32(data[off+20 : off+24])
		sigSize := binary.LittleEndian.Uint32(data[off+24 : off+28])

		if listSize < sigListHeaderSize+headerSize || sigSize < 16 {
			return nil, fmt.Errorf("uefivars: invalid list at offset %d (listSize=%d headerSize=%d sigSize=%d)", off, listSize, headerSize, sigSize)
		}
		if off+int(listSize) > len(data) {
			return nil, fmt.Errorf("uefivars: list at offset %d claims %d bytes but only %d remain", off, listSize, len(data)-off)
		}

		sigType := classifyGUID(sigTypeGUID)
		bodyStart := off + sigListHeaderSize + int(headerSize)
		bodyEnd := off + int(listSize)
		entryIdx := 0
		for pos := bodyStart; pos+int(sigSize) <= bodyEnd; pos += int(sigSize) {
			ownerGUID := guidToString(data[pos : pos+16])
			sigData := make([]byte, sigSize-16)
			copy(sigData, data[pos+16:pos+int(sigSize)])
			entries = append(entries, SignatureEntry{
				Type:       sigType,
				OwnerGUID:  ownerGUID,
				Data:       sigData,
				ListIndex:  listIdx,
				EntryIndex: entryIdx,
			})
			entryIdx++
		}
		off += int(listSize)
		listIdx++
	}
	return entries, nil
}

// guidToString renders 16 mixed-endian GUID bytes as a lowercase dashed string.
func guidToString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	// Swap the mixed-endian fields back to big-endian for printing.
	out := make([]byte, 16)
	copy(out, b)
	out[0], out[3] = out[3], out[0]
	out[1], out[2] = out[2], out[1]
	out[4], out[5] = out[5], out[4]
	out[6], out[7] = out[7], out[6]
	h := hex.EncodeToString(out)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func classifyGUID(guid string) SignatureType {
	switch strings.ToLower(guid) {
	case CertX509GUID:
		return SigTypeX509
	case CertSHA256GUID:
		return SigTypeSHA256
	}
	return SigTypeUnknown
}
