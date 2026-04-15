package cli

import (
	"encoding/binary"
	"fmt"
)

const (
	tableTypeRef     = 0x01
	tableAssemblyRef = 0x23

	heapSizeStringsBit = 0x01
	heapSizeGUIDBit    = 0x02
	heapSizeBlobBit    = 0x04
)

// parseTablesStream walks the #~ stream and returns every TypeRef row resolved
// against the #Strings heap. Ignores ResolutionScope (assembly attribution).
func parseTablesStream(tables, strings []byte) ([]TypeRef, error) {
	if len(tables) < 24 {
		return nil, fmt.Errorf("cli: #~ stream too short (%d bytes)", len(tables))
	}
	if reserved := binary.LittleEndian.Uint32(tables[0:4]); reserved != 0 {
		return nil, fmt.Errorf("cli: #~ reserved field is 0x%08x, want 0", reserved)
	}
	heapSizes := tables[6]
	stringsIdxSize := 2
	if heapSizes&heapSizeStringsBit != 0 {
		stringsIdxSize = 4
	}
	guidIdxSize := 2
	if heapSizes&heapSizeGUIDBit != 0 {
		guidIdxSize = 4
	}
	_ = guidIdxSize

	validMask := binary.LittleEndian.Uint64(tables[8:16])
	off := 24

	rowCounts := make(map[int]uint32)
	for bit := 0; bit < 64; bit++ {
		if validMask&(1<<bit) == 0 {
			continue
		}
		if off+4 > len(tables) {
			return nil, fmt.Errorf("cli: row count for table 0x%02x truncated", bit)
		}
		rowCounts[bit] = binary.LittleEndian.Uint32(tables[off : off+4])
		off += 4
	}

	// ResolutionScope coded index: small (2 bytes) when each referenced table fits in 2^14 rows.
	maxResScope := uint32(0)
	for _, t := range []int{0x00, tableAssemblyRef, 0x1A, tableTypeRef} {
		if rowCounts[t] > maxResScope {
			maxResScope = rowCounts[t]
		}
	}
	resScopeSize := 2
	if maxResScope >= (1 << 14) {
		resScopeSize = 4
	}

	// Skip every table that comes before TypeRef (only Module=0x00).
	rowSizes := map[int]int{
		0x00: 2 + stringsIdxSize + 3*guidIdxSize, // Module: Generation, Name, Mvid, EncId, EncBaseId
	}
	for bit := 0; bit < tableTypeRef; bit++ {
		off += int(rowCounts[bit]) * rowSizes[bit]
	}

	typeRefRows := rowCounts[tableTypeRef]
	typeRefRowSize := resScopeSize + 2*stringsIdxSize
	if off+int(typeRefRows)*typeRefRowSize > len(tables) {
		return nil, fmt.Errorf("cli: TypeRef table truncated")
	}

	out := make([]TypeRef, 0, typeRefRows)
	for i := uint32(0); i < typeRefRows; i++ {
		off += resScopeSize
		nameIdx := readHeapIndex(tables[off:], stringsIdxSize)
		off += stringsIdxSize
		nsIdx := readHeapIndex(tables[off:], stringsIdxSize)
		off += stringsIdxSize

		name, err := readStringAt(strings, nameIdx)
		if err != nil {
			continue
		}
		ns, err := readStringAt(strings, nsIdx)
		if err != nil {
			continue
		}
		out = append(out, TypeRef{Namespace: ns, Name: name})
	}
	return out, nil
}

func readHeapIndex(b []byte, size int) uint32 {
	if size == 4 {
		return binary.LittleEndian.Uint32(b[:4])
	}
	return uint32(binary.LittleEndian.Uint16(b[:2]))
}
