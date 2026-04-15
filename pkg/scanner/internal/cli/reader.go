package cli

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ReadAssembly parses a .NET PE assembly and returns the union of its TypeRef
// names and #US user-string entries.
func ReadAssembly(r io.ReaderAt) (*Assembly, error) {
	mdOff, mdSize, err := LocateCLIMetadata(r)
	if err != nil {
		return nil, err
	}
	if mdSize > 64*1024*1024 {
		return nil, fmt.Errorf("cli: metadata size %d exceeds 64MB cap", mdSize)
	}
	metadata := make([]byte, mdSize)
	if _, err := r.ReadAt(metadata, int64(mdOff)); err != nil {
		return nil, fmt.Errorf("cli: read metadata blob: %w", err)
	}

	streams, err := parseStreamHeaders(metadata)
	if err != nil {
		return nil, err
	}

	a := &Assembly{}
	if tablesData, ok := streams["#~"]; ok {
		if stringsData, ok := streams["#Strings"]; ok {
			refs, err := parseTablesStream(tablesData, stringsData)
			if err == nil {
				a.TypeRefs = make([]string, 0, len(refs))
				for _, ref := range refs {
					a.TypeRefs = append(a.TypeRefs, ref.FullName())
				}
			}
		}
	}
	if usData, ok := streams["#US"]; ok {
		if us, err := parseUSHeap(usData); err == nil {
			a.UserStrings = us
		}
	}
	return a, nil
}

// parseStreamHeaders walks the metadata root and returns a map of stream
// name → stream-data slice (sliced from the metadata blob).
//
// ECMA-335 §II.24.2.1: metadata root layout is
//
//	uint32 signature ('BSJB'), uint16 major, uint16 minor, uint32 reserved,
//	uint32 length, byte[length] version (UTF-8, null-padded to 4-byte boundary),
//	uint16 flags, uint16 streams, then stream-header[streams]:
//	  uint32 offset (from metadata root), uint32 size, byte[] name
//	  (null-terminated UTF-8, padded with nulls to a 4-byte boundary).
func parseStreamHeaders(metadata []byte) (map[string][]byte, error) {
	if len(metadata) < 20 {
		return nil, fmt.Errorf("cli: metadata too short")
	}
	off := 12 // skip signature(4) + major(2) + minor(2) + reserved(4)
	versionLen := binary.LittleEndian.Uint32(metadata[off:])
	if versionLen > 255 {
		return nil, fmt.Errorf("cli: metadata version length %d exceeds 255 (ECMA-335 §II.24.2.1)", versionLen)
	}
	off += 4 + int(versionLen)
	if off+4 > len(metadata) {
		return nil, fmt.Errorf("cli: metadata header truncated past version")
	}
	off += 2 // flags
	streamCount := binary.LittleEndian.Uint16(metadata[off:])
	off += 2

	out := make(map[string][]byte, streamCount)
	for i := uint16(0); i < streamCount; i++ {
		if off+8 > len(metadata) {
			return nil, fmt.Errorf("cli: stream header %d truncated", i)
		}
		streamOff := binary.LittleEndian.Uint32(metadata[off:])
		streamSize := binary.LittleEndian.Uint32(metadata[off+4:])
		off += 8

		// Scan the null-terminated name.
		nameStart := off
		for off < len(metadata) && metadata[off] != 0 {
			off++
		}
		if off >= len(metadata) {
			return nil, fmt.Errorf("cli: stream header %d name unterminated", i)
		}
		name := string(metadata[nameStart:off])

		// Total name-field length (including null) is rounded up to a 4-byte
		// multiple. We're currently at the null byte; advance past it plus any
		// trailing padding.
		nameBytesIncludingNull := off - nameStart + 1
		padded := ((nameBytesIncludingNull + 3) / 4) * 4
		off = nameStart + padded

		if int(streamOff)+int(streamSize) > len(metadata) {
			continue
		}
		out[name] = metadata[streamOff : streamOff+streamSize]
	}
	return out, nil
}
