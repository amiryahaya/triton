package cli

import (
	"errors"
	"fmt"
	"unicode/utf16"
)

// readStringAt reads a null-terminated UTF-8 string from the #Strings heap
// starting at the given index. ECMA-335 §II.24.2.3.
func readStringAt(heap []byte, idx uint32) (string, error) {
	if int(idx) >= len(heap) {
		return "", fmt.Errorf("cli: #Strings index %d out of bounds (heap=%d)", idx, len(heap))
	}
	if idx == 0 {
		// ECMA-335 §II.24.2.3: index 0 is always the empty string.
		return "", nil
	}
	end := int(idx)
	for end < len(heap) && heap[end] != 0 {
		end++
	}
	return string(heap[idx:end]), nil
}

// parseUSHeap decodes every entry in the #US heap into a Go string.
// Each entry: compressed-length prefix, UTF-16LE bytes, optional 1-byte terminal.
// ECMA-335 §II.24.2.4.
func parseUSHeap(heap []byte) ([]string, error) {
	var out []string
	off := 0
	for off < len(heap) {
		n, consumed, err := readCompressedUInt(heap[off:])
		if err != nil {
			return nil, fmt.Errorf("cli: #US length at offset %d: %w", off, err)
		}
		off += consumed
		if n == 0 {
			continue
		}
		if off+int(n) > len(heap) {
			return nil, errors.New("cli: #US entry runs past end of heap")
		}
		payloadLen := int(n) - 1
		if payloadLen <= 0 || payloadLen%2 != 0 {
			off += int(n)
			continue
		}
		u16 := make([]uint16, payloadLen/2)
		for i := 0; i < payloadLen/2; i++ {
			u16[i] = uint16(heap[off+2*i]) | uint16(heap[off+2*i+1])<<8
		}
		out = append(out, string(utf16.Decode(u16)))
		off += int(n)
	}
	return out, nil
}

// readCompressedUInt decodes an ECMA-335 compressed unsigned integer
// (§II.23.2). Returns the value, bytes consumed, and any error.
func readCompressedUInt(b []byte) (value uint32, consumed int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("cli: empty compressed-uint buffer")
	}
	first := b[0]
	switch {
	case first&0x80 == 0:
		return uint32(first), 1, nil
	case first&0xC0 == 0x80:
		if len(b) < 2 {
			return 0, 0, errors.New("cli: truncated 2-byte compressed-uint")
		}
		return (uint32(first&0x3F) << 8) | uint32(b[1]), 2, nil
	case first&0xE0 == 0xC0:
		if len(b) < 4 {
			return 0, 0, errors.New("cli: truncated 4-byte compressed-uint")
		}
		return (uint32(first&0x1F) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | uint32(b[3]), 4, nil
	}
	return 0, 0, fmt.Errorf("cli: invalid compressed-uint lead byte 0x%02x", first)
}
