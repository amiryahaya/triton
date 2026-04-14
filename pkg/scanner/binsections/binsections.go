// Package binsections extracts read-only data sections from ELF, Mach-O, and PE
// binaries. Used by the OID byte scanner to scope its search to sections that
// legitimately contain constant data (avoiding code, stacks, heaps).
package binsections

import (
	"bytes"
	"errors"
	"os"
)

// Section is a named read-only byte region extracted from a binary.
type Section struct {
	Name string
	Data []byte
}

var (
	elfMagic   = []byte{0x7f, 'E', 'L', 'F'}
	machoMagic = [][]byte{
		{0xCF, 0xFA, 0xED, 0xFE}, // 64-bit
		{0xFE, 0xED, 0xFA, 0xCF}, // 64-bit swap
		{0xCE, 0xFA, 0xED, 0xFE}, // 32-bit
		{0xCA, 0xFE, 0xBA, 0xBE}, // universal/fat
	}
	peMagic = []byte{'M', 'Z'}
)

// ErrUnsupportedFormat is returned for files that aren't ELF/Mach-O/PE.
var ErrUnsupportedFormat = errors.New("binsections: unsupported binary format")

// ExtractSections inspects the first 4 bytes of path, dispatches to the
// correct format-specific extractor, and returns the read-only sections.
func ExtractSections(path string) ([]Section, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var header [4]byte
	n, _ := f.Read(header[:])
	_ = f.Close()
	if n < 2 {
		return nil, ErrUnsupportedFormat
	}

	switch {
	case n >= 4 && bytes.Equal(header[:4], elfMagic):
		return ExtractELFSections(path)
	case n >= 4 && isMachOMagic(header[:4]):
		return ExtractMachOSections(path)
	case bytes.Equal(header[:2], peMagic):
		return ExtractPESections(path)
	}
	return nil, ErrUnsupportedFormat
}

func isMachOMagic(h []byte) bool {
	for _, m := range machoMagic {
		if bytes.Equal(h, m) {
			return true
		}
	}
	return false
}
