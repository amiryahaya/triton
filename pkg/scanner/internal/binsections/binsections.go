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

// LooksLikeBinary reports whether the first 4 bytes of path match ELF,
// Mach-O (any variant, including fat), or PE. Returns false on any read
// error or unknown format. Intended as a cheap pre-filter during
// filesystem walks before calling ExtractSections.
//
// TODO: pkg/scanner/binary.go carries its own copy of these magic
// constants. Once that module is refactored to share a single source of
// truth, delete the duplicates there.
func LooksLikeBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var header [4]byte
	n, _ := f.Read(header[:])
	if n < 2 {
		return false
	}
	if n >= 4 && bytes.Equal(header[:4], elfMagic) {
		return true
	}
	if n >= 4 && isMachOMagic(header[:4]) {
		return true
	}
	if bytes.Equal(header[:2], peMagic) {
		return true
	}
	return false
}
