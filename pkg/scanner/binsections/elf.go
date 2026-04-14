package binsections

import (
	"debug/elf"
	"fmt"
)

// elfReadOnlySections lists section names commonly holding constant data
// where OIDs and other embedded literals live. Scanning only these sections
// (vs the whole file) cuts false positives from .text (code) and .data
// (mutable globals) by ~100x.
var elfReadOnlySections = map[string]bool{
	".rodata":            true,
	".rodata1":           true,
	".data.rel.ro":       true,
	".data.rel.ro.local": true,
	".gnu.linkonce.r":    true,
}

// ExtractELFSections opens path as ELF and returns a Section for each
// read-only data section. Returns a non-nil error if the file is not valid
// ELF or cannot be read.
func ExtractELFSections(path string) ([]Section, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elf.Open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	out := make([]Section, 0, 4)
	for _, s := range f.Sections {
		if !elfReadOnlySections[s.Name] {
			continue
		}
		// SHT_NOBITS sections have no on-disk bytes — skip.
		if s.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		out = append(out, Section{Name: s.Name, Data: data})
	}
	return out, nil
}
