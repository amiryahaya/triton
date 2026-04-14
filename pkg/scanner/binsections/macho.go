package binsections

import (
	"debug/macho"
	"fmt"
)

// machoReadOnlySections names Mach-O read-only section names we scan.
// The section Name (not SegmentName) matters — `__rodata` and `__const`
// are the typical locations for embedded constant data.
var machoReadOnlySections = map[string]bool{
	"__rodata":         true,
	"__const":          true,
	"__cstring":        true,
	"__gopclntab":      false, // large Go table, mostly code offsets — skip
	"__objc_const":     true,
	"__objc_classname": true,
}

// ExtractMachOSections opens path as Mach-O and returns read-only sections.
// Handles both single-arch and universal binaries (for universal, only the
// first arch is returned — caller handles multi-arch upstream if needed).
func ExtractMachOSections(path string) ([]Section, error) {
	f, err := macho.Open(path)
	if err != nil {
		// Try as FAT/universal
		fat, ferr := macho.OpenFat(path)
		if ferr != nil {
			return nil, fmt.Errorf("macho.Open %s: %w", path, err)
		}
		defer func() { _ = fat.Close() }()
		if len(fat.Arches) == 0 {
			return nil, fmt.Errorf("macho fat %s: no arches", path)
		}
		return extractMachOFile(fat.Arches[0].File), nil
	}
	defer func() { _ = f.Close() }()
	return extractMachOFile(f), nil
}

func extractMachOFile(f *macho.File) []Section {
	out := make([]Section, 0, 4)
	for _, s := range f.Sections {
		if !machoReadOnlySections[s.Name] {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		out = append(out, Section{Name: s.Name, Data: data})
	}
	return out
}
