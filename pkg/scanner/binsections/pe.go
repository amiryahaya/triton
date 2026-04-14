package binsections

import (
	"debug/pe"
	"fmt"
)

// peReadOnlySections lists PE section names typically holding constant data.
// `.rdata` is the primary location; some compilers also use `.rodata`.
var peReadOnlySections = map[string]bool{
	".rdata":  true,
	".rodata": true,
	".data":   false, // mutable globals, skip
}

// ExtractPESections opens path as PE/COFF and returns read-only sections.
func ExtractPESections(path string) ([]Section, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pe.Open %s: %w", path, err)
	}
	defer f.Close()

	out := make([]Section, 0, 4)
	for _, s := range f.Sections {
		if !peReadOnlySections[s.Name] {
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
