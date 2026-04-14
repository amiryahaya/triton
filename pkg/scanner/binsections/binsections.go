// Package binsections extracts read-only data sections from ELF, Mach-O, and PE
// binaries. Used by the OID byte scanner to scope its search to sections that
// legitimately contain constant data (avoiding code, stacks, heaps).
package binsections

// Section is a named read-only byte region extracted from a binary.
type Section struct {
	Name string
	Data []byte
}
