// Package javaclass parses Java class files (JVM spec §4.4) and extracts
// UTF-8 + String constant-pool entries. Used by the java_bytecode scanner
// to find algorithm literals embedded in compiled Java code, where source
// scanners can't reach after obfuscation or strip of debug info.
//
// This parser is deliberately minimal: it walks the header + constant
// pool only and stops. We don't decode method bytecode, attributes, or
// fields — the constant pool already contains every string literal a
// crypto API call can pass to JCA.
package javaclass

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// classMagic is the big-endian 4-byte header every JVM class file starts with.
var classMagic = []byte{0xCA, 0xFE, 0xBA, 0xBE}

// Constant pool tag values from JVM spec §4.4-A.
const (
	tagUtf8               = 1
	tagInteger            = 3
	tagFloat              = 4
	tagLong               = 5
	tagDouble             = 6
	tagClass              = 7
	tagString             = 8
	tagFieldref           = 9
	tagMethodref          = 10
	tagInterfaceMethodref = 11
	tagNameAndType        = 12
	tagMethodHandle       = 15
	tagMethodType         = 16
	tagDynamic            = 17
	tagInvokeDynamic      = 18
	tagModule             = 19
	tagPackage            = 20
)

// ErrNotClassFile is returned when the 4-byte header doesn't match.
var ErrNotClassFile = errors.New("javaclass: not a JVM class file (magic mismatch)")

// ParseClass reads a class file byte slice and returns every UTF-8 constant-pool
// string. Returns ErrNotClassFile if the magic is wrong, or a descriptive
// error if the constant pool is truncated.
//
// Strings are returned in the order they appear in the constant pool; duplicates
// are preserved so callers can dedupe as needed (the scanner dedupes at the
// finding level anyway).
func ParseClass(data []byte) ([]string, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("javaclass: file too short (%d bytes)", len(data))
	}
	if !equalMagic(data[:4]) {
		return nil, ErrNotClassFile
	}

	// Skip minor + major version (4 bytes). Then read constant_pool_count (u2).
	// Per spec, cpCount is one greater than the actual number of entries.
	off := 8
	cpCount := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if cpCount == 0 {
		return nil, fmt.Errorf("javaclass: constant_pool_count = 0 (invalid)")
	}

	// Entries are 1-indexed. cpCount-1 actual entries.
	out := make([]string, 0, cpCount/2)
	i := 1
	for i < cpCount {
		if off >= len(data) {
			return nil, fmt.Errorf("javaclass: truncated at cp entry %d/%d", i, cpCount-1)
		}
		tag := data[off]
		off++
		size, consumesTwoSlots, err := cpEntrySize(tag, data, off)
		if err != nil {
			return nil, fmt.Errorf("javaclass: cp entry %d: %w", i, err)
		}
		if tag == tagUtf8 {
			if off+2 > len(data) {
				return nil, fmt.Errorf("javaclass: utf8 length at entry %d truncated", i)
			}
			strLen := int(binary.BigEndian.Uint16(data[off : off+2]))
			start := off + 2
			end := start + strLen
			if end > len(data) {
				return nil, fmt.Errorf("javaclass: utf8 entry %d claims %d bytes, only %d remain", i, strLen, len(data)-start)
			}
			out = append(out, string(data[start:end]))
		}
		off += size
		i++
		if consumesTwoSlots {
			i++ // Long/Double consume two slots per §4.4.5.
		}
	}

	return out, nil
}

func equalMagic(b []byte) bool {
	if len(b) != 4 {
		return false
	}
	for i := range classMagic {
		if b[i] != classMagic[i] {
			return false
		}
	}
	return true
}

// cpEntrySize returns the size in bytes of a constant-pool entry body (excluding
// the tag byte, which has already been consumed). consumesTwoSlots is true for
// Long/Double which advance the pool index by 2 instead of 1.
func cpEntrySize(tag byte, data []byte, off int) (size int, consumesTwoSlots bool, err error) {
	switch tag {
	case tagUtf8:
		if off+2 > len(data) {
			return 0, false, fmt.Errorf("utf8 length header truncated")
		}
		strLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		return 2 + strLen, false, nil
	case tagInteger, tagFloat:
		return 4, false, nil
	case tagLong, tagDouble:
		return 8, true, nil
	case tagClass, tagString, tagMethodType, tagModule, tagPackage:
		return 2, false, nil
	case tagFieldref, tagMethodref, tagInterfaceMethodref,
		tagNameAndType, tagDynamic, tagInvokeDynamic:
		return 4, false, nil
	case tagMethodHandle:
		return 3, false, nil
	default:
		return 0, false, fmt.Errorf("unknown constant-pool tag %d", tag)
	}
}

// JARHit pairs a UTF-8 constant-pool string with the class path inside the
// JAR that produced it. Used by the scanner to attribute findings precisely.
type JARHit struct {
	ClassPath string // e.g. "com/example/Foo.class"
	Value     string
}

// ScanJAR walks a JAR/WAR/EAR (ZIP archive) and returns every UTF-8
// constant-pool string from every .class entry it contains. Non-class
// entries are ignored. Manifest parsing is a separate function.
//
// Large JARs are processed lazily — entries are read one at a time, so
// memory stays bounded to the largest individual .class file.
func ScanJAR(path string) ([]JARHit, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("javaclass: open %s: %w", path, err)
	}
	defer func() { _ = r.Close() }()

	var hits []JARHit
	for _, f := range r.File {
		if !isClassEntry(f.Name) {
			continue
		}
		strs, err := readClassFromZip(f)
		if err != nil {
			// Don't abort the whole JAR on one bad class — skip and continue.
			continue
		}
		for _, s := range strs {
			hits = append(hits, JARHit{ClassPath: f.Name, Value: s})
		}
	}
	return hits, nil
}

func isClassEntry(name string) bool {
	n := len(name)
	return n > 6 && name[n-6:] == ".class"
}

func readClassFromZip(f *zip.File) ([]string, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return ParseClass(data)
}
