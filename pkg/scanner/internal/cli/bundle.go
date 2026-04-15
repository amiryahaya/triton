package cli

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
)

// BundledAssembly is one DLL extracted from a single-file bundle.
type BundledAssembly struct {
	Path     string
	Assembly *Assembly
}

// bundleMarker is the 16-byte SHA-256-prefix marker the .NET single-file host
// writes at the very end of the bundle.
var bundleMarker = []byte{
	0x8B, 0x17, 0xFF, 0x58, 0x9D, 0x19, 0xFA, 0x3A,
	0x4D, 0x2E, 0x6E, 0x7E, 0xCB, 0x55, 0x77, 0x59,
}

const (
	maxBundleEntries  = 2000
	maxBundleEntry    = 32 * 1024 * 1024 // 32 MB per inner assembly
	bundleScanWindow  = 64 * 1024
	maxBundleHostSize = 256 * 1024 * 1024 // 256 MB cap on host file size we'll fully read
)

// ScanBundle inspects the file at path. If it is a .NET single-file bundle,
// every inner .dll/.exe entry is parsed via ReadAssembly and returned. Files
// without the bundle marker return nil with no error.
func ScanBundle(path string) ([]BundledAssembly, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size < int64(len(bundleMarker)+8) {
		return nil, nil
	}

	windowSize := int64(bundleScanWindow)
	if windowSize > size {
		windowSize = size
	}
	tail := make([]byte, windowSize)
	if _, err := f.ReadAt(tail, size-windowSize); err != nil {
		return nil, fmt.Errorf("cli: read bundle tail: %w", err)
	}
	idx := bytes.LastIndex(tail, bundleMarker)
	if idx < 0 {
		return nil, nil
	}
	if idx < 8 {
		return nil, nil
	}
	hdrOff := binary.LittleEndian.Uint64(tail[idx-8 : idx])
	if hdrOff > uint64(size) || hdrOff > uint64(math.MaxInt64) {
		return nil, nil
	}

	hdrBuf := make([]byte, 12)
	if _, err := f.ReadAt(hdrBuf, int64(hdrOff)); err != nil {
		return nil, nil
	}
	major := binary.LittleEndian.Uint32(hdrBuf[0:4])
	if major < 1 || major > 10 {
		return nil, nil
	}
	fileCount := int32(binary.LittleEndian.Uint32(hdrBuf[8:12]))
	if fileCount <= 0 || fileCount > maxBundleEntries {
		return nil, nil
	}

	if size > int64(maxBundleHostSize) {
		return nil, nil // too large to safely scan via current heuristic
	}
	all := make([]byte, size)
	if _, err := f.ReadAt(all, 0); err != nil {
		return nil, err
	}

	// Constrain search to the bytes before the header so we don't match inside
	// the header/bundleID region.
	searchLimit := int(hdrOff)
	if searchLimit > len(all) {
		searchLimit = len(all)
	}

	out := make([]BundledAssembly, 0, fileCount)
	cursor := 0
	for i := int32(0); i < fileCount; i++ {
		if cursor >= searchLimit {
			break
		}
		match := findNextEntry(all[cursor:searchLimit])
		if match.length == 0 {
			break
		}
		entryStart := cursor + match.entryStart
		offset := binary.LittleEndian.Uint64(all[entryStart : entryStart+8])
		entrySize := binary.LittleEndian.Uint64(all[entryStart+8 : entryStart+16])
		if entrySize == 0 || entrySize > maxBundleEntry {
			cursor = entryStart + match.length
			continue
		}
		if offset > uint64(size) || entrySize > uint64(size)-offset || offset > uint64(math.MaxInt64) {
			cursor = entryStart + match.length
			continue
		}
		section := io.NewSectionReader(f, int64(offset), int64(entrySize))
		asm, err := ReadAssembly(section)
		if err == nil {
			out = append(out, BundledAssembly{Path: match.path, Assembly: asm})
		}
		cursor = entryStart + match.length
	}
	return out, nil
}

type entryMatch struct {
	entryStart int
	path       string
	length     int
}

// findNextEntry locates the next plausible bundle manifest entry within b.
// Entry layout: offset(u64), size(u64), compressed(u64), type(u8), pathLen(u8), path[pathLen].
// We search by looking for printable .dll/.exe paths preceded by a valid type+pathLen pair.
func findNextEntry(b []byte) entryMatch {
	for i := 0; i+26 < len(b); i++ {
		// Layout: offset(u64) at i+0, size(u64) at i+8, compressed(u64) at i+16,
		// type(u8) at i+24, pathLen(u8) at i+25, path at i+26.
		pathLen := int(b[i+25])
		if pathLen == 0 || pathLen > 200 {
			continue
		}
		if i+26+pathLen > len(b) {
			continue
		}
		path := string(b[i+26 : i+26+pathLen])
		if !looksLikeBundlePath(path) {
			continue
		}
		if b[i+24] < 1 || b[i+24] > 6 {
			continue
		}
		return entryMatch{entryStart: i, path: path, length: 26 + pathLen}
	}
	return entryMatch{}
}

func looksLikeBundlePath(p string) bool {
	for _, ext := range []string{".dll", ".exe"} {
		if len(p) > len(ext) && p[len(p)-len(ext):] == ext {
			return true
		}
	}
	return false
}
