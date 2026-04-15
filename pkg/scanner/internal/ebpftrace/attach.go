package ebpftrace

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// discoveredLib represents one crypto library found loaded in a process address
// space, dedup'd by inode so uprobes attach once per physical file.
type discoveredLib struct {
	Path  string
	Inode string // keep as string (not uint64) since /proc/maps may be malformed
	LibID LibID
}

// cryptoLibMatchers lists substring patterns that identify supported libraries.
// Ordered by specificity: more-specific patterns first.
var cryptoLibMatchers = []struct {
	pattern string
	libID   LibID
}{
	{"libcrypto.so", LibLibcrypto},
	{"libgnutls.so", LibGnuTLS},
	{"libnss3.so", LibNSS},
}

// discoverLibsFromMaps parses /proc/PID/maps content and returns a dedup'd list
// of crypto libraries mapped into the process. Input is any io.Reader so tests
// can feed fixtures.
//
// /proc/PID/maps line format:
//
//	address-range perms offset dev inode pathname
//
// Example:
//
//	7f1234000000-7f1234050000 r-xp 00000000 08:01 262145 /usr/lib/libcrypto.so.3
func discoverLibsFromMaps(r io.Reader) ([]discoveredLib, error) {
	seen := map[string]bool{} // inode → seen
	out := []discoveredLib{}
	scanner := bufio.NewScanner(r)
	// /proc/maps lines can be long if the path has many components; raise the buffer.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// /proc/PID/maps lines have exactly 5 whitespace-separated fields
		// before the path; the path itself may contain spaces. Reconstruct
		// it from the remainder of the line rather than using fields[5].
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue // no path → not a file-backed mapping
		}
		inode := fields[4]
		firstFiveJoined := strings.Join(fields[:5], " ")
		pathStart := strings.Index(line, firstFiveJoined) + len(firstFiveJoined)
		path := strings.TrimSpace(line[pathStart:])
		// Files unlinked after mapping show up as "/path (deleted)".
		path = strings.TrimSuffix(path, " (deleted)")
		if inode == "0" {
			continue // anonymous mapping
		}
		matcher := matchCryptoLib(path)
		if matcher == nil {
			continue
		}
		if seen[inode] {
			continue
		}
		seen[inode] = true
		out = append(out, discoveredLib{Path: path, Inode: inode, LibID: matcher.libID})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ebpftrace: scan maps: %w", err)
	}
	return out, nil
}

func matchCryptoLib(path string) *struct {
	pattern string
	libID   LibID
} {
	for i := range cryptoLibMatchers {
		if strings.Contains(path, cryptoLibMatchers[i].pattern) {
			return &cryptoLibMatchers[i]
		}
	}
	return nil
}
