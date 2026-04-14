package fsadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CommandExecutor runs a command and returns combined stdout. Kept as
// an interface (not directly importing netadapter.CommandRunner) to
// avoid an import cycle and allow easy mocking in tests.
type CommandExecutor interface {
	Run(ctx context.Context, command string) (string, error)
}

// SshReader reads files and walks directories on a remote host by
// executing commands over an SSH connection. Binary-safe via base64.
type SshReader struct {
	exec CommandExecutor
}

// NewSshReader wraps a command executor (typically an SSH client).
func NewSshReader(exec CommandExecutor) *SshReader {
	return &SshReader{exec: exec}
}

// ReadFile returns the contents of the file at path on the remote host.
// Uses base64 for binary-safe transport.
func (s *SshReader) ReadFile(ctx context.Context, path string) ([]byte, error) {
	quoted := shellQuote(path)
	// -w0 disables line wrapping on GNU base64; BSD/macOS base64 doesn't
	// wrap by default but accepts the flag on recent versions. Fall back
	// to plain `base64` if -w0 fails.
	cmd := fmt.Sprintf("base64 -w0 < %s 2>/dev/null || base64 < %s", quoted, quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh read %s: %w", path, err)
	}
	// Strip any stray newlines from BSD base64 output.
	out = strings.ReplaceAll(out, "\n", "")
	out = strings.TrimSpace(out)
	data, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return nil, fmt.Errorf("decode base64 for %s: %w", path, err)
	}
	return data, nil
}

// Stat returns file metadata. Runs `stat -c` (GNU) with a fallback to
// `stat -f` (BSD/macOS).
func (s *SshReader) Stat(ctx context.Context, path string) (fs.FileInfo, error) {
	quoted := shellQuote(path)
	// Format: size\tmtime_unix\tmode_octal\ttype
	gnuFmt := "'%s\t%Y\t%a\t%F'"
	bsdFmt := "'%z\t%m\t%Lp\t%HT'"
	cmd := fmt.Sprintf("stat -c %s %s 2>/dev/null || stat -f %s %s",
		gnuFmt, quoted, bsdFmt, quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh stat %s: %w", path, err)
	}
	return parseStatOutput(filepath.Base(path), out)
}

// ReadDir returns the direct children of path. Used rarely; Walk is
// preferred for performance.
func (s *SshReader) ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error) {
	quoted := shellQuote(path)
	cmd := fmt.Sprintf("find %s -maxdepth 1 -mindepth 1 -printf '%%p\\t%%y\\t%%s\\n' 2>/dev/null", quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh readdir %s: %w", path, err)
	}
	return parseFindEntries(out), nil
}

// Walk recursively walks all entries under root using a SINGLE find
// command. This is the critical performance optimization: 50,000
// entries = one SSH round-trip, not 50,000.
func (s *SshReader) Walk(ctx context.Context, root string, fn WalkFunc) error {
	quoted := shellQuote(root)
	// Format: path\ttype\tsize\n (tab-separated fields, newline-separated records).
	cmd := fmt.Sprintf("find %s -printf '%%p\\t%%y\\t%%s\\n' 2>/dev/null", quoted)
	out, err := s.exec.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("ssh walk %s: %w", root, err)
	}

	// skipPrefixes tracks directories for which SkipDir was returned.
	// Because find emits a flat sorted list, we honor SkipDir by
	// filtering out any subsequent entry whose path is under a
	// skipped prefix. This preserves the filepath.WalkDir contract
	// for depth limits and exclude patterns.
	var skipPrefixes []string

	for _, line := range strings.Split(out, "\n") {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			continue
		}

		path := fields[0]
		// Skip any entry under a previously-pruned directory.
		if isUnderSkipped(path, skipPrefixes) {
			continue
		}

		size, _ := strconv.ParseInt(fields[2], 10, 64)
		entry := &remoteDirEntry{
			name:    filepath.Base(path),
			isDir:   fields[1] == "d",
			typeBit: typeFromFindCode(fields[1]),
			size:    size,
		}
		if err := fn(path, entry, nil); err != nil {
			if err == filepath.SkipDir {
				// Prune this subtree from future iterations.
				skipPrefixes = append(skipPrefixes, path)
				continue
			}
			return err
		}
	}
	return nil
}

// isUnderSkipped reports whether path is equal to or under any of the
// given prefixes (which are directory paths).
func isUnderSkipped(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p {
			return true
		}
		// Match "/etc/proc/foo" under "/etc/proc" but not "/etc/proc-helper".
		if strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// --- helpers ---

// shellQuote wraps a path in single-quotes, escaping embedded single quotes.
// Paths with any shell metacharacters are safely passed to POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// remoteDirEntry implements fs.DirEntry for SSH-walked entries.
type remoteDirEntry struct {
	name    string
	isDir   bool
	typeBit fs.FileMode
	size    int64
}

func (e *remoteDirEntry) Name() string      { return e.name }
func (e *remoteDirEntry) IsDir() bool       { return e.isDir }
func (e *remoteDirEntry) Type() fs.FileMode { return e.typeBit }
func (e *remoteDirEntry) Info() (fs.FileInfo, error) {
	return &remoteFileInfo{name: e.name, size: e.size, mode: e.typeBit}, nil
}

// remoteFileInfo implements fs.FileInfo.
type remoteFileInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	mtime time.Time
}

func (i *remoteFileInfo) Name() string       { return i.name }
func (i *remoteFileInfo) Size() int64        { return i.size }
func (i *remoteFileInfo) Mode() fs.FileMode  { return i.mode }
func (i *remoteFileInfo) ModTime() time.Time { return i.mtime }
func (i *remoteFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i *remoteFileInfo) Sys() any           { return nil }

// typeFromFindCode maps find -printf '%y' codes to fs.FileMode bits.
func typeFromFindCode(code string) fs.FileMode {
	switch code {
	case "d":
		return fs.ModeDir
	case "l":
		return fs.ModeSymlink
	case "p":
		return fs.ModeNamedPipe
	case "s":
		return fs.ModeSocket
	case "b":
		return fs.ModeDevice
	case "c":
		return fs.ModeDevice | fs.ModeCharDevice
	default:
		return 0 // regular file
	}
}

func parseFindEntries(out string) []fs.DirEntry {
	var entries []fs.DirEntry
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		size, _ := strconv.ParseInt(fields[2], 10, 64)
		entries = append(entries, &remoteDirEntry{
			name:    filepath.Base(fields[0]),
			isDir:   fields[1] == "d",
			typeBit: typeFromFindCode(fields[1]),
			size:    size,
		})
	}
	return entries
}

func parseStatOutput(name, out string) (fs.FileInfo, error) {
	fields := strings.Split(strings.TrimSpace(out), "\t")
	if len(fields) < 4 {
		return nil, fmt.Errorf("unexpected stat output: %q", out)
	}
	size, _ := strconv.ParseInt(fields[0], 10, 64)
	mtimeUnix, _ := strconv.ParseInt(fields[1], 10, 64)
	modeOctal, _ := strconv.ParseUint(fields[2], 8, 32)
	mode := fs.FileMode(modeOctal)
	// GNU stat produces lowercase ("directory"), BSD/macOS stat produces
	// title case ("Directory"). Normalize to lowercase for matching.
	typeStr := strings.ToLower(fields[3])
	if strings.Contains(typeStr, "directory") {
		mode |= fs.ModeDir
	} else if strings.Contains(typeStr, "symbolic link") {
		mode |= fs.ModeSymlink
	}
	return &remoteFileInfo{
		name:  name,
		size:  size,
		mode:  mode,
		mtime: time.Unix(mtimeUnix, 0),
	}, nil
}
