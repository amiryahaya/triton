package pyimport

import (
	"os"
	"path/filepath"
	"strings"
)

// stdlibModules is the set of Python standard-library top-level module names
// that are relevant for crypto scanning and import resolution.
var stdlibModules = map[string]bool{
	"hashlib":     true,
	"hmac":        true,
	"ssl":         true,
	"secrets":     true,
	"os":          true,
	"sys":         true,
	"io":          true,
	"re":          true,
	"json":        true,
	"math":        true,
	"time":        true,
	"datetime":    true,
	"collections": true,
	"functools":   true,
	"itertools":   true,
	"pathlib":     true,
	"typing":      true,
	"abc":         true,
	"struct":      true,
	"base64":      true,
	"binascii":    true,
	"socket":      true,
	"http":        true,
	"urllib":      true,
}

// IsStdlib reports whether a module (or its top-level package) is part of the
// Python standard library. Dotted paths are reduced to their top-level name
// before the lookup (e.g. "hashlib.sha256" → "hashlib").
func IsStdlib(module string) bool {
	top := module
	if idx := strings.IndexByte(module, '.'); idx >= 0 {
		top = module[:idx]
	}
	return stdlibModules[top]
}

// ResolveModule maps a dotted Python module name to a filesystem path under
// root. It tries two candidates:
//  1. root/a/b/c.py  (module file)
//  2. root/a/b/c/__init__.py  (package)
//
// Returns the first existing path, or "" if neither exists.
// Any module name that would resolve to a path outside root (e.g. via ".."
// segments) is rejected and returns "".
func ResolveModule(module, root string) string {
	// Convert dotted name to path segments.
	parts := strings.Split(module, ".")
	rel := filepath.Join(parts...)

	// rootAnchor is the canonical root with a trailing separator so that
	// strings.HasPrefix gives an exact directory-boundary match.
	rootAnchor := filepath.Clean(root) + string(filepath.Separator)

	// Try module file first.
	candidate := filepath.Join(root, rel+".py")
	// Guard against path traversal via ".." segments in module names.
	if !strings.HasPrefix(filepath.Clean(candidate), rootAnchor) {
		return ""
	}
	if fileExists(candidate) {
		return candidate
	}

	// Try package __init__.py.
	candidate = filepath.Join(root, rel, "__init__.py")
	// Guard against path traversal via ".." segments in module names.
	if !strings.HasPrefix(filepath.Clean(candidate), rootAnchor) {
		return ""
	}
	if fileExists(candidate) {
		return candidate
	}

	return ""
}

// DetectProjectRoot walks up the directory tree from startDir looking for
// pyproject.toml, setup.py, or setup.cfg. Returns the first directory that
// contains one of these markers, or startDir if none is found.
func DetectProjectRoot(startDir string) string {
	markers := []string{"pyproject.toml", "setup.py", "setup.cfg"}

	dir := startDir
	for {
		for _, marker := range markers {
			if fileExists(filepath.Join(dir, marker)) {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root.
			break
		}
		dir = parent
	}

	return startDir
}

// FileToPackage converts an absolute file path to a dotted Python package name
// relative to projectRoot.
//
// Examples:
//
//	/project/myapp/utils.py  → "myapp.utils"
//	/project/myapp/__init__.py → "myapp"
//	/project/main.py → "main"
func FileToPackage(filePath, projectRoot string) string {
	// Make both paths clean and absolute.
	rel, err := filepath.Rel(projectRoot, filePath)
	if err != nil {
		// Fall back to base name without extension.
		return strings.TrimSuffix(filepath.Base(filePath), ".py")
	}

	// Remove .py extension.
	rel = strings.TrimSuffix(rel, ".py")

	// Convert path separators to dots.
	dotted := strings.ReplaceAll(rel, string(filepath.Separator), ".")

	// __init__ at the end means this is the package itself.
	dotted = strings.TrimSuffix(dotted, ".__init__")

	return dotted
}

// fileExists is a small helper to check if a regular file exists.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
