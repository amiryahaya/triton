package pyimport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsStdlib_Hashlib(t *testing.T) {
	if !IsStdlib("hashlib") {
		t.Error("hashlib should be stdlib")
	}
}

func TestIsStdlib_Hmac(t *testing.T) {
	if !IsStdlib("hmac") {
		t.Error("hmac should be stdlib")
	}
}

func TestIsStdlib_Ssl(t *testing.T) {
	if !IsStdlib("ssl") {
		t.Error("ssl should be stdlib")
	}
}

func TestIsStdlib_Cryptography_False(t *testing.T) {
	if IsStdlib("cryptography") {
		t.Error("cryptography should NOT be stdlib")
	}
}

func TestIsStdlib_Submodule_TopLevel(t *testing.T) {
	// "hashlib.sha256" → top-level is hashlib → stdlib
	if !IsStdlib("hashlib.sha256") {
		t.Error("hashlib.sha256 top-level hashlib should be stdlib")
	}
}

func TestResolveModule_SimpleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "utils.py")
	if err := os.WriteFile(f, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveModule("utils", dir)
	if got != f {
		t.Errorf("want %q, got %q", f, got)
	}
}

func TestResolveModule_Package(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "myapp")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	initFile := filepath.Join(pkgDir, "__init__.py")
	if err := os.WriteFile(initFile, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveModule("myapp", dir)
	if got != initFile {
		t.Errorf("want %q, got %q", initFile, got)
	}
}

func TestResolveModule_DottedPath(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "myapp", "crypto")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(subDir, "aes.py")
	if err := os.WriteFile(f, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveModule("myapp.crypto.aes", dir)
	if got != f {
		t.Errorf("want %q, got %q", f, got)
	}
}

func TestResolveModule_NotFound(t *testing.T) {
	dir := t.TempDir()
	got := ResolveModule("nonexistent.module", dir)
	if got != "" {
		t.Errorf("want empty string for not-found, got %q", got)
	}
}

func TestDetectProjectRoot_PyprojectToml(t *testing.T) {
	dir := t.TempDir()
	// Create pyproject.toml at the root.
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// Create a nested directory.
	nested := filepath.Join(dir, "myapp", "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got := DetectProjectRoot(nested)
	if got != dir {
		t.Errorf("want %q, got %q", dir, got)
	}
}

func TestDetectProjectRoot_SetupPy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dir, "myapp")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got := DetectProjectRoot(nested)
	if got != dir {
		t.Errorf("want %q, got %q", dir, got)
	}
}

func TestDetectProjectRoot_NoMarker(t *testing.T) {
	dir := t.TempDir()
	got := DetectProjectRoot(dir)
	if got != dir {
		t.Errorf("with no marker, should fall back to startDir %q, got %q", dir, got)
	}
}

func TestFileToPackage_ModuleFile(t *testing.T) {
	root := "/project"
	got := FileToPackage("/project/myapp/utils.py", root)
	if got != "myapp.utils" {
		t.Errorf("want myapp.utils, got %q", got)
	}
}

func TestFileToPackage_InitFile(t *testing.T) {
	root := "/project"
	got := FileToPackage("/project/myapp/__init__.py", root)
	if got != "myapp" {
		t.Errorf("want myapp, got %q", got)
	}
}

func TestFileToPackage_TopLevel(t *testing.T) {
	root := "/project"
	got := FileToPackage("/project/main.py", root)
	if got != "main" {
		t.Errorf("want main, got %q", got)
	}
}
