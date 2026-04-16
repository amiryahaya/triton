package pyimport

import (
	"testing"
)

// helper to build a FileImports for testing.
func makeFile(path, pkg string, imports []string, calls []FunctionCall) FileImports {
	fi := FileImports{Path: path, Package: pkg}
	for _, imp := range imports {
		fi.Imports = append(fi.Imports, ImportInfo{Module: imp, Line: 1})
	}
	fi.Calls = calls
	return fi
}

func TestBuildGraph_Empty(t *testing.T) {
	g := BuildGraph(nil)
	if g == nil {
		t.Fatal("BuildGraph(nil) returned nil")
	}
	if len(g.Files) != 0 {
		t.Errorf("want 0 nodes, got %d", len(g.Files))
	}
}

func TestBuildGraph_DirectImport(t *testing.T) {
	files := []FileImports{
		makeFile("/app/main.py", "main", []string{"hashlib"}, nil),
	}
	g := BuildGraph(files)
	if len(g.Files) != 1 {
		t.Fatalf("want 1 node, got %d", len(g.Files))
	}
	node, ok := g.Files["/app/main.py"]
	if !ok {
		t.Fatal("missing node for /app/main.py")
	}
	if node.Package != "main" {
		t.Errorf("Package: want main, got %q", node.Package)
	}
	if len(node.Imports) != 1 || node.Imports[0] != "hashlib" {
		t.Errorf("Imports: want [hashlib], got %v", node.Imports)
	}
}

func TestClassifyCrypto_Direct(t *testing.T) {
	// main.py imports hashlib and calls hashlib.sha256 — not imported by anyone.
	files := []FileImports{
		{
			Path:    "/app/main.py",
			Package: "main",
			Imports: []ImportInfo{{Module: "hashlib", Line: 1}},
			Calls: []FunctionCall{
				{Receiver: "hashlib", Name: "sha256", FullPath: "hashlib.sha256", Line: 5},
			},
		},
	}
	g := BuildGraph(files)
	matches := ClassifyCrypto(g, files)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 crypto match, got 0")
	}
	m := matches[0]
	if m.ImportPath != "hashlib.sha256" {
		t.Errorf("ImportPath: want hashlib.sha256, got %q", m.ImportPath)
	}
	if m.FilePath != "/app/main.py" {
		t.Errorf("FilePath: want /app/main.py, got %q", m.FilePath)
	}
	if m.Reachability != "direct" {
		t.Errorf("Reachability: want direct, got %q", m.Reachability)
	}
	if m.Confidence != 0.95 {
		t.Errorf("Confidence: want 0.95, got %f", m.Confidence)
	}
}

func TestClassifyCrypto_Transitive(t *testing.T) {
	// main.py imports utils; utils.py calls hashlib.sha256.
	files := []FileImports{
		{
			Path:    "/app/main.py",
			Package: "main",
			Imports: []ImportInfo{{Module: "utils", Line: 1}},
			Calls:   nil,
		},
		{
			Path:    "/app/utils.py",
			Package: "utils",
			Imports: []ImportInfo{{Module: "hashlib", Line: 1}},
			Calls: []FunctionCall{
				{Receiver: "hashlib", Name: "sha256", FullPath: "hashlib.sha256", Line: 3},
			},
		},
	}
	g := BuildGraph(files)
	matches := ClassifyCrypto(g, files)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 crypto match, got 0")
	}
	m := matches[0]
	if m.Reachability != "transitive" {
		t.Errorf("Reachability: want transitive, got %q", m.Reachability)
	}
	if m.Confidence != 0.75 {
		t.Errorf("Confidence: want 0.75, got %f", m.Confidence)
	}
	// DependencyPath should include main.py → utils.py
	if len(m.DependencyPath) < 2 {
		t.Errorf("DependencyPath: want at least 2 entries, got %v", m.DependencyPath)
	}
}

func TestClassifyCrypto_CircularImport(t *testing.T) {
	// a.py imports b; b.py imports a; b.py also calls hashlib.sha256.
	// Must not infinite-loop.
	files := []FileImports{
		{
			Path:    "/app/a.py",
			Package: "a",
			Imports: []ImportInfo{{Module: "b", Line: 1}},
		},
		{
			Path:    "/app/b.py",
			Package: "b",
			Imports: []ImportInfo{{Module: "a", Line: 1}},
			Calls: []FunctionCall{
				{Receiver: "hashlib", Name: "sha256", FullPath: "hashlib.sha256", Line: 3},
			},
		},
	}
	g := BuildGraph(files)
	// Should complete without hanging.
	matches := ClassifyCrypto(g, files)
	// Both a and b are imported by each other; result is non-nil.
	_ = matches
}

func TestClassifyCrypto_DiamondDependency(t *testing.T) {
	// main → a, main → b; a → crypto; b → crypto.
	// crypto.py calls hashlib.sha256. Should deduplicate to one match.
	files := []FileImports{
		{
			Path:    "/app/main.py",
			Package: "main",
			Imports: []ImportInfo{
				{Module: "a", Line: 1},
				{Module: "b", Line: 2},
			},
		},
		{
			Path:    "/app/a.py",
			Package: "a",
			Imports: []ImportInfo{{Module: "crypto", Line: 1}},
		},
		{
			Path:    "/app/b.py",
			Package: "b",
			Imports: []ImportInfo{{Module: "crypto", Line: 1}},
		},
		{
			Path:    "/app/crypto.py",
			Package: "crypto",
			Imports: []ImportInfo{{Module: "hashlib", Line: 1}},
			Calls: []FunctionCall{
				{Receiver: "hashlib", Name: "sha256", FullPath: "hashlib.sha256", Line: 3},
			},
		},
	}
	g := BuildGraph(files)
	matches := ClassifyCrypto(g, files)
	// Count how many times hashlib.sha256 from crypto.py appears.
	count := 0
	for _, m := range matches {
		if m.ImportPath == "hashlib.sha256" && m.FilePath == "/app/crypto.py" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated match for hashlib.sha256 in crypto.py, got %d", count)
	}
}

func TestClassifyCrypto_NoCrypto(t *testing.T) {
	files := []FileImports{
		makeFile("/app/main.py", "main", []string{"os", "sys"}, nil),
	}
	g := BuildGraph(files)
	matches := ClassifyCrypto(g, files)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-crypto imports, got %d", len(matches))
	}
}

func TestClassifyCrypto_CryptographyLibrary(t *testing.T) {
	// from cryptography.fernet import Fernet
	// f = Fernet(key) → resolved to cryptography.fernet.Fernet
	files := []FileImports{
		{
			Path:    "/app/main.py",
			Package: "main",
			Imports: []ImportInfo{
				{Module: "cryptography.fernet", Names: []string{"Fernet"}, Line: 1},
			},
			Calls: []FunctionCall{
				{Receiver: "", Name: "Fernet", FullPath: "cryptography.fernet.Fernet", Line: 5},
			},
		},
	}
	g := BuildGraph(files)
	matches := ClassifyCrypto(g, files)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 crypto match for cryptography.fernet.Fernet")
	}
	found := false
	for _, m := range matches {
		if m.ImportPath == "cryptography.fernet.Fernet" {
			found = true
			if m.Reachability != "direct" {
				t.Errorf("Reachability: want direct, got %q", m.Reachability)
			}
		}
	}
	if !found {
		t.Errorf("no match found for cryptography.fernet.Fernet, got: %v", matches)
	}
}
