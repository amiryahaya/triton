package pyimport

import (
	"strings"
	"testing"
)

func TestParseSource_SimpleImport(t *testing.T) {
	src := `import hashlib`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	if imp.Module != "hashlib" {
		t.Errorf("Module: want hashlib, got %q", imp.Module)
	}
	if imp.Alias != "" {
		t.Errorf("Alias: want empty, got %q", imp.Alias)
	}
	if len(imp.Names) != 0 {
		t.Errorf("Names: want empty, got %v", imp.Names)
	}
}

func TestParseSource_ImportAs(t *testing.T) {
	src := `import hashlib as hl`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	if imp.Module != "hashlib" {
		t.Errorf("Module: want hashlib, got %q", imp.Module)
	}
	if imp.Alias != "hl" {
		t.Errorf("Alias: want hl, got %q", imp.Alias)
	}
}

func TestParseSource_FromImport(t *testing.T) {
	src := `from cryptography.hazmat.primitives import hashes`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	if imp.Module != "cryptography.hazmat.primitives" {
		t.Errorf("Module: want cryptography.hazmat.primitives, got %q", imp.Module)
	}
	if len(imp.Names) != 1 || imp.Names[0] != "hashes" {
		t.Errorf("Names: want [hashes], got %v", imp.Names)
	}
}

func TestParseSource_FromImportMultiple(t *testing.T) {
	src := `from cryptography.hazmat.primitives import hashes, ciphers, padding`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	want := []string{"hashes", "ciphers", "padding"}
	if len(imp.Names) != len(want) {
		t.Fatalf("Names: want %v, got %v", want, imp.Names)
	}
	for i, w := range want {
		if imp.Names[i] != w {
			t.Errorf("Names[%d]: want %q, got %q", i, w, imp.Names[i])
		}
	}
}

func TestParseSource_MultiLineImport(t *testing.T) {
	src := `from cryptography.hazmat.primitives import (
    hashes,
    ciphers,
    padding
)`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	want := []string{"hashes", "ciphers", "padding"}
	if len(imp.Names) != len(want) {
		t.Fatalf("Names: want %v, got %v", want, imp.Names)
	}
	for i, w := range want {
		if imp.Names[i] != w {
			t.Errorf("Names[%d]: want %q, got %q", i, w, imp.Names[i])
		}
	}
}

func TestParseSource_RelativeImport(t *testing.T) {
	src := `from . import utils`
	fi, err := ParseSource("/app/myapp/main.py", "myapp", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	if imp.Module != "myapp" {
		t.Errorf("Module: want myapp, got %q", imp.Module)
	}
	if len(imp.Names) != 1 || imp.Names[0] != "utils" {
		t.Errorf("Names: want [utils], got %v", imp.Names)
	}
}

func TestParseSource_ParentRelativeImport(t *testing.T) {
	src := `from ..crypto import aes`
	fi, err := ParseSource("/app/myapp/sub/main.py", "myapp.sub", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	imp := fi.Imports[0]
	// ..crypto from myapp.sub → myapp.crypto
	if imp.Module != "myapp.crypto" {
		t.Errorf("Module: want myapp.crypto, got %q", imp.Module)
	}
	if len(imp.Names) != 1 || imp.Names[0] != "aes" {
		t.Errorf("Names: want [aes], got %v", imp.Names)
	}
}

func TestParseSource_CommentIgnored(t *testing.T) {
	src := `# import hashlib
# from cryptography import fernet
x = 1`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 0 {
		t.Errorf("want 0 imports, got %d: %v", len(fi.Imports), fi.Imports)
	}
}

func TestParseSource_StringIgnored(t *testing.T) {
	src := `"""
import hashlib
from cryptography import fernet
"""
x = 1`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 0 {
		t.Errorf("want 0 imports inside triple-quote, got %d", len(fi.Imports))
	}
}

func TestParseSource_FunctionCall(t *testing.T) {
	src := `import hashlib
h = hashlib.sha256(data)`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(fi.Calls))
	}
	c := fi.Calls[0]
	if c.Receiver != "hashlib" {
		t.Errorf("Receiver: want hashlib, got %q", c.Receiver)
	}
	if c.Name != "sha256" {
		t.Errorf("Name: want sha256, got %q", c.Name)
	}
	if c.FullPath != "hashlib.sha256" {
		t.Errorf("FullPath: want hashlib.sha256, got %q", c.FullPath)
	}
}

func TestParseSource_FromImportCall(t *testing.T) {
	src := `from cryptography.fernet import Fernet
f = Fernet(key)`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	// Should detect Fernet() call resolved to cryptography.fernet.Fernet
	found := false
	for _, c := range fi.Calls {
		if c.FullPath == "cryptography.fernet.Fernet" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected call with FullPath=cryptography.fernet.Fernet, got calls: %v", fi.Calls)
	}
}

func TestParseSource_AliasedCall(t *testing.T) {
	src := `import hashlib as hl
h = hl.md5(data)`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range fi.Calls {
		if c.FullPath == "hashlib.md5" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected call with FullPath=hashlib.md5, got calls: %v", fi.Calls)
	}
}

func TestParseSource_MultipleImports(t *testing.T) {
	src := `import os, hashlib, sys`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 3 {
		t.Fatalf("want 3 imports, got %d: %v", len(fi.Imports), fi.Imports)
	}
	mods := map[string]bool{}
	for _, imp := range fi.Imports {
		mods[imp.Module] = true
	}
	for _, want := range []string{"os", "hashlib", "sys"} {
		if !mods[want] {
			t.Errorf("missing import %q", want)
		}
	}
}

func TestParseSource_EmptyFile(t *testing.T) {
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 0 {
		t.Errorf("want 0 imports, got %d", len(fi.Imports))
	}
	if len(fi.Calls) != 0 {
		t.Errorf("want 0 calls, got %d", len(fi.Calls))
	}
}

func TestParseSource_MultipleImportOnOneLine(t *testing.T) {
	src := `import os, hashlib`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 2 {
		t.Fatalf("want 2 imports, got %d: %v", len(fi.Imports), fi.Imports)
	}
}

func TestParseSource_FromImportAlias(t *testing.T) {
	src := `from cryptography.hazmat.primitives.hashes import SHA256 as H
h = H()`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	// Alias in from import
	imp := fi.Imports[0]
	if imp.Alias != "H" {
		t.Errorf("Alias: want H, got %q", imp.Alias)
	}
	// Call H() should resolve to cryptography.hazmat.primitives.hashes.SHA256
	found := false
	for _, c := range fi.Calls {
		if c.FullPath == "cryptography.hazmat.primitives.hashes.SHA256" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected call FullPath=cryptography.hazmat.primitives.hashes.SHA256, got: %v", fi.Calls)
	}
}

func TestParseSource_LineNumbers(t *testing.T) {
	src := `# comment
import hashlib
x = 1
h = hashlib.sha256(data)`
	fi, err := ParseSource("/app/main.py", "main", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fi.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(fi.Imports))
	}
	if fi.Imports[0].Line != 2 {
		t.Errorf("Import Line: want 2, got %d", fi.Imports[0].Line)
	}
	if len(fi.Calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(fi.Calls))
	}
	if fi.Calls[0].Line != 4 {
		t.Errorf("Call Line: want 4, got %d", fi.Calls[0].Line)
	}
}

func TestParseSource_PathAndPackage(t *testing.T) {
	src := ``
	fi, err := ParseSource("/app/myapp/utils.py", "myapp.utils", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Path != "/app/myapp/utils.py" {
		t.Errorf("Path: want /app/myapp/utils.py, got %q", fi.Path)
	}
	if fi.Package != "myapp.utils" {
		t.Errorf("Package: want myapp.utils, got %q", fi.Package)
	}
}
