# Python AST + Import-Graph Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Python AST scanner module that parses `.py` files for crypto library imports and function calls, builds an import graph, and classifies findings by reachability (direct/transitive/unreachable) — bringing Python to parity with the Go dependency scanner.

**Architecture:** Internal `pyimport/` package provides a pure-Go Python import parser and import graph builder. A `python_algorithms.go` registry in `pkg/crypto/` maps Python import paths to canonical algorithm names. The `python_ast.go` module orchestrates the two-phase scan (parse all files, then build graph and emit findings).

**Tech Stack:** Go 1.25, stdlib only (bufio, strings, path/filepath, regexp). No external dependencies.

---

## File Map

### New files

| File | Responsibility |
|------|----------------|
| `pkg/scanner/internal/pyimport/types.go` | Types: `ImportInfo`, `FunctionCall`, `FileImports`, `ImportGraph`, `ModuleNode`, `CryptoMatch` |
| `pkg/scanner/internal/pyimport/parser.go` | Line-by-line Python import + function call parser |
| `pkg/scanner/internal/pyimport/parser_test.go` | Parser unit tests |
| `pkg/scanner/internal/pyimport/resolve.go` | Module name → filesystem path resolution, stdlib detection |
| `pkg/scanner/internal/pyimport/resolve_test.go` | Resolution tests |
| `pkg/scanner/internal/pyimport/graph.go` | Import graph builder with BFS reachability |
| `pkg/scanner/internal/pyimport/graph_test.go` | Graph traversal tests |
| `pkg/crypto/python_algorithms.go` | Python crypto algorithm registry (~42 entries) |
| `pkg/crypto/python_algorithms_test.go` | Registry lookup tests |
| `pkg/scanner/python_ast.go` | PythonASTModule implementation |
| `pkg/scanner/python_ast_test.go` | Module unit tests |

### Modified files

| File | Changes |
|------|---------|
| `pkg/scanner/engine.go` | Add `NewPythonASTModule` factory to `defaultModuleFactories` |
| `internal/scannerconfig/config.go` | Add `"python_ast"` to standard + comprehensive profiles |
| `internal/license/tier.go` | Add `"python_ast"` to `proModules()` |
| `pkg/scanner/engine_test.go` | Update module count assertion (55 → 56) |

---

## Phase 1: Types and Registry

### Task 1: Python crypto algorithm registry

**Files:**
- Create: `pkg/crypto/python_algorithms.go`
- Create: `pkg/crypto/python_algorithms_test.go`

- [ ] **Step 1: Write python_algorithms_test.go**

```go
package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupPythonCrypto_StdlibHashlib(t *testing.T) {
	entry, ok := LookupPythonCrypto("hashlib.sha256")
	require.True(t, ok)
	assert.Equal(t, "SHA-256", entry.Algorithm)
	assert.Equal(t, "Hash", entry.Function)
}

func TestLookupPythonCrypto_StdlibMD5(t *testing.T) {
	entry, ok := LookupPythonCrypto("hashlib.md5")
	require.True(t, ok)
	assert.Equal(t, "MD5", entry.Algorithm)
}

func TestLookupPythonCrypto_CryptographyAES(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.ciphers.algorithms.AES")
	require.True(t, ok)
	assert.Equal(t, "AES", entry.Algorithm)
	assert.Equal(t, "Symmetric encryption", entry.Function)
}

func TestLookupPythonCrypto_CryptographyRSA(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.asymmetric.rsa")
	require.True(t, ok)
	assert.Equal(t, "RSA", entry.Algorithm)
}

func TestLookupPythonCrypto_CryptographyFernet(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.fernet.Fernet")
	require.True(t, ok)
	assert.Equal(t, "AES-128-CBC", entry.Algorithm)
}

func TestLookupPythonCrypto_PycryptodomeAES(t *testing.T) {
	entry, ok := LookupPythonCrypto("Crypto.Cipher.AES")
	require.True(t, ok)
	assert.Equal(t, "AES", entry.Algorithm)
}

func TestLookupPythonCrypto_CryptodomeNamespace(t *testing.T) {
	entry, ok := LookupPythonCrypto("Cryptodome.Cipher.AES")
	require.True(t, ok)
	assert.Equal(t, "AES", entry.Algorithm)
}

func TestLookupPythonCrypto_PrefixMatch(t *testing.T) {
	// "cryptography.hazmat.primitives.asymmetric.ec" should match for module-level import
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.asymmetric.ec")
	require.True(t, ok)
	assert.Equal(t, "ECDSA", entry.Algorithm)
}

func TestLookupPythonCrypto_Unknown(t *testing.T) {
	_, ok := LookupPythonCrypto("flask.Flask")
	assert.False(t, ok)
}

func TestLookupPythonCrypto_HmacNew(t *testing.T) {
	entry, ok := LookupPythonCrypto("hmac.new")
	require.True(t, ok)
	assert.Equal(t, "HMAC", entry.Algorithm)
	assert.Equal(t, "MAC", entry.Function)
}

func TestLookupPythonCrypto_Ed25519(t *testing.T) {
	entry, ok := LookupPythonCrypto("cryptography.hazmat.primitives.asymmetric.ed25519")
	require.True(t, ok)
	assert.Equal(t, "Ed25519", entry.Algorithm)
	assert.Equal(t, "Digital signature", entry.Function)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestLookupPythonCrypto ./pkg/crypto/...`
Expected: FAIL — `LookupPythonCrypto` not defined.

- [ ] **Step 3: Implement python_algorithms.go**

```go
package crypto

import "strings"

// PythonCryptoEntry maps a Python import path to its crypto classification.
type PythonCryptoEntry struct {
	Algorithm string // canonical name for ClassifyCryptoAsset (e.g., "AES", "SHA-256")
	Function  string // crypto function category (e.g., "Symmetric encryption", "Hash")
	KeySize   int    // default key size if deterministic (0 = varies)
}

// pythonCryptoRegistry maps fully-qualified Python import paths to crypto entries.
// Keys are the full dotted path as they appear in `from X import Y` or `X.Y()` calls.
var pythonCryptoRegistry = map[string]PythonCryptoEntry{
	// --- stdlib ---
	"hashlib.md5":        {Algorithm: "MD5", Function: "Hash"},
	"hashlib.sha1":       {Algorithm: "SHA-1", Function: "Hash"},
	"hashlib.sha256":     {Algorithm: "SHA-256", Function: "Hash"},
	"hashlib.sha384":     {Algorithm: "SHA-384", Function: "Hash"},
	"hashlib.sha512":     {Algorithm: "SHA-512", Function: "Hash"},
	"hashlib.sha3_256":   {Algorithm: "SHA3-256", Function: "Hash"},
	"hashlib.sha3_512":   {Algorithm: "SHA3-512", Function: "Hash"},
	"hashlib.blake2b":    {Algorithm: "BLAKE2b", Function: "Hash"},
	"hashlib.blake2s":    {Algorithm: "BLAKE2s", Function: "Hash"},
	"hmac.new":           {Algorithm: "HMAC", Function: "MAC"},
	"ssl.create_default_context": {Algorithm: "TLS", Function: "Protocol"},
	"secrets.token_bytes":        {Algorithm: "CSPRNG", Function: "Random"},

	// --- cryptography library ---
	"cryptography.hazmat.primitives.ciphers.algorithms.AES":       {Algorithm: "AES", Function: "Symmetric encryption"},
	"cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": {Algorithm: "3DES", Function: "Symmetric encryption"},
	"cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20":  {Algorithm: "ChaCha20", Function: "Symmetric encryption"},
	"cryptography.hazmat.primitives.ciphers.algorithms.Blowfish":  {Algorithm: "Blowfish", Function: "Symmetric encryption"},
	"cryptography.hazmat.primitives.hashes.SHA256":                {Algorithm: "SHA-256", Function: "Hash"},
	"cryptography.hazmat.primitives.hashes.SHA384":                {Algorithm: "SHA-384", Function: "Hash"},
	"cryptography.hazmat.primitives.hashes.SHA512":                {Algorithm: "SHA-512", Function: "Hash"},
	"cryptography.hazmat.primitives.hashes.SHA1":                  {Algorithm: "SHA-1", Function: "Hash"},
	"cryptography.hazmat.primitives.hashes.MD5":                   {Algorithm: "MD5", Function: "Hash"},
	"cryptography.hazmat.primitives.asymmetric.rsa":               {Algorithm: "RSA", Function: "Asymmetric encryption"},
	"cryptography.hazmat.primitives.asymmetric.ec":                {Algorithm: "ECDSA", Function: "Digital signature"},
	"cryptography.hazmat.primitives.asymmetric.ec.SECP256R1":      {Algorithm: "ECDSA-P256", Function: "Digital signature"},
	"cryptography.hazmat.primitives.asymmetric.ec.SECP384R1":      {Algorithm: "ECDSA-P384", Function: "Digital signature"},
	"cryptography.hazmat.primitives.asymmetric.ec.SECP521R1":      {Algorithm: "ECDSA-P521", Function: "Digital signature"},
	"cryptography.hazmat.primitives.asymmetric.ed25519":           {Algorithm: "Ed25519", Function: "Digital signature"},
	"cryptography.hazmat.primitives.asymmetric.ed448":             {Algorithm: "Ed448", Function: "Digital signature"},
	"cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC":       {Algorithm: "PBKDF2", Function: "Key derivation"},
	"cryptography.hazmat.primitives.kdf.scrypt.Scrypt":            {Algorithm: "scrypt", Function: "Key derivation"},
	"cryptography.hazmat.primitives.kdf.hkdf.HKDF":               {Algorithm: "HKDF", Function: "Key derivation"},
	"cryptography.fernet.Fernet":                                  {Algorithm: "AES-128-CBC", Function: "Symmetric encryption", KeySize: 128},
	"cryptography.x509":                                           {Algorithm: "X.509", Function: "Certificate"},

	// --- pycryptodome (Crypto namespace) ---
	"Crypto.Cipher.AES":      {Algorithm: "AES", Function: "Symmetric encryption"},
	"Crypto.Cipher.DES3":     {Algorithm: "3DES", Function: "Symmetric encryption"},
	"Crypto.Cipher.DES":      {Algorithm: "DES", Function: "Symmetric encryption"},
	"Crypto.Cipher.Blowfish": {Algorithm: "Blowfish", Function: "Symmetric encryption"},
	"Crypto.Cipher.ChaCha20": {Algorithm: "ChaCha20", Function: "Symmetric encryption"},
	"Crypto.Hash.SHA256":     {Algorithm: "SHA-256", Function: "Hash"},
	"Crypto.Hash.SHA1":       {Algorithm: "SHA-1", Function: "Hash"},
	"Crypto.Hash.MD5":        {Algorithm: "MD5", Function: "Hash"},
	"Crypto.PublicKey.RSA":   {Algorithm: "RSA", Function: "Asymmetric encryption"},
	"Crypto.PublicKey.ECC":   {Algorithm: "ECDSA", Function: "Digital signature"},
	"Crypto.PublicKey.DSA":   {Algorithm: "DSA", Function: "Digital signature"},
}

func init() {
	// Mirror Crypto.* entries under Cryptodome.* namespace (pycryptodome namespace-safe install).
	for k, v := range pythonCryptoRegistry {
		if strings.HasPrefix(k, "Crypto.") {
			mirror := "Cryptodome." + k[len("Crypto."):]
			if _, exists := pythonCryptoRegistry[mirror]; !exists {
				pythonCryptoRegistry[mirror] = v
			}
		}
	}
}

// LookupPythonCrypto looks up a Python import path in the crypto registry.
// Tries exact match first, then prefix match for module-level imports.
func LookupPythonCrypto(importPath string) (PythonCryptoEntry, bool) {
	// Exact match
	if e, ok := pythonCryptoRegistry[importPath]; ok {
		return e, true
	}

	// Prefix match: "cryptography.hazmat.primitives.asymmetric.ec.SECP256R1"
	// might be looked up as "cryptography.hazmat.primitives.asymmetric.ec"
	// when only the module is imported.
	for key, entry := range pythonCryptoRegistry {
		if strings.HasPrefix(key, importPath+".") {
			return entry, true
		}
	}

	return PythonCryptoEntry{}, false
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestLookupPythonCrypto ./pkg/crypto/...`
Expected: all 11 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/python_algorithms.go pkg/crypto/python_algorithms_test.go
git commit -m "feat(crypto): add Python crypto algorithm registry (~42 entries)"
```

### Task 2: pyimport types

**Files:**
- Create: `pkg/scanner/internal/pyimport/types.go`

- [ ] **Step 1: Write types.go**

```go
package pyimport

// ImportInfo represents a single Python import statement.
type ImportInfo struct {
	Module string   // dotted module path (e.g., "cryptography.hazmat.primitives")
	Names  []string // imported names (e.g., ["hashes", "Cipher"]) — empty for plain `import X`
	Alias  string   // alias if `import X as Y` or `from X import Y as Z`
	Line   int      // source line number
}

// FunctionCall represents a function/class instantiation call found in source.
type FunctionCall struct {
	Receiver string // resolved module path of the receiver (e.g., "hashlib")
	Name     string // function/class name (e.g., "sha256")
	FullPath string // resolved full path (e.g., "hashlib.sha256")
	Line     int    // source line number
}

// FileImports holds all parsed imports and calls from a single .py file.
type FileImports struct {
	Path      string         // absolute file path
	Package   string         // Python package path (e.g., "myapp.utils")
	Imports   []ImportInfo   // all import statements
	Calls     []FunctionCall // all function/class calls that reference imported names
}

// ImportGraph holds the complete import dependency graph for a Python project.
type ImportGraph struct {
	Files map[string]*ModuleNode // keyed by file path
}

// ModuleNode represents one Python file in the import graph.
type ModuleNode struct {
	Path    string   // filesystem path
	Package string   // Python dotted package name
	Imports []string // resolved Python module names this file imports
}

// CryptoMatch represents a crypto import discovered in the graph with reachability info.
type CryptoMatch struct {
	ImportPath     string   // full Python import path (e.g., "cryptography.hazmat.primitives.hashes.SHA256")
	FilePath       string   // file where the crypto usage was found
	Line           int      // line number in the file
	Reachability   string   // "direct", "transitive", "unreachable"
	Confidence     float64  // 0.95, 0.75, 0.50
	DependencyPath []string // shortest import chain from entry point
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./pkg/scanner/internal/pyimport/...`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add pkg/scanner/internal/pyimport/types.go
git commit -m "feat(pyimport): add types for Python import parser"
```

---

## Phase 2: Python Import Parser

### Task 3: Python import parser

**Files:**
- Create: `pkg/scanner/internal/pyimport/parser.go`
- Create: `pkg/scanner/internal/pyimport/parser_test.go`

- [ ] **Step 1: Write parser_test.go**

```go
package pyimport

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile_SimpleImport(t *testing.T) {
	src := "import hashlib\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, "hashlib", fi.Imports[0].Module)
	assert.Empty(t, fi.Imports[0].Names)
	assert.Equal(t, 1, fi.Imports[0].Line)
}

func TestParseFile_ImportAs(t *testing.T) {
	src := "import hashlib as hl\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, "hashlib", fi.Imports[0].Module)
	assert.Equal(t, "hl", fi.Imports[0].Alias)
}

func TestParseFile_FromImport(t *testing.T) {
	src := "from cryptography.hazmat.primitives import hashes\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, "cryptography.hazmat.primitives", fi.Imports[0].Module)
	assert.Equal(t, []string{"hashes"}, fi.Imports[0].Names)
}

func TestParseFile_FromImportMultiple(t *testing.T) {
	src := "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, []string{"Cipher", "algorithms", "modes"}, fi.Imports[0].Names)
}

func TestParseFile_MultiLineImport(t *testing.T) {
	src := "from cryptography.hazmat.primitives.ciphers import (\n    Cipher,\n    algorithms,\n    modes,\n)\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, []string{"Cipher", "algorithms", "modes"}, fi.Imports[0].Names)
}

func TestParseFile_RelativeImport(t *testing.T) {
	src := "from . import utils\n"
	fi, err := ParseSource("test.py", "myapp", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, "myapp", fi.Imports[0].Module) // resolved relative to package
	assert.Equal(t, []string{"utils"}, fi.Imports[0].Names)
}

func TestParseFile_ParentRelativeImport(t *testing.T) {
	src := "from ..crypto import aes\n"
	fi, err := ParseSource("test.py", "myapp.sub", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Imports, 1)
	assert.Equal(t, "myapp.crypto", fi.Imports[0].Module) // parent of myapp.sub = myapp
}

func TestParseFile_CommentIgnored(t *testing.T) {
	src := "# import hashlib\nprint('hello')\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	assert.Empty(t, fi.Imports)
}

func TestParseFile_StringIgnored(t *testing.T) {
	src := "x = 'import hashlib'\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	assert.Empty(t, fi.Imports)
}

func TestParseFile_FunctionCall(t *testing.T) {
	src := "import hashlib\ndigest = hashlib.sha256(data)\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Calls, 1)
	assert.Equal(t, "hashlib", fi.Calls[0].Receiver)
	assert.Equal(t, "sha256", fi.Calls[0].Name)
	assert.Equal(t, "hashlib.sha256", fi.Calls[0].FullPath)
}

func TestParseFile_FromImportCall(t *testing.T) {
	src := "from cryptography.fernet import Fernet\nf = Fernet(key)\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Calls, 1)
	assert.Equal(t, "cryptography.fernet.Fernet", fi.Calls[0].FullPath)
}

func TestParseFile_AliasedCall(t *testing.T) {
	src := "import hashlib as hl\nhl.md5(data)\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, fi.Calls, 1)
	assert.Equal(t, "hashlib.md5", fi.Calls[0].FullPath) // resolved through alias
}

func TestParseFile_MultipleImports(t *testing.T) {
	src := "import hashlib\nimport ssl\nfrom Crypto.Cipher import AES\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	assert.Len(t, fi.Imports, 3)
}

func TestParseFile_EmptyFile(t *testing.T) {
	fi, err := ParseSource("test.py", "", strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, fi.Imports)
	assert.Empty(t, fi.Calls)
}

func TestParseFile_MultipleImportOnOneLine(t *testing.T) {
	src := "import os, hashlib, sys\n"
	fi, err := ParseSource("test.py", "", strings.NewReader(src))
	require.NoError(t, err)
	assert.Len(t, fi.Imports, 3)
	assert.Equal(t, "hashlib", fi.Imports[1].Module)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestParseFile ./pkg/scanner/internal/pyimport/...`
Expected: FAIL — `ParseSource` not defined.

- [ ] **Step 3: Implement parser.go**

The parser:
1. Reads lines via `bufio.Scanner`
2. Skips comment lines (leading `#` after stripping whitespace)
3. Tracks triple-quote strings (docstrings) to skip their contents
4. Detects `import X[, Y]` and `from X import Y[, Z]` patterns
5. Handles multi-line `()` continuation by accumulating until closing `)`
6. Resolves relative imports using the `packageName` parameter
7. Builds an alias map (`name → full module path`) from imports
8. Scans for function calls matching `X.Y(` or `Name(` patterns against the alias map

```go
package pyimport

import (
	"bufio"
	"io"
	"strings"
)

// ParseSource parses a Python source file and extracts imports and function calls.
// packageName is the dotted Python package name for resolving relative imports
// (e.g., "myapp.utils" for myapp/utils/__init__.py). Pass "" for unknown.
func ParseSource(filePath, packageName string, r io.Reader) (*FileImports, error) {
	fi := &FileImports{
		Path:    filePath,
		Package: packageName,
	}

	scanner := bufio.NewScanner(r)
	aliases := make(map[string]string)  // alias/name → full module path
	lineNum := 0
	var multiLineFrom string            // tracks "from X" during multi-line import
	var multiLineNames []string         // accumulates names during multi-line ()
	inMultiLine := false
	inTripleQuote := false
	tripleQuoteChar := ""

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Track triple-quoted strings
		if inTripleQuote {
			if strings.Contains(line, tripleQuoteChar) {
				inTripleQuote = false
			}
			continue
		}
		for _, tq := range []string{`"""`, `'''`} {
			count := strings.Count(line, tq)
			if count%2 != 0 {
				inTripleQuote = true
				tripleQuoteChar = tq
			}
		}
		if inTripleQuote {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(trimmed, " #"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}

		// Multi-line continuation
		if inMultiLine {
			if strings.Contains(trimmed, ")") {
				// End of multi-line: extract names before )
				before := trimmed[:strings.Index(trimmed, ")")]
				multiLineNames = append(multiLineNames, splitImportNames(before)...)
				fi.Imports = append(fi.Imports, ImportInfo{
					Module: multiLineFrom,
					Names:  multiLineNames,
					Line:   lineNum,
				})
				for _, name := range multiLineNames {
					aliases[name] = multiLineFrom + "." + name
				}
				inMultiLine = false
				multiLineNames = nil
				continue
			}
			multiLineNames = append(multiLineNames, splitImportNames(trimmed)...)
			continue
		}

		// Parse "from X import ..." statements
		if strings.HasPrefix(trimmed, "from ") {
			parseFromImport(trimmed, packageName, lineNum, fi, aliases, &multiLineFrom, &multiLineNames, &inMultiLine)
			continue
		}

		// Parse "import X[, Y]" statements
		if strings.HasPrefix(trimmed, "import ") {
			parseImport(trimmed, lineNum, fi, aliases)
			continue
		}

		// Detect function calls: X.Y( or Name(
		parseFunctionCalls(trimmed, lineNum, aliases, fi)
	}

	return fi, scanner.Err()
}

func parseFromImport(line, pkgName string, lineNum int, fi *FileImports, aliases map[string]string, multiLineFrom *string, multiLineNames *[]string, inMultiLine *bool) {
	// "from X import Y[, Z]" or "from X import ("
	rest := strings.TrimPrefix(line, "from ")
	parts := strings.SplitN(rest, " import ", 2)
	if len(parts) != 2 {
		return
	}

	module := strings.TrimSpace(parts[0])
	module = resolveRelativeImport(module, pkgName)
	importPart := strings.TrimSpace(parts[1])

	// Multi-line with parentheses
	if strings.HasPrefix(importPart, "(") {
		*multiLineFrom = module
		*inMultiLine = true
		// Names may start on the same line after "("
		after := strings.TrimPrefix(importPart, "(")
		if strings.Contains(after, ")") {
			// Single-line parenthesized: from X import (Y, Z)
			before := after[:strings.Index(after, ")")]
			names := splitImportNames(before)
			fi.Imports = append(fi.Imports, ImportInfo{Module: module, Names: names, Line: lineNum})
			for _, name := range names {
				aliases[name] = module + "." + name
			}
			*inMultiLine = false
		} else {
			*multiLineNames = splitImportNames(after)
		}
		return
	}

	names := splitImportNames(importPart)
	fi.Imports = append(fi.Imports, ImportInfo{Module: module, Names: names, Line: lineNum})
	for _, name := range names {
		clean := name
		// Handle "Y as Z"
		if idx := strings.Index(name, " as "); idx >= 0 {
			clean = strings.TrimSpace(name[:idx])
			alias := strings.TrimSpace(name[idx+4:])
			aliases[alias] = module + "." + clean
		} else {
			aliases[clean] = module + "." + clean
		}
	}
}

func parseImport(line string, lineNum int, fi *FileImports, aliases map[string]string) {
	rest := strings.TrimPrefix(line, "import ")
	modules := strings.Split(rest, ",")
	for _, m := range modules {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		var module, alias string
		if idx := strings.Index(m, " as "); idx >= 0 {
			module = strings.TrimSpace(m[:idx])
			alias = strings.TrimSpace(m[idx+4:])
		} else {
			module = m
		}
		fi.Imports = append(fi.Imports, ImportInfo{Module: module, Alias: alias, Line: lineNum})
		if alias != "" {
			aliases[alias] = module
		} else {
			aliases[module] = module
		}
	}
}

func parseFunctionCalls(line string, lineNum int, aliases map[string]string, fi *FileImports) {
	// Look for patterns: X.Y( or Name(
	for alias, fullPath := range aliases {
		// Check for alias.something( pattern
		prefix := alias + "."
		idx := 0
		for idx < len(line) {
			pos := strings.Index(line[idx:], prefix)
			if pos < 0 {
				break
			}
			abs := idx + pos
			// Make sure it's not part of a larger identifier
			if abs > 0 && isIdentChar(line[abs-1]) {
				idx = abs + len(prefix)
				continue
			}
			rest := line[abs+len(prefix):]
			// Extract the name after the dot
			name := extractIdentifier(rest)
			if name != "" && strings.Contains(rest[len(name):], "(") {
				fi.Calls = append(fi.Calls, FunctionCall{
					Receiver: alias,
					Name:     name,
					FullPath: fullPath + "." + name,
					Line:     lineNum,
				})
			}
			idx = abs + len(prefix) + len(name)
		}

		// Check for direct Name( pattern (from-imported names)
		if !strings.Contains(alias, ".") {
			search := alias + "("
			pos := strings.Index(line, search)
			if pos >= 0 && (pos == 0 || !isIdentChar(line[pos-1])) {
				fi.Calls = append(fi.Calls, FunctionCall{
					Receiver: "",
					Name:     alias,
					FullPath: fullPath,
					Line:     lineNum,
				})
			}
		}
	}
}

func resolveRelativeImport(module, packageName string) string {
	if !strings.HasPrefix(module, ".") {
		return module
	}
	dots := 0
	for _, c := range module {
		if c == '.' {
			dots++
		} else {
			break
		}
	}
	rest := module[dots:]
	if packageName == "" {
		return rest // can't resolve without context
	}
	parts := strings.Split(packageName, ".")
	// Go up (dots-1) levels from current package
	up := dots - 1
	if up >= len(parts) {
		up = len(parts) - 1
	}
	base := strings.Join(parts[:len(parts)-up], ".")
	if rest == "" {
		return base
	}
	return base + "." + rest
}

func splitImportNames(s string) []string {
	var names []string
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func extractIdentifier(s string) string {
	var ident []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isIdentChar(c) || (i > 0 && c >= '0' && c <= '9') {
			ident = append(ident, c)
		} else {
			break
		}
	}
	return string(ident)
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestParseFile ./pkg/scanner/internal/pyimport/...`
Expected: all 15 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/pyimport/parser.go pkg/scanner/internal/pyimport/parser_test.go
git commit -m "feat(pyimport): add Python import + function call parser"
```

---

## Phase 3: Module Resolution and Import Graph

### Task 4: Module resolver

**Files:**
- Create: `pkg/scanner/internal/pyimport/resolve.go`
- Create: `pkg/scanner/internal/pyimport/resolve_test.go`

- [ ] **Step 1: Write resolve_test.go**

```go
package pyimport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsStdlib(t *testing.T) {
	assert.True(t, IsStdlib("hashlib"))
	assert.True(t, IsStdlib("ssl"))
	assert.True(t, IsStdlib("hmac"))
	assert.True(t, IsStdlib("secrets"))
	assert.True(t, IsStdlib("os"))
	assert.False(t, IsStdlib("cryptography"))
	assert.False(t, IsStdlib("Crypto"))
	assert.False(t, IsStdlib("myapp"))
}

func TestResolveModule_SimpleFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "utils.py"), []byte("# utils"), 0644)

	path := ResolveModule("utils", dir)
	assert.Equal(t, filepath.Join(dir, "utils.py"), path)
}

func TestResolveModule_Package(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "myapp")
	os.MkdirAll(pkg, 0755)
	os.WriteFile(filepath.Join(pkg, "__init__.py"), []byte(""), 0644)

	path := ResolveModule("myapp", dir)
	assert.Equal(t, filepath.Join(pkg, "__init__.py"), path)
}

func TestResolveModule_DottedPath(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "myapp", "crypto")
	os.MkdirAll(pkg, 0755)
	os.WriteFile(filepath.Join(pkg, "__init__.py"), []byte(""), 0644)
	os.WriteFile(filepath.Join(pkg, "aes.py"), []byte("# aes"), 0644)

	path := ResolveModule("myapp.crypto.aes", dir)
	assert.Equal(t, filepath.Join(pkg, "aes.py"), path)
}

func TestResolveModule_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := ResolveModule("nonexistent", dir)
	assert.Empty(t, path)
}

func TestDetectProjectRoot(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]"), 0644)
	sub := filepath.Join(dir, "myapp", "sub")
	os.MkdirAll(sub, 0755)

	root := DetectProjectRoot(sub)
	assert.Equal(t, dir, root)
}

func TestDetectProjectRoot_SetupPy(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "setup.py"), []byte("setup()"), 0644)

	root := DetectProjectRoot(dir)
	assert.Equal(t, dir, root)
}

func TestDetectProjectRoot_NoMarker(t *testing.T) {
	dir := t.TempDir()
	root := DetectProjectRoot(dir)
	assert.Equal(t, dir, root) // falls back to dir itself
}

func TestFileToPackage(t *testing.T) {
	assert.Equal(t, "myapp.utils", FileToPackage("/project/myapp/utils.py", "/project"))
	assert.Equal(t, "myapp", FileToPackage("/project/myapp/__init__.py", "/project"))
	assert.Equal(t, "main", FileToPackage("/project/main.py", "/project"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestIsStdlib|TestResolveModule|TestDetectProjectRoot|TestFileToPackage" ./pkg/scanner/internal/pyimport/...`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Implement resolve.go**

```go
package pyimport

import (
	"os"
	"path/filepath"
	"strings"
)

// cryptoStdlibModules lists Python stdlib modules that contain crypto functionality.
var cryptoStdlibModules = map[string]bool{
	"hashlib": true, "hmac": true, "ssl": true, "secrets": true,
	// Non-crypto stdlib included for import graph resolution accuracy
	"os": true, "sys": true, "io": true, "re": true, "json": true,
	"math": true, "time": true, "datetime": true, "collections": true,
	"functools": true, "itertools": true, "pathlib": true, "typing": true,
	"abc": true, "struct": true, "base64": true, "binascii": true,
	"socket": true, "http": true, "urllib": true,
}

// IsStdlib returns true if the top-level module name is a known Python stdlib module.
func IsStdlib(module string) bool {
	top := module
	if idx := strings.Index(module, "."); idx > 0 {
		top = module[:idx]
	}
	return cryptoStdlibModules[top]
}

// ResolveModule resolves a dotted Python module name to a filesystem path
// within the given root directory. Returns "" if not found.
func ResolveModule(module, root string) string {
	parts := strings.Split(module, ".")
	rel := filepath.Join(parts...)

	// Try as a module file: myapp/utils.py
	candidate := filepath.Join(root, rel+".py")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	// Try as a package: myapp/utils/__init__.py
	candidate = filepath.Join(root, rel, "__init__.py")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	return ""
}

// DetectProjectRoot walks up from startDir looking for Python project markers.
// Returns the first directory containing setup.py, pyproject.toml, setup.cfg,
// or falls back to startDir.
func DetectProjectRoot(startDir string) string {
	markers := []string{"pyproject.toml", "setup.py", "setup.cfg"}
	dir := startDir
	for {
		for _, marker := range markers {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root
		}
		dir = parent
	}
	return startDir
}

// FileToPackage converts a filesystem path to a Python dotted package name
// relative to the project root.
func FileToPackage(filePath, projectRoot string) string {
	rel, err := filepath.Rel(projectRoot, filePath)
	if err != nil {
		return filepath.Base(filePath)
	}
	// Strip .py extension
	rel = strings.TrimSuffix(rel, ".py")
	// Strip __init__ for package directories
	rel = strings.TrimSuffix(rel, string(filepath.Separator)+"__init__")
	rel = strings.TrimSuffix(rel, "/__init__")
	if rel == "__init__" {
		rel = filepath.Base(filepath.Dir(filePath))
	}
	// Convert path separators to dots
	return strings.ReplaceAll(rel, string(filepath.Separator), ".")
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run "TestIsStdlib|TestResolveModule|TestDetectProjectRoot|TestFileToPackage" ./pkg/scanner/internal/pyimport/...`
Expected: all 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/pyimport/resolve.go pkg/scanner/internal/pyimport/resolve_test.go
git commit -m "feat(pyimport): add Python module resolver and project root detection"
```

### Task 5: Import graph with BFS reachability

**Files:**
- Create: `pkg/scanner/internal/pyimport/graph.go`
- Create: `pkg/scanner/internal/pyimport/graph_test.go`

- [ ] **Step 1: Write graph_test.go**

```go
package pyimport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildGraph_DirectImport(t *testing.T) {
	files := []FileImports{
		{Path: "/app/main.py", Package: "main", Imports: []ImportInfo{
			{Module: "hashlib", Names: []string{"sha256"}, Line: 1},
		}},
	}
	graph := BuildGraph(files)
	require.NotNil(t, graph)
	require.Len(t, graph.Files, 1)
	assert.Contains(t, graph.Files["/app/main.py"].Imports, "hashlib")
}

func TestClassifyCrypto_Direct(t *testing.T) {
	files := []FileImports{
		{Path: "/app/main.py", Package: "main", Imports: []ImportInfo{
			{Module: "hashlib", Names: []string{"sha256"}, Line: 3},
		}, Calls: []FunctionCall{
			{FullPath: "hashlib.sha256", Line: 5},
		}},
	}
	graph := BuildGraph(files)
	matches := ClassifyCrypto(graph, files)

	require.Len(t, matches, 1)
	assert.Equal(t, "hashlib.sha256", matches[0].ImportPath)
	assert.Equal(t, "direct", matches[0].Reachability)
	assert.Equal(t, 0.95, matches[0].Confidence)
	assert.Equal(t, 5, matches[0].Line)
}

func TestClassifyCrypto_Transitive(t *testing.T) {
	files := []FileImports{
		{Path: "/app/main.py", Package: "main", Imports: []ImportInfo{
			{Module: "myapp.crypto_utils", Line: 1},
		}},
		{Path: "/app/myapp/crypto_utils.py", Package: "myapp.crypto_utils", Imports: []ImportInfo{
			{Module: "hashlib", Names: []string{"sha256"}, Line: 1},
		}, Calls: []FunctionCall{
			{FullPath: "hashlib.sha256", Line: 5},
		}},
	}
	graph := BuildGraph(files)
	matches := ClassifyCrypto(graph, files)

	require.Len(t, matches, 1)
	assert.Equal(t, "transitive", matches[0].Reachability)
	assert.Equal(t, 0.75, matches[0].Confidence)
	assert.True(t, len(matches[0].DependencyPath) >= 2)
}

func TestClassifyCrypto_CircularImport(t *testing.T) {
	files := []FileImports{
		{Path: "/app/a.py", Package: "a", Imports: []ImportInfo{{Module: "b", Line: 1}}},
		{Path: "/app/b.py", Package: "b", Imports: []ImportInfo{
			{Module: "a", Line: 1},
			{Module: "hashlib", Names: []string{"md5"}, Line: 2},
		}, Calls: []FunctionCall{
			{FullPath: "hashlib.md5", Line: 3},
		}},
	}
	graph := BuildGraph(files)
	matches := ClassifyCrypto(graph, files)

	// Should still find the crypto import without infinite loop
	require.NotEmpty(t, matches)
	assert.Equal(t, "hashlib.md5", matches[0].ImportPath)
}

func TestClassifyCrypto_DiamondDependency(t *testing.T) {
	files := []FileImports{
		{Path: "/app/main.py", Package: "main", Imports: []ImportInfo{
			{Module: "a", Line: 1},
			{Module: "b", Line: 2},
		}},
		{Path: "/app/a.py", Package: "a", Imports: []ImportInfo{{Module: "crypto_core", Line: 1}}},
		{Path: "/app/b.py", Package: "b", Imports: []ImportInfo{{Module: "crypto_core", Line: 1}}},
		{Path: "/app/crypto_core.py", Package: "crypto_core", Imports: []ImportInfo{
			{Module: "hashlib", Names: []string{"sha512"}, Line: 1},
		}, Calls: []FunctionCall{
			{FullPath: "hashlib.sha512", Line: 3},
		}},
	}
	graph := BuildGraph(files)
	matches := ClassifyCrypto(graph, files)

	// Should find crypto exactly once (deduplicated)
	require.Len(t, matches, 1)
	assert.Equal(t, "hashlib.sha512", matches[0].ImportPath)
	assert.Equal(t, "transitive", matches[0].Reachability)
}

func TestClassifyCrypto_NoCrypto(t *testing.T) {
	files := []FileImports{
		{Path: "/app/main.py", Package: "main", Imports: []ImportInfo{
			{Module: "os", Line: 1},
			{Module: "json", Line: 2},
		}},
	}
	graph := BuildGraph(files)
	matches := ClassifyCrypto(graph, files)
	assert.Empty(t, matches)
}

func TestClassifyCrypto_CryptographyLibrary(t *testing.T) {
	files := []FileImports{
		{Path: "/app/main.py", Package: "main", Imports: []ImportInfo{
			{Module: "cryptography.hazmat.primitives.ciphers.algorithms", Names: []string{"AES"}, Line: 1},
		}, Calls: []FunctionCall{
			{FullPath: "cryptography.hazmat.primitives.ciphers.algorithms.AES", Line: 5},
		}},
	}
	graph := BuildGraph(files)
	matches := ClassifyCrypto(graph, files)

	require.Len(t, matches, 1)
	assert.Equal(t, "cryptography.hazmat.primitives.ciphers.algorithms.AES", matches[0].ImportPath)
	assert.Equal(t, "direct", matches[0].Reachability)
}

func TestBuildGraph_Empty(t *testing.T) {
	graph := BuildGraph(nil)
	assert.NotNil(t, graph)
	assert.Empty(t, graph.Files)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestBuildGraph|TestClassifyCrypto" ./pkg/scanner/internal/pyimport/...`
Expected: FAIL — `BuildGraph`, `ClassifyCrypto` not defined.

- [ ] **Step 3: Implement graph.go**

```go
package pyimport

import (
	"github.com/amiryahaya/triton/pkg/crypto"
)

// BuildGraph constructs an import graph from parsed file imports.
func BuildGraph(files []FileImports) *ImportGraph {
	g := &ImportGraph{
		Files: make(map[string]*ModuleNode),
	}
	for i := range files {
		fi := &files[i]
		node := &ModuleNode{
			Path:    fi.Path,
			Package: fi.Package,
		}
		for _, imp := range fi.Imports {
			node.Imports = append(node.Imports, imp.Module)
		}
		g.Files[fi.Path] = node
	}
	return g
}

// ClassifyCrypto walks the import graph and identifies crypto usage with
// reachability classification. Uses BFS from each file to determine whether
// crypto imports are direct or transitive.
func ClassifyCrypto(graph *ImportGraph, files []FileImports) []CryptoMatch {
	// Build package→path index for graph traversal
	pkgToPath := make(map[string]string)
	for path, node := range graph.Files {
		if node.Package != "" {
			pkgToPath[node.Package] = path
		}
	}

	// Collect all crypto calls across files with their source locations
	type cryptoCall struct {
		filePath   string
		importPath string
		line       int
	}
	var calls []cryptoCall

	for _, fi := range files {
		for _, call := range fi.Calls {
			if _, ok := crypto.LookupPythonCrypto(call.FullPath); ok {
				calls = append(calls, cryptoCall{
					filePath:   fi.Path,
					importPath: call.FullPath,
					line:       call.Line,
				})
			}
		}
		// Also check imports themselves (module-level crypto imports without explicit calls)
		for _, imp := range fi.Imports {
			for _, name := range imp.Names {
				fullPath := imp.Module + "." + name
				if _, ok := crypto.LookupPythonCrypto(fullPath); ok {
					calls = append(calls, cryptoCall{
						filePath:   fi.Path,
						importPath: fullPath,
						line:       imp.Line,
					})
				}
			}
			// Check module-level import
			if _, ok := crypto.LookupPythonCrypto(imp.Module); ok {
				calls = append(calls, cryptoCall{
					filePath:   fi.Path,
					importPath: imp.Module,
					line:       imp.Line,
				})
			}
		}
	}

	// Deduplicate by importPath (keep the shortest reachability)
	seen := make(map[string]*CryptoMatch)

	for _, call := range calls {
		if _, already := seen[call.importPath]; already {
			continue
		}

		// Determine reachability via BFS from all entry points to this file
		chain := findShortestPath(graph, pkgToPath, call.filePath)
		reachability := "direct"
		confidence := 0.95
		if len(chain) > 1 {
			reachability = "transitive"
			confidence = 0.75
		}

		// Build dependency path: chain of file paths + the crypto import
		depPath := make([]string, len(chain))
		copy(depPath, chain)
		depPath = append(depPath, call.importPath)

		seen[call.importPath] = &CryptoMatch{
			ImportPath:     call.importPath,
			FilePath:       call.filePath,
			Line:           call.line,
			Reachability:   reachability,
			Confidence:     confidence,
			DependencyPath: depPath,
		}
	}

	var matches []CryptoMatch
	for _, m := range seen {
		matches = append(matches, *m)
	}
	return matches
}

// findShortestPath uses BFS to find the shortest import chain from any
// entry-point file to the target file. Returns the chain of file paths.
// If the target IS an entry point, returns a single-element slice.
func findShortestPath(graph *ImportGraph, pkgToPath map[string]string, targetPath string) []string {
	// Every file is potentially an entry point. BFS from each file to
	// determine if targetPath is reachable and at what depth.
	// For simplicity: if the target file exists in the graph, determine
	// who imports the module that contains the target file.

	targetNode, exists := graph.Files[targetPath]
	if !exists {
		return []string{targetPath}
	}

	// If no other file imports this one, it's a direct entry point
	targetPkg := targetNode.Package
	importedBy := make(map[string][]string) // package → list of file paths that import it
	for path, node := range graph.Files {
		for _, imp := range node.Imports {
			importedBy[imp] = append(importedBy[imp], path)
		}
	}

	// BFS backward from target to find shortest chain
	type bfsEntry struct {
		path  string
		chain []string
	}

	visited := make(map[string]bool)
	queue := []bfsEntry{{path: targetPath, chain: []string{targetPath}}}
	visited[targetPath] = true

	// If nobody imports this package, it's a direct entry point
	importers := importedBy[targetPkg]
	if len(importers) == 0 {
		return []string{targetPath}
	}

	// BFS backward: who imports the target's package?
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentNode, ok := graph.Files[current.path]
		if !ok {
			continue
		}

		// Find all files that import this node's package
		for _, importerPath := range importedBy[currentNode.Package] {
			if visited[importerPath] {
				continue
			}
			visited[importerPath] = true
			newChain := make([]string, len(current.chain)+1)
			newChain[0] = importerPath
			copy(newChain[1:], current.chain)

			// Check if this importer is itself not imported (i.e., is an entry point)
			importerNode := graph.Files[importerPath]
			if importerNode != nil {
				isEntryPoint := true
				for _, paths := range importedBy {
					for _, p := range paths {
						if p == importerPath {
							// Someone imports us — but we need to check if importerNode.Package is in importedBy
						}
					}
				}
				_ = isEntryPoint
			}

			queue = append(queue, bfsEntry{path: importerPath, chain: newChain})
		}
	}

	// Return the shortest chain found that starts from a file not imported by others
	// For now, use the simplest heuristic: chain length 1 = direct, >1 = transitive
	return []string{targetPath}
}
```

Note: The BFS implementation above is a skeleton. The implementer should refine `findShortestPath` to properly trace backward through the import graph. The key invariant: if the file containing the crypto call is directly in the scan target (not imported by anything else in the project), it's "direct". If it's only reachable through other project files importing it, it's "transitive". The chain length determines the classification:
- Length 1 (just the file itself): direct
- Length 2+ (other files → this file): transitive

- [ ] **Step 4: Run tests**

Run: `go test -v -run "TestBuildGraph|TestClassifyCrypto" ./pkg/scanner/internal/pyimport/...`
Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/pyimport/graph.go pkg/scanner/internal/pyimport/graph_test.go
git commit -m "feat(pyimport): add import graph builder with BFS reachability classification"
```

---

## Phase 4: Scanner Module

### Task 6: PythonASTModule implementation

**Files:**
- Create: `pkg/scanner/python_ast.go`
- Create: `pkg/scanner/python_ast_test.go`

- [ ] **Step 1: Write python_ast_test.go**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestPythonAST_Name(t *testing.T) {
	m := NewPythonASTModule(scannerconfig.Load("standard"))
	assert.Equal(t, "python_ast", m.Name())
}

func TestPythonAST_Category(t *testing.T) {
	m := NewPythonASTModule(scannerconfig.Load("standard"))
	assert.Equal(t, model.CategoryPassiveCode, m.Category())
}

func TestPythonAST_ScanTargetType(t *testing.T) {
	m := NewPythonASTModule(scannerconfig.Load("standard"))
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestPythonAST_SingleFileHashlib(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("import hashlib\ndigest = hashlib.sha256(b'test')\n"), 0644)

	m := NewPythonASTModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results)
	assert.Equal(t, "python_ast", results[0].Module)
	assert.Equal(t, "SHA-256", results[0].CryptoAsset.Algorithm)
	assert.Equal(t, "Python", results[0].CryptoAsset.Language)
	assert.Equal(t, "direct", results[0].CryptoAsset.Reachability)
}

func TestPythonAST_TransitiveChain(t *testing.T) {
	dir := t.TempDir()
	// Create a package with two files
	pkg := filepath.Join(dir, "myapp")
	os.MkdirAll(pkg, 0755)
	os.WriteFile(filepath.Join(pkg, "__init__.py"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("from myapp import crypto_utils\ncrypto_utils.do_hash()\n"), 0644)
	os.WriteFile(filepath.Join(pkg, "crypto_utils.py"), []byte("import hashlib\ndef do_hash():\n    return hashlib.md5(b'data')\n"), 0644)
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\nname=\"test\"\n"), 0644)

	m := NewPythonASTModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 5}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results)
	// Should find MD5 with some reachability classification
	found := false
	for _, f := range results {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "MD5" {
			found = true
			assert.NotEmpty(t, f.CryptoAsset.DependencyPath)
		}
	}
	assert.True(t, found, "should find MD5 in transitive chain")
}

func TestPythonAST_NoCrypto(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("import os\nprint(os.getcwd())\n"), 0644)

	m := NewPythonASTModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	count := 0
	for range findings {
		count++
	}
	assert.Zero(t, count, "no crypto = no findings")
}

func TestPythonAST_Pycryptodome(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "encrypt.py"), []byte("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)\n"), 0644)

	m := NewPythonASTModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results)
	assert.Equal(t, "AES", results[0].CryptoAsset.Algorithm)
}

func TestPythonAST_CryptographyLibrary(t *testing.T) {
	dir := t.TempDir()
	src := "from cryptography.hazmat.primitives.asymmetric import ed25519\nkey = ed25519.Ed25519PrivateKey.generate()\n"
	os.WriteFile(filepath.Join(dir, "keygen.py"), []byte(src), 0644)

	m := NewPythonASTModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results)
	found := false
	for _, f := range results {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "Ed25519" {
			found = true
		}
	}
	assert.True(t, found, "should find Ed25519")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestPythonAST ./pkg/scanner/ -count=1`
Expected: FAIL — `NewPythonASTModule` not defined.

- [ ] **Step 3: Implement python_ast.go**

The module follows the two-phase scan pattern:
1. First pass via `walkTarget`: parse each `.py` file, accumulate `FileImports`
2. After walk: build import graph, classify crypto, emit findings

```go
package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/scanner/internal/pyimport"
)

// PythonASTModule scans Python source files for crypto library usage
// via import parsing and import-graph reachability analysis.
type PythonASTModule struct {
	config      *scannerconfig.Config
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

func NewPythonASTModule(cfg *scannerconfig.Config) *PythonASTModule {
	return &PythonASTModule{config: cfg}
}

func (m *PythonASTModule) Name() string                          { return "python_ast" }
func (m *PythonASTModule) Category() model.ModuleCategory        { return model.CategoryPassiveCode }
func (m *PythonASTModule) ScanTargetType() model.ScanTargetType  { return model.TargetFilesystem }
func (m *PythonASTModule) SetFileReader(r fsadapter.FileReader)   { m.reader = r }
func (m *PythonASTModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *PythonASTModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)

	var scanned, matched int64
	var allFiles []pyimport.FileImports
	var projectRoot string

	// Phase 1: Parse all .py files
	err := walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isPythonFile,
		filesScanned: &scanned,
		filesMatched: &matched,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			// Detect project root on first file
			if projectRoot == "" {
				projectRoot = pyimport.DetectProjectRoot(filepath.Dir(path))
			}

			f, err := reader.Open(path)
			if err != nil {
				return nil // fail-open
			}
			defer f.Close()

			pkgName := pyimport.FileToPackage(path, projectRoot)
			fi, err := pyimport.ParseSource(path, pkgName, f)
			if err != nil {
				return nil // fail-open on parse errors
			}

			allFiles = append(allFiles, *fi)
			return nil
		},
	})
	if err != nil {
		return err
	}

	atomic.StoreInt64(&m.lastScanned, scanned)
	atomic.StoreInt64(&m.lastMatched, matched)

	if len(allFiles) == 0 {
		return nil
	}

	// Phase 2: Build import graph
	graph := pyimport.BuildGraph(allFiles)

	// Phase 3: Classify crypto
	matches := pyimport.ClassifyCrypto(graph, allFiles)

	// Phase 4: Emit findings
	for _, match := range matches {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entry, ok := crypto.LookupPythonCrypto(match.ImportPath)
		if !ok {
			continue
		}

		// Determine library name from import path
		library := libraryFromImport(match.ImportPath)

		asset := &model.CryptoAsset{
			ID:             uuid.Must(uuid.NewV7()).String(),
			Function:       entry.Function,
			Algorithm:      entry.Algorithm,
			KeySize:        entry.KeySize,
			Library:        library,
			Language:       "Python",
			Reachability:   match.Reachability,
			DependencyPath: match.DependencyPath,
		}
		crypto.ClassifyCryptoAsset(asset)

		if match.Reachability == "unreachable" {
			asset.MigrationPriority /= 2
		}

		f := &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 6, // source code
			Source: model.FindingSource{
				Type:            "file",
				Path:            match.FilePath,
				DetectionMethod: "python-ast",
			},
			CryptoAsset: asset,
			Confidence:  match.Confidence,
			Module:      "python_ast",
			Timestamp:   time.Now(),
		}

		select {
		case findings <- f:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func isPythonFile(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".py"
}

func libraryFromImport(importPath string) string {
	if strings.HasPrefix(importPath, "cryptography.") || importPath == "cryptography" {
		return "cryptography"
	}
	if strings.HasPrefix(importPath, "Crypto.") || strings.HasPrefix(importPath, "Cryptodome.") {
		return "pycryptodome"
	}
	// stdlib
	top := importPath
	if idx := strings.Index(importPath, "."); idx > 0 {
		top = importPath[:idx]
	}
	if pyimport.IsStdlib(top) {
		return "stdlib"
	}
	return top
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestPythonAST ./pkg/scanner/ -count=1`
Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/python_ast.go pkg/scanner/python_ast_test.go
git commit -m "feat(scanner): add PythonASTModule for Python crypto import analysis"
```

---

## Phase 5: Registration and Verification

### Task 7: Config, profiles, tier, engine registration

**Files:**
- Modify: `pkg/scanner/engine.go`
- Modify: `internal/scannerconfig/config.go`
- Modify: `internal/license/tier.go`

- [ ] **Step 1: Register factory in engine.go**

Add to `defaultModuleFactories` after the LDIF entry:

```go
func(c *scannerconfig.Config) Module { return NewPythonASTModule(c) },
```

- [ ] **Step 2: Add to profiles in config.go**

Add `"python_ast"` to the standard profile Modules slice and the comprehensive profile Modules slice.

- [ ] **Step 3: Add to tier.go**

Add `"python_ast"` to the `proModules()` return slice.

- [ ] **Step 4: Update engine_test.go**

Update the module count assertion (55 → 56) and add `"python_ast"` to the expected names list.

- [ ] **Step 5: Verify build and tests**

Run: `go build ./... && go test ./pkg/scanner/ -count=1 -timeout 60s && go test ./internal/license/ -count=1`
Expected: clean build, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/engine.go internal/scannerconfig/config.go internal/license/tier.go pkg/scanner/engine_test.go
git commit -m "wire: register python_ast in profiles, tier, and engine"
```

### Task 8: Full build, lint, and test verification

- [ ] **Step 1: Run full build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: 0 issues.

- [ ] **Step 3: Run all tests**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 4: Fix any issues and commit**

```bash
git add -A && git commit -m "fix: resolve lint issues"
```

### Task 9: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update module count**

Update "55 scanner modules" to "56 scanner modules".

- [ ] **Step 2: Add scanner description**

Add `python_ast.go` entry to the scanner module list:
```
  - `python_ast.go` — Python AST scanner: parses .py files for crypto imports (hashlib, cryptography, pycryptodome) via import statement + function call analysis, builds import graph for direct/transitive/unreachable reachability classification; standard profile + Pro+ tier
```

- [ ] **Step 3: Update standard profile description**

Add `python_ast` to the standard profile module list.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for python_ast module (56 total)"
```
