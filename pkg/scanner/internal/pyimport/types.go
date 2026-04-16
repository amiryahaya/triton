// Package pyimport defines data types for Python import analysis used by the
// Python AST scanner. These types model import statements, function calls,
// per-file import graphs, and crypto match results, mirroring the conventions
// established by the javaclass internal package.
package pyimport

// ImportInfo represents a single Python import statement parsed from source.
// It covers both "import X" and "from X import Y [as Z]" forms.
type ImportInfo struct {
	// Module is the dotted module path (e.g. "cryptography.hazmat.primitives.ciphers").
	Module string
	// Names is the list of names imported from the module (empty for bare "import X").
	Names []string
	// Alias is the local alias, if present ("import numpy as np" → "np").
	Alias string
	// Line is the 1-based source line number.
	Line int
}

// FunctionCall represents a crypto-relevant function or constructor call
// identified during AST traversal.
type FunctionCall struct {
	// Receiver is the object or module on which the method is called
	// (e.g. "hashlib" in "hashlib.sha256(...)").
	Receiver string
	// Name is the function or method name (e.g. "sha256").
	Name string
	// FullPath is the resolved dotted import path used for registry lookup
	// (e.g. "hashlib.sha256").
	FullPath string
	// Line is the 1-based source line number.
	Line int
}

// FileImports aggregates all import and call information extracted from a
// single Python source file.
type FileImports struct {
	// Path is the absolute filesystem path to the source file.
	Path string
	// Package is the Python package name derived from directory structure
	// (e.g. "myapp.utils").
	Package string
	// Imports holds all import statements found in the file.
	Imports []ImportInfo
	// Calls holds all crypto-relevant function calls found in the file.
	Calls []FunctionCall
}

// ImportGraph is a lightweight dependency graph of Python modules within the
// scanned tree. It maps file paths to their corresponding ModuleNode.
type ImportGraph struct {
	// Files maps the absolute file path to its module node.
	Files map[string]*ModuleNode
}

// ModuleNode is a vertex in the ImportGraph representing a single Python module.
type ModuleNode struct {
	// Path is the absolute filesystem path to the source file.
	Path string
	// Package is the dotted Python package name for this module.
	Package string
	// Imports is the list of dotted module paths that this module imports.
	Imports []string
}

// CryptoMatch is a confirmed crypto usage found by correlating an ImportInfo
// or FunctionCall against the Python crypto registry.
type CryptoMatch struct {
	// ImportPath is the resolved dotted import path that matched the registry
	// (e.g. "cryptography.hazmat.primitives.ciphers.algorithms.AES").
	ImportPath string
	// FilePath is the absolute path to the source file containing the usage.
	FilePath string
	// Line is the 1-based source line number of the import or call.
	Line int
	// Reachability indicates how the crypto usage was reached: "direct",
	// "transitive", or "unreachable". Mirrors the convention in deps.go.
	Reachability string
	// Confidence is a normalised score in [0, 1] reflecting certainty of the
	// match. Direct usages carry 0.95; transitive 0.75; unreachable 0.50.
	Confidence float64
	// DependencyPath is the shortest import chain from an entry-point module
	// to this file (used for reporting, mirrors CryptoAsset.DependencyPath).
	DependencyPath []string
}
