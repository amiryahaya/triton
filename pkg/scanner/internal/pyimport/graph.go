package pyimport

import (
	"strings"

	"github.com/amiryahaya/triton/pkg/crypto"
)

// BuildGraph constructs an ImportGraph from a slice of parsed FileImports.
// Each file becomes a ModuleNode; the Imports field holds the dotted module
// names that the file imports.
func BuildGraph(files []FileImports) *ImportGraph {
	g := &ImportGraph{
		Files: make(map[string]*ModuleNode, len(files)),
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

// ClassifyCrypto walks the import graph, finds crypto imports and calls in each
// file, classifies them via the Python crypto registry, and assigns reachability:
//   - "direct"     (0.95) — the file containing the crypto is not imported by any
//     other project file (it is an entry point or standalone module).
//   - "transitive" (0.75) — the file IS imported by at least one other project file.
//
// Results are deduplicated by (importPath, filePath).
func ClassifyCrypto(g *ImportGraph, files []FileImports) []CryptoMatch {
	// Build a package→path index for files in the project.
	pkgToPath := make(map[string]string, len(files))
	for _, fi := range files {
		pkgToPath[fi.Package] = fi.Path
	}

	// Build a reverse index: filePath → set of file paths that import it.
	// We use the ModuleNode.Imports (dotted module names) and resolve them via
	// pkgToPath.
	importedBy := make(map[string][]string) // filePath → []importer paths
	for _, node := range g.Files {
		for _, imp := range node.Imports {
			if targetPath, ok := pkgToPath[imp]; ok {
				importedBy[targetPath] = append(importedBy[targetPath], node.Path)
			}
		}
	}

	// BFS helper: find shortest path from any file that is NOT imported by anyone
	// (i.e. an entry point) to a given target file.
	// Returns the chain [entryPath, ..., targetPath] or nil if unreachable.
	findChain := func(targetPath string) []string {
		// Identify entry points: files not imported by anyone.
		var entryPoints []string
		for _, fi := range files {
			if len(importedBy[fi.Path]) == 0 {
				entryPoints = append(entryPoints, fi.Path)
			}
		}

		// BFS from entry points.
		type qItem struct {
			path  string
			chain []string
		}
		visited := map[string]bool{}
		queue := make([]qItem, 0, len(entryPoints))
		for _, ep := range entryPoints {
			queue = append(queue, qItem{ep, []string{ep}})
			visited[ep] = true
		}

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if cur.path == targetPath {
				return cur.chain
			}
			node, ok := g.Files[cur.path]
			if !ok {
				continue
			}
			for _, imp := range node.Imports {
				childPath, ok := pkgToPath[imp]
				if !ok || visited[childPath] {
					continue
				}
				visited[childPath] = true
				newChain := make([]string, len(cur.chain)+1)
				copy(newChain, cur.chain)
				newChain[len(cur.chain)] = childPath
				queue = append(queue, qItem{childPath, newChain})
			}
		}
		return nil
	}

	// Collect crypto candidates from each file.
	type dedupKey struct {
		importPath string
		filePath   string
	}
	seen := map[dedupKey]bool{}
	var result []CryptoMatch

	for _, fi := range files {
		// Check function calls first.
		for _, call := range fi.Calls {
			if _, ok := crypto.LookupPythonCrypto(call.FullPath); ok {
				k := dedupKey{call.FullPath, fi.Path}
				if seen[k] {
					continue
				}
				seen[k] = true

				isImported := len(importedBy[fi.Path]) > 0
				m := cryptoMatchForFile(fi.Path, call.FullPath, call.Line, isImported, findChain)
				result = append(result, m)
			}
		}

		// Check import statements (module-level crypto imports).
		for _, imp := range fi.Imports {
			// Build candidate paths to check: the module itself and module.Name for each name.
			candidates := []struct {
				path string
				line int
			}{
				{imp.Module, imp.Line},
			}
			for _, name := range imp.Names {
				candidates = append(candidates, struct {
					path string
					line int
				}{imp.Module + "." + name, imp.Line})
			}

			for _, cand := range candidates {
				if _, ok := crypto.LookupPythonCrypto(cand.path); ok {
					k := dedupKey{cand.path, fi.Path}
					if seen[k] {
						continue
					}
					seen[k] = true

					isImported := len(importedBy[fi.Path]) > 0
					m := cryptoMatchForFile(fi.Path, cand.path, cand.line, isImported, findChain)
					result = append(result, m)
				}
			}
		}
	}

	return result
}

// cryptoMatchForFile creates a CryptoMatch for a given file and import path,
// determining reachability and running BFS if the file is transitive.
func cryptoMatchForFile(
	filePath, importPath string,
	line int,
	isImported bool,
	findChain func(string) []string,
) CryptoMatch {
	m := CryptoMatch{
		ImportPath: importPath,
		FilePath:   filePath,
		Line:       line,
	}

	if !isImported {
		m.Reachability = "direct"
		m.Confidence = 0.95
		m.DependencyPath = []string{filePath}
	} else {
		m.Reachability = "transitive"
		m.Confidence = 0.75
		chain := findChain(filePath)
		if chain != nil {
			m.DependencyPath = chain
		} else {
			m.DependencyPath = []string{filePath}
		}
	}

	return m
}

// resolveImportToPath resolves a dotted module import name to a file path using
// the package-to-path index. Returns "" if not found. Used internally.
func resolveImportToPath(imp string, pkgToPath map[string]string) string {
	if p, ok := pkgToPath[imp]; ok {
		return p
	}
	// Try prefix match: "myapp.utils" might partially match "myapp".
	for pkg, path := range pkgToPath {
		if strings.HasPrefix(imp, pkg+".") {
			return path
		}
	}
	return ""
}
