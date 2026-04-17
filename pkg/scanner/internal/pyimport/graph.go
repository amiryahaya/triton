package pyimport

import (
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
//
// BFS complexity: O(N + M) — a single multi-source BFS from all entry points
// pre-computes shortest chains for every reachable file before the match loop.
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

	// Pre-compute shortest chains from all entry points in a single BFS pass
	// (O(N + M)) so the match loop below can do O(1) lookups instead of
	// re-running BFS for every crypto match (was O(M×N)).
	chainFrom := computeChains(g, files, importedBy, pkgToPath)

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
			if _, ok := crypto.LookupPythonCrypto(call.FullPath); !ok {
				continue
			}
			k := dedupKey{call.FullPath, fi.Path}
			if seen[k] {
				continue
			}
			seen[k] = true

			isImported := len(importedBy[fi.Path]) > 0
			m := cryptoMatchForFile(fi.Path, call.FullPath, call.Line, isImported, chainFrom)
			result = append(result, m)
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
				if _, ok := crypto.LookupPythonCrypto(cand.path); !ok {
					continue
				}
				k := dedupKey{cand.path, fi.Path}
				if seen[k] {
					continue
				}
				seen[k] = true

				isImported := len(importedBy[fi.Path]) > 0
				m := cryptoMatchForFile(fi.Path, cand.path, cand.line, isImported, chainFrom)
				result = append(result, m)
			}
		}
	}

	return result
}

// computeChains runs a single multi-source BFS from all entry points (files not
// imported by any other file in the graph) and returns a map from filePath to
// its shortest chain from an entry point.  The BFS is O(N + M) where N is the
// number of files and M is the total number of import edges.
func computeChains(
	g *ImportGraph,
	files []FileImports,
	importedBy map[string][]string,
	pkgToPath map[string]string,
) map[string][]string {
	type qItem struct {
		path  string
		chain []string
	}

	chains := make(map[string][]string, len(files))
	queue := make([]qItem, 0, len(files))

	// Seed BFS with all entry points.
	for _, fi := range files {
		if len(importedBy[fi.Path]) == 0 {
			chain := []string{fi.Path}
			chains[fi.Path] = chain
			queue = append(queue, qItem{fi.Path, chain})
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		node, ok := g.Files[cur.path]
		if !ok {
			continue
		}
		for _, imp := range node.Imports {
			childPath, ok := pkgToPath[imp]
			if !ok {
				continue
			}
			if _, visited := chains[childPath]; visited {
				continue
			}
			newChain := make([]string, len(cur.chain)+1)
			copy(newChain, cur.chain)
			newChain[len(cur.chain)] = childPath
			chains[childPath] = newChain
			queue = append(queue, qItem{childPath, newChain})
		}
	}

	return chains
}

// cryptoMatchForFile creates a CryptoMatch for a given file and import path,
// determining reachability using the pre-computed chain map.
func cryptoMatchForFile(
	filePath, importPath string,
	line int,
	isImported bool,
	chainFrom map[string][]string,
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
		if chain, ok := chainFrom[filePath]; ok {
			m.DependencyPath = chain
		} else {
			m.DependencyPath = []string{filePath}
		}
	}

	return m
}
