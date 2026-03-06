package scanner

import (
	"bufio"
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// goModuleAnalyzer abstracts Go module analysis for testability.
type goModuleAnalyzer interface {
	ParseGoMod(moduleRoot string) (*goModuleInfo, error)
	ParseGoSum(moduleRoot string) ([]string, error)
	BuildImportGraph(ctx context.Context, moduleRoot string) (*goImportGraph, error)
}

type goModuleInfo struct {
	ModulePath string
	GoVersion  string
	Requires   []goModuleRequire
}

type goModuleRequire struct {
	Path     string
	Version  string
	Indirect bool
}

type goImportGraph struct {
	PackageImports map[string][]string // package name → its imports
}

// cryptoModule represents a crypto-related module found in go.sum.
type cryptoModule struct {
	modulePath string
	algorithm  string
}

// DepsModule scans Go module dependencies to classify crypto reachability.
type DepsModule struct {
	config      *config.Config
	analyzer    goModuleAnalyzer
	lastScanned int64
	lastMatched int64
}

func NewDepsModule(cfg *config.Config) *DepsModule {
	return &DepsModule{
		config:   cfg,
		analyzer: &defaultAnalyzer{},
	}
}

func (m *DepsModule) Name() string                         { return "deps" }
func (m *DepsModule) Category() model.ModuleCategory       { return model.CategoryPassiveCode }
func (m *DepsModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *DepsModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *DepsModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	var scanned, matched int64

	wc := walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		filesScanned: &scanned,
		filesMatched: &matched,
		matchFile:    isGoModFile,
		processFile: func(path string) error {
			return m.analyzeGoModule(ctx, filepath.Dir(path), path, findings)
		},
	}

	err := walkTarget(wc)
	atomic.StoreInt64(&m.lastScanned, scanned)
	atomic.StoreInt64(&m.lastMatched, matched)
	return err
}

func isGoModFile(path string) bool {
	return filepath.Base(path) == "go.mod"
}

func (m *DepsModule) analyzeGoModule(ctx context.Context, moduleRoot, goModPath string, findings chan<- *model.Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Level 1: Parse go.mod
	modInfo, err := m.analyzer.ParseGoMod(moduleRoot)
	if err != nil {
		return nil // Skip modules we can't parse
	}

	// Level 1: Parse go.sum
	sumModules, _ := m.analyzer.ParseGoSum(moduleRoot)

	// Identify crypto modules from go.sum
	cryptoMods := identifyCryptoModules(sumModules)

	// Level 2: Build import graph
	importGraph, _ := m.analyzer.BuildImportGraph(ctx, moduleRoot)

	// Identify direct crypto imports from the root module's packages
	rootPackages := getRootPackages(importGraph, modInfo.ModulePath)

	// Collect all crypto imports found (both from import graph and go.sum)
	type cryptoFinding struct {
		algorithm      string
		importPath     string
		reachability   string
		confidence     float64
		dependencyPath []string
	}

	var cryptoFindings []cryptoFinding

	// Check direct/transitive crypto imports via import graph
	if importGraph != nil {
		// Collect all unique crypto imports across all packages
		seen := make(map[string]cryptoEntry)
		for _, imports := range importGraph.PackageImports {
			for _, imp := range imports {
				if _, already := seen[imp]; already {
					continue
				}
				entry, isCrypto := cryptoImportRegistry[imp]
				if !isCrypto {
					// Check prefix matches
					for prefix, e := range cryptoPrefixRegistry {
						if strings.HasPrefix(imp, prefix) {
							entry = e
							isCrypto = true
							break
						}
					}
				}
				if isCrypto {
					seen[imp] = entry
				}
			}
		}

		// Determine reachability for each crypto import via BFS.
		// BFS seeds from root packages, so chain length alone determines
		// reachability: length 2 = direct (root → crypto), 3+ = transitive.
		for imp, entry := range seen {
			chain := findImportChain(importGraph, rootPackages, imp)
			if chain != nil {
				reachability := "transitive"
				confidence := 0.75

				if len(chain) == 2 {
					reachability = "direct"
					confidence = 0.95
				}

				cryptoFindings = append(cryptoFindings, cryptoFinding{
					algorithm:      entry.algorithm,
					importPath:     imp,
					reachability:   reachability,
					confidence:     confidence,
					dependencyPath: chain,
				})
			}
		}
	}

	// Check go.sum-only crypto modules (unreachable if not found in import graph)
	for _, cm := range cryptoMods {
		// Check if any import graph finding already covers this module
		alreadyCovered := false
		for _, cf := range cryptoFindings {
			if strings.HasPrefix(cf.importPath, cm.modulePath) {
				alreadyCovered = true
				break
			}
		}
		if !alreadyCovered {
			cryptoFindings = append(cryptoFindings, cryptoFinding{
				algorithm:    cm.algorithm,
				importPath:   cm.modulePath,
				reachability: "unreachable",
				confidence:   0.50,
			})
		}
	}

	// Emit findings
	for _, cf := range cryptoFindings {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		asset := &model.CryptoAsset{
			ID:             uuid.Must(uuid.NewV7()).String(),
			Function:       "Dependency crypto import",
			Algorithm:      cf.algorithm,
			Language:       "Go",
			Reachability:   cf.reachability,
			DependencyPath: cf.dependencyPath,
		}
		crypto.ClassifyCryptoAsset(asset)

		// Reduce migration priority for unreachable findings
		if cf.reachability == "unreachable" {
			asset.MigrationPriority /= 2
		}

		finding := &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 6, // Source code analysis
			Source: model.FindingSource{
				Type:            "file",
				Path:            goModPath,
				DetectionMethod: "dependency-analysis",
			},
			CryptoAsset: asset,
			Confidence:  cf.confidence,
			Module:      "deps",
			Timestamp:   time.Now(),
		}

		select {
		case findings <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// getRootPackages returns package names belonging to the root module.
func getRootPackages(graph *goImportGraph, modulePath string) []string {
	if graph == nil {
		return nil
	}
	var roots []string
	for pkg := range graph.PackageImports {
		if pkg == modulePath || strings.HasPrefix(pkg, modulePath+"/") {
			roots = append(roots, pkg)
		}
	}
	// Also add short package names (e.g., "main") that aren't module-prefixed
	// These are common in local packages parsed by go/parser
	for pkg := range graph.PackageImports {
		if !strings.Contains(pkg, "/") && !strings.Contains(pkg, ".") {
			roots = append(roots, pkg)
		}
	}
	return roots
}

// findImportChain performs BFS from root packages to find the shortest import
// chain to the target crypto package.
func findImportChain(graph *goImportGraph, rootPackages []string, target string) []string {
	if graph == nil || len(rootPackages) == 0 {
		return nil
	}

	type bfsNode struct {
		pkg  string
		path []string
	}

	visited := make(map[string]bool)
	queue := make([]bfsNode, 0, len(rootPackages))

	for _, root := range rootPackages {
		if visited[root] {
			continue
		}
		visited[root] = true
		queue = append(queue, bfsNode{pkg: root, path: []string{root}})
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for _, imp := range graph.PackageImports[node.pkg] {
			if imp == target {
				return append(node.path, target)
			}
			if visited[imp] {
				continue
			}
			visited[imp] = true
			newPath := make([]string, len(node.path)+1)
			copy(newPath, node.path)
			newPath[len(node.path)] = imp
			queue = append(queue, bfsNode{pkg: imp, path: newPath})
		}
	}

	return nil
}

// --- Crypto import registry ---

type cryptoEntry struct {
	algorithm string
}

// cryptoImportRegistry maps Go import paths to algorithm names.
var cryptoImportRegistry = map[string]cryptoEntry{
	// Go stdlib crypto packages
	"crypto/aes":      {algorithm: "AES"},
	"crypto/des":      {algorithm: "DES"},
	"crypto/rc4":      {algorithm: "RC4"},
	"crypto/rsa":      {algorithm: "RSA"},
	"crypto/ecdsa":    {algorithm: "ECDSA"},
	"crypto/ed25519":  {algorithm: "Ed25519"},
	"crypto/sha256":   {algorithm: "SHA-256"},
	"crypto/sha512":   {algorithm: "SHA-512"},
	"crypto/sha1":     {algorithm: "SHA-1"},
	"crypto/md5":      {algorithm: "MD5"},
	"crypto/tls":      {algorithm: "TLS"},
	"crypto/hmac":     {algorithm: "HMAC-SHA256"}, // Algorithm-agnostic; SHA-256 is most common usage
	"crypto/cipher":   {algorithm: "AES"},         // Mode-of-operation package; AES is most common block cipher
	"crypto/elliptic": {algorithm: "ECDSA"},

	// golang.org/x/crypto packages
	"golang.org/x/crypto/chacha20poly1305": {algorithm: "ChaCha20-Poly1305"},
	"golang.org/x/crypto/bcrypt":           {algorithm: "Bcrypt"},
	"golang.org/x/crypto/scrypt":           {algorithm: "scrypt"},
	"golang.org/x/crypto/argon2":           {algorithm: "Argon2"},
	"golang.org/x/crypto/ssh":              {algorithm: "SSH"},
	"golang.org/x/crypto/nacl":             {algorithm: "X25519"},
	"golang.org/x/crypto/hkdf":             {algorithm: "HKDF"},
	"golang.org/x/crypto/pbkdf2":           {algorithm: "PBKDF2"},
	"golang.org/x/crypto/blake2b":          {algorithm: "BLAKE2b"},
	"golang.org/x/crypto/blake2s":          {algorithm: "BLAKE2s"},
	"golang.org/x/crypto/sha3":             {algorithm: "SHA3-256"},
	"golang.org/x/crypto/curve25519":       {algorithm: "X25519"},
	"golang.org/x/crypto/ed25519":          {algorithm: "Ed25519"},
	"golang.org/x/crypto/salsa20":          {algorithm: "Salsa20"},
}

// cryptoPrefixRegistry matches import paths by prefix for third-party PQC libraries.
var cryptoPrefixRegistry = map[string]cryptoEntry{
	"github.com/cloudflare/circl/kem":        {algorithm: "ML-KEM"},
	"github.com/cloudflare/circl/sign":       {algorithm: "ML-DSA"},
	"github.com/open-quantum-safe/liboqs-go": {algorithm: "ML-KEM"},
}

// identifyCryptoModules cross-references go.sum module paths with the crypto registry.
func identifyCryptoModules(sumModules []string) []cryptoModule {
	var result []cryptoModule

	for _, mod := range sumModules {
		// Check exact match in import registry
		if entry, ok := cryptoImportRegistry[mod]; ok {
			result = append(result, cryptoModule{modulePath: mod, algorithm: entry.algorithm})
			continue
		}

		// Check golang.org/x/crypto (module-level, covers all sub-packages)
		if strings.HasPrefix(mod, "golang.org/x/crypto") {
			result = append(result, cryptoModule{modulePath: mod, algorithm: "TLS"})
			continue
		}

		// Check third-party PQC libraries by substring
		if strings.Contains(mod, "cloudflare/circl") {
			result = append(result, cryptoModule{modulePath: mod, algorithm: "ML-KEM"})
			continue
		}
		if strings.Contains(mod, "liboqs-go") || strings.Contains(mod, "open-quantum-safe") {
			result = append(result, cryptoModule{modulePath: mod, algorithm: "ML-KEM"})
			continue
		}
	}

	return result
}

// --- Default analyzer implementation ---

type defaultAnalyzer struct{}

func (a *defaultAnalyzer) ParseGoMod(moduleRoot string) (*goModuleInfo, error) {
	path := filepath.Join(moduleRoot, "go.mod")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info := &goModuleInfo{}
	scanner := bufio.NewScanner(f)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Handle require block
		if line == ")" {
			inRequireBlock = false
			continue
		}

		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require(") {
			inRequireBlock = true
			continue
		}

		if inRequireBlock {
			req := parseRequireLine(line)
			if req != nil {
				info.Requires = append(info.Requires, *req)
			}
			continue
		}

		// Single-line directives
		if strings.HasPrefix(line, "module ") {
			info.ModulePath = strings.TrimPrefix(line, "module ")
			continue
		}

		if strings.HasPrefix(line, "go ") {
			info.GoVersion = strings.TrimPrefix(line, "go ")
			continue
		}

		if strings.HasPrefix(line, "require ") {
			// Single-line require
			rest := strings.TrimPrefix(line, "require ")
			req := parseRequireLine(rest)
			if req != nil {
				info.Requires = append(info.Requires, *req)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return info, nil
}

func parseRequireLine(line string) *goModuleRequire {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return nil
	}

	indirect := strings.Contains(line, "// indirect")
	// Remove comment
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	return &goModuleRequire{
		Path:     parts[0],
		Version:  parts[1],
		Indirect: indirect,
	}
}

func (a *defaultAnalyzer) ParseGoSum(moduleRoot string) ([]string, error) {
	path := filepath.Join(moduleRoot, "go.sum")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	seen := make(map[string]bool)
	var modules []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		mod := parts[0]
		if !seen[mod] {
			seen[mod] = true
			modules = append(modules, mod)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return modules, nil
}

func (a *defaultAnalyzer) BuildImportGraph(ctx context.Context, moduleRoot string) (*goImportGraph, error) {
	graph := &goImportGraph{
		PackageImports: make(map[string][]string),
	}

	// Parse the root module's .go files
	err := a.parseDirectoryImports(ctx, moduleRoot, graph)
	if err != nil {
		return nil, err
	}

	// Also parse vendor/ directory if it exists
	vendorDir := filepath.Join(moduleRoot, "vendor")
	if info, err := os.Stat(vendorDir); err == nil && info.IsDir() {
		err = a.parseVendorImports(ctx, vendorDir, graph)
		if err != nil {
			return nil, err
		}
	}

	if len(graph.PackageImports) == 0 {
		return nil, nil
	}

	return graph, nil
}

func (a *defaultAnalyzer) parseDirectoryImports(ctx context.Context, dir string, graph *goImportGraph) error {
	fset := token.NewFileSet()

	// Parse .go files in the directory (ImportsOnly mode — lightweight, no type checking).
	// We intentionally use ParseDir over x/tools/go/packages to avoid adding a heavy
	// external dependency; build tags are not relevant for import-only scanning.
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // see above
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		return nil // Skip directories that can't be parsed
	}

	for pkgName, pkg := range pkgs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var imports []string
		for _, file := range pkg.Files {
			for _, imp := range file.Imports {
				impPath, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					continue
				}
				imports = append(imports, impPath)
			}
		}

		// Deduplicate imports
		seen := make(map[string]bool)
		var unique []string
		for _, imp := range imports {
			if !seen[imp] {
				seen[imp] = true
				unique = append(unique, imp)
			}
		}

		if len(unique) > 0 {
			graph.PackageImports[pkgName] = unique
		}
	}

	// Recurse into subdirectories (but skip vendor, .git, testdata)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "vendor" || name == ".git" || name == "testdata" || name == "node_modules" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := a.parseDirectoryImports(ctx, filepath.Join(dir, name), graph); err != nil {
			return err
		}
	}

	return nil
}

func (a *defaultAnalyzer) parseVendorImports(ctx context.Context, vendorDir string, graph *goImportGraph) error {
	return filepath.WalkDir(vendorDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if !d.IsDir() {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try to parse .go files in this directory
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, path, func(fi os.FileInfo) bool { //nolint:staticcheck // intentional: avoids x/tools dep
			return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		if err != nil {
			return nil
		}

		for _, pkg := range pkgs {
			// Compute the import path from the vendor directory structure
			rel, err := filepath.Rel(vendorDir, path)
			if err != nil {
				continue
			}
			importPath := filepath.ToSlash(rel)

			var imports []string
			for _, file := range pkg.Files {
				for _, imp := range file.Imports {
					impPath, err := strconv.Unquote(imp.Path.Value)
					if err != nil {
						continue
					}
					imports = append(imports, impPath)
				}
			}

			// Deduplicate
			seen := make(map[string]bool)
			var unique []string
			for _, imp := range imports {
				if !seen[imp] {
					seen[imp] = true
					unique = append(unique, imp)
				}
			}

			if len(unique) > 0 {
				graph.PackageImports[importPath] = unique
			}
		}

		return nil
	})
}
