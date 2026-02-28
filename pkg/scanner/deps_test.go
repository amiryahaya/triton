package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// --- Mock analyzer ---

type mockGoModuleAnalyzer struct {
	modInfo    *goModuleInfo
	modErr     error
	sumModules []string
	sumErr     error
	importGraph *goImportGraph
	graphErr    error
}

func (m *mockGoModuleAnalyzer) ParseGoMod(moduleRoot string) (*goModuleInfo, error) {
	return m.modInfo, m.modErr
}

func (m *mockGoModuleAnalyzer) ParseGoSum(moduleRoot string) ([]string, error) {
	return m.sumModules, m.sumErr
}

func (m *mockGoModuleAnalyzer) BuildImportGraph(ctx context.Context, moduleRoot string) (*goImportGraph, error) {
	return m.importGraph, m.graphErr
}

// --- Helper ---

func depsTestConfig() *config.Config {
	return &config.Config{
		Profile: "standard",
		Workers: 4,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: "/tmp/test", Depth: 10},
		},
	}
}

func collectFindings(ch chan *model.Finding) []model.Finding {
	var findings []model.Finding
	for f := range ch {
		findings = append(findings, *f)
	}
	return findings
}

// --- Test 1: Interface ---

func TestDepsModule_Interface(t *testing.T) {
	m := NewDepsModule(depsTestConfig())

	assert.Equal(t, "deps", m.Name())
	assert.Equal(t, model.CategoryPassiveCode, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

// --- Test 2: isGoModFile ---

func TestDepsModule_IsGoModFile(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"/project/go.mod", true},
		{"/project/sub/go.mod", true},
		{"go.mod", true},
		{"/project/go.sum", false},
		{"/project/main.go", false},
		{"/project/go.mod.bak", false},
		{"/project/Dockerfile", false},
		{"/project/my-go.mod", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isGoModFile(tt.path))
		})
	}
}

// --- Test 3: ParseGoMod basic ---

func TestParseGoMod_Basic(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	err := os.WriteFile(gomod, []byte(`module github.com/example/myapp

go 1.21

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.1.0
)
`), 0644)
	require.NoError(t, err)

	a := &defaultAnalyzer{}
	info, err := a.ParseGoMod(dir)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "github.com/example/myapp", info.ModulePath)
	assert.Equal(t, "1.21", info.GoVersion)
	assert.Len(t, info.Requires, 2)
	assert.Equal(t, "github.com/foo/bar", info.Requires[0].Path)
	assert.Equal(t, "v1.2.3", info.Requires[0].Version)
	assert.False(t, info.Requires[0].Indirect)
}

// --- Test 4: ParseGoMod indirect deps ---

func TestParseGoMod_IndirectDeps(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	err := os.WriteFile(gomod, []byte(`module github.com/example/myapp

go 1.21

require (
	github.com/foo/bar v1.0.0
	github.com/indirect/dep v2.0.0 // indirect
)
`), 0644)
	require.NoError(t, err)

	a := &defaultAnalyzer{}
	info, err := a.ParseGoMod(dir)
	require.NoError(t, err)

	require.Len(t, info.Requires, 2)

	assert.Equal(t, "github.com/foo/bar", info.Requires[0].Path)
	assert.False(t, info.Requires[0].Indirect)

	assert.Equal(t, "github.com/indirect/dep", info.Requires[1].Path)
	assert.True(t, info.Requires[1].Indirect)
}

// --- Test 5: ParseGoSum deduplicates ---

func TestParseGoSum_Deduplicates(t *testing.T) {
	dir := t.TempDir()
	gosum := filepath.Join(dir, "go.sum")
	err := os.WriteFile(gosum, []byte(`github.com/foo/bar v1.0.0 h1:abc123=
github.com/foo/bar v1.0.0/go.mod h1:def456=
github.com/baz/qux v0.1.0 h1:ghi789=
github.com/baz/qux v0.1.0/go.mod h1:jkl012=
golang.org/x/crypto v0.17.0 h1:mno345=
golang.org/x/crypto v0.17.0/go.mod h1:pqr678=
`), 0644)
	require.NoError(t, err)

	a := &defaultAnalyzer{}
	modules, err := a.ParseGoSum(dir)
	require.NoError(t, err)

	// Should have 3 unique modules, not 6 lines
	assert.Len(t, modules, 3)
	assert.Contains(t, modules, "github.com/foo/bar")
	assert.Contains(t, modules, "github.com/baz/qux")
	assert.Contains(t, modules, "golang.org/x/crypto")
}

// --- Test 6: identifyCryptoModules ---

func TestIdentifyCryptoModules(t *testing.T) {
	sumModules := []string{
		"github.com/foo/bar",
		"golang.org/x/crypto",
		"github.com/cloudflare/circl",
		"github.com/baz/qux",
		"github.com/open-quantum-safe/liboqs-go",
	}

	found := identifyCryptoModules(sumModules)

	// Should find crypto-related modules
	assert.NotEmpty(t, found)

	// Check known crypto modules are detected
	var paths []string
	for _, cm := range found {
		paths = append(paths, cm.modulePath)
	}
	assert.Contains(t, paths, "golang.org/x/crypto")
	assert.Contains(t, paths, "github.com/cloudflare/circl")
	assert.Contains(t, paths, "github.com/open-quantum-safe/liboqs-go")

	// Non-crypto modules should not be included
	assert.NotContains(t, paths, "github.com/foo/bar")
	assert.NotContains(t, paths, "github.com/baz/qux")
}

// --- Test 7: Reachability direct ---

func TestReachability_Direct(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/myapp",
			GoVersion:  "1.21",
			Requires: []goModuleRequire{
				{Path: "golang.org/x/crypto", Version: "v0.17.0", Indirect: false},
			},
		},
		sumModules: []string{"golang.org/x/crypto"},
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{
				"github.com/example/myapp": {"crypto/aes"},
			},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}

	// Create go.mod in target dir
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	// Find the direct finding
	var directFound bool
	for _, f := range result {
		if f.CryptoAsset != nil && f.CryptoAsset.Reachability == "direct" {
			directFound = true
			assert.InDelta(t, 0.95, f.Confidence, 0.01)
		}
	}
	assert.True(t, directFound, "should have at least one direct reachability finding")
}

// --- Test 8: Reachability transitive ---

func TestReachability_Transitive(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/myapp",
			GoVersion:  "1.21",
			Requires: []goModuleRequire{
				{Path: "github.com/foo/bar", Version: "v1.0.0", Indirect: false},
			},
		},
		sumModules: []string{"github.com/foo/bar", "golang.org/x/crypto"},
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{
				"github.com/example/myapp": {"github.com/foo/bar"},
				"github.com/foo/bar":       {"crypto/des"},
			},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	var transitiveFound bool
	for _, f := range result {
		if f.CryptoAsset != nil && f.CryptoAsset.Reachability == "transitive" {
			transitiveFound = true
			assert.InDelta(t, 0.75, f.Confidence, 0.01)
			assert.True(t, len(f.CryptoAsset.DependencyPath) >= 3,
				"transitive path should have at least 3 hops")
		}
	}
	assert.True(t, transitiveFound, "should have at least one transitive reachability finding")
}

// --- Test 9: Reachability unreachable ---

func TestReachability_Unreachable(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/myapp",
			GoVersion:  "1.21",
			Requires: []goModuleRequire{
				{Path: "github.com/foo/bar", Version: "v1.0.0", Indirect: false},
			},
		},
		sumModules: []string{"github.com/foo/bar", "golang.org/x/crypto"},
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{
				"github.com/example/myapp": {"fmt"},
			},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	var unreachableFound bool
	for _, f := range result {
		if f.CryptoAsset != nil && f.CryptoAsset.Reachability == "unreachable" {
			unreachableFound = true
			assert.InDelta(t, 0.50, f.Confidence, 0.01)
		}
	}
	assert.True(t, unreachableFound, "should have at least one unreachable finding")
}

// --- Test 10: findImportChain shortest path ---

func TestFindImportChain_ShortestPath(t *testing.T) {
	graph := &goImportGraph{
		PackageImports: map[string][]string{
			"myapp":        {"pkg/a", "pkg/b"},
			"pkg/a":        {"crypto/aes"},
			"pkg/b":        {"pkg/c"},
			"pkg/c":        {"crypto/aes"},
		},
	}

	chain := findImportChain(graph, []string{"myapp"}, "crypto/aes")
	require.NotNil(t, chain)
	// Shortest path: myapp → pkg/a → crypto/aes (length 3)
	assert.Equal(t, 3, len(chain))
	assert.Equal(t, "myapp", chain[0])
	assert.Equal(t, "crypto/aes", chain[len(chain)-1])
}

// --- Test 11: findImportChain no path ---

func TestFindImportChain_NoPath(t *testing.T) {
	graph := &goImportGraph{
		PackageImports: map[string][]string{
			"myapp": {"fmt", "os"},
		},
	}

	chain := findImportChain(graph, []string{"myapp"}, "crypto/des")
	assert.Nil(t, chain)
}

// --- Test 12: Migration priority reduction ---

func TestMigrationPriorityReduction(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/myapp",
			GoVersion:  "1.21",
			Requires: []goModuleRequire{
				{Path: "golang.org/x/crypto", Version: "v0.17.0", Indirect: true},
			},
		},
		sumModules: []string{"golang.org/x/crypto"},
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{
				"github.com/example/myapp": {"fmt"}, // No crypto imports
			},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)

	for _, f := range result {
		if f.CryptoAsset != nil && f.CryptoAsset.Reachability == "unreachable" {
			// Unreachable findings should have reduced priority
			assert.True(t, f.CryptoAsset.MigrationPriority < 100,
				"unreachable findings should have reduced migration priority")
		}
	}
}

// --- Test 13: No go.mod → graceful skip ---

func TestScan_NoGoMod(t *testing.T) {
	m := NewDepsModule(depsTestConfig())

	dir := t.TempDir()
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 10}

	go func() {
		defer close(findings)
		err := m.Scan(context.Background(), target, findings)
		assert.NoError(t, err)
	}()

	result := collectFindings(findings)
	assert.Empty(t, result)
}

// --- Test 14: Empty module ---

func TestScan_EmptyModule(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/empty",
			GoVersion:  "1.21",
			Requires:   nil,
		},
		sumModules: nil,
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/empty\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	assert.Empty(t, result)
}

// --- Test 15: Integration with synthetic Go module ---

func TestScan_Integration(t *testing.T) {
	dir := t.TempDir()

	// Create go.mod
	err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module github.com/test/integration

go 1.21

require (
	github.com/foo/bar v1.0.0
)
`), 0644)
	require.NoError(t, err)

	// Create go.sum
	err = os.WriteFile(filepath.Join(dir, "go.sum"), []byte(`github.com/foo/bar v1.0.0 h1:abc123=
github.com/foo/bar v1.0.0/go.mod h1:def456=
golang.org/x/crypto v0.17.0 h1:ghi789=
golang.org/x/crypto v0.17.0/go.mod h1:jkl012=
`), 0644)
	require.NoError(t, err)

	// Create main.go that imports crypto/sha256
	err = os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	h := sha256.Sum256([]byte("hello"))
	fmt.Printf("%x\n", h)
}
`), 0644)
	require.NoError(t, err)

	m := NewDepsModule(depsTestConfig())
	// Use real analyzer for integration test

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 10}

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	// Should find sha256 as directly imported
	var foundSha256 bool
	for _, f := range result {
		if f.CryptoAsset != nil && f.CryptoAsset.Reachability == "direct" {
			foundSha256 = true
		}
	}
	assert.True(t, foundSha256, "should detect directly imported crypto/sha256")
}

// --- Test 16: PQC classification ---

func TestScan_PQCClassification(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/myapp",
			GoVersion:  "1.21",
			Requires:   nil,
		},
		sumModules: nil,
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{
				"github.com/example/myapp": {"crypto/des", "crypto/aes"},
			},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	for _, f := range result {
		require.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus, "CryptoAsset should have PQC classification")
	}
}

// --- Test 17: Finding shape ---

func TestScan_FindingShape(t *testing.T) {
	m := NewDepsModule(depsTestConfig())
	m.analyzer = &mockGoModuleAnalyzer{
		modInfo: &goModuleInfo{
			ModulePath: "github.com/example/myapp",
			GoVersion:  "1.21",
			Requires:   nil,
		},
		sumModules: nil,
		importGraph: &goImportGraph{
			PackageImports: map[string][]string{
				"github.com/example/myapp": {"crypto/aes"},
			},
		},
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: t.TempDir(), Depth: 10}
	gomod := filepath.Join(target.Value, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	f := result[0]
	assert.Equal(t, 6, f.Category)
	assert.Equal(t, "deps", f.Module)
	assert.Equal(t, "dependency-analysis", f.Source.DetectionMethod)
	assert.Equal(t, "file", f.Source.Type)
	assert.NotEmpty(t, f.ID)
	assert.False(t, f.Timestamp.IsZero())
}

// --- Test 18: Context cancellation ---

func TestScan_ContextCancellation(t *testing.T) {
	m := NewDepsModule(depsTestConfig())

	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	err := os.WriteFile(gomod, []byte("module github.com/example/myapp\n\ngo 1.21\n"), 0644)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 10}

	done := make(chan struct{})
	go func() {
		defer close(findings)
		_ = m.Scan(ctx, target, findings)
		close(done)
	}()

	select {
	case <-done:
		// Completed without hanging
	case <-time.After(2 * time.Second):
		t.Fatal("Scan did not respect context cancellation")
	}
}

// --- Test 19: BuildImportGraph with stdlib parser ---

func TestBuildImportGraph_StdlibParser(t *testing.T) {
	dir := t.TempDir()

	// Create a Go source file
	err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"
)

func main() {
	fmt.Println(aes.BlockSize)
	_ = sha256.New()
}
`), 0644)
	require.NoError(t, err)

	a := &defaultAnalyzer{}
	graph, err := a.BuildImportGraph(context.Background(), dir)
	require.NoError(t, err)
	require.NotNil(t, graph)

	// The "main" package should have imports
	mainImports := graph.PackageImports["main"]
	assert.Contains(t, mainImports, "crypto/aes")
	assert.Contains(t, mainImports, "crypto/sha256")
	assert.Contains(t, mainImports, "fmt")
}

// --- Test 20: Vendor directory ---

func TestScan_VendorDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create go.mod
	err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module github.com/test/vendor

go 1.21

require github.com/foo/bar v1.0.0
`), 0644)
	require.NoError(t, err)

	// Create go.sum
	err = os.WriteFile(filepath.Join(dir, "go.sum"), []byte(`github.com/foo/bar v1.0.0 h1:abc123=
github.com/foo/bar v1.0.0/go.mod h1:def456=
`), 0644)
	require.NoError(t, err)

	// Create main.go importing vendor dep
	err = os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main

import "github.com/foo/bar"

func main() { bar.Do() }
`), 0644)
	require.NoError(t, err)

	// Create vendor directory with dep that imports crypto
	vendorDir := filepath.Join(dir, "vendor", "github.com", "foo", "bar")
	require.NoError(t, os.MkdirAll(vendorDir, 0755))

	err = os.WriteFile(filepath.Join(vendorDir, "bar.go"), []byte(`package bar

import "crypto/des"

func Do() { _ = des.BlockSize }
`), 0644)
	require.NoError(t, err)

	m := NewDepsModule(depsTestConfig())

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 10}

	go func() {
		defer close(findings)
		_ = m.Scan(context.Background(), target, findings)
	}()

	result := collectFindings(findings)
	require.NotEmpty(t, result)

	// The vendor dep's crypto/des should be detected as transitive
	var foundTransitive bool
	for _, f := range result {
		if f.CryptoAsset != nil && f.CryptoAsset.Reachability == "transitive" {
			foundTransitive = true
		}
	}
	assert.True(t, foundTransitive, "should detect transitive crypto through vendor directory")
}
