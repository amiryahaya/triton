package scanner

import (
	"bytes"
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

// PythonASTModule scans Python source files (.py) for crypto-API usage by
// parsing import statements and function calls. It operates in two phases:
//
//  1. Walk phase — collects all FileImports from matching .py files using
//     pyimport.ParseSource.
//  2. Classify phase — builds an import graph (pyimport.BuildGraph) and
//     classifies crypto matches (pyimport.ClassifyCrypto).
//
// Detection method: "python-ast". Gated to the standard profile and Pro+
// licence tier, matching the intent of deps_ecosystems.go.
type PythonASTModule struct {
	config      *scannerconfig.Config
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

// NewPythonASTModule constructs the module.
func NewPythonASTModule(cfg *scannerconfig.Config) *PythonASTModule {
	return &PythonASTModule{config: cfg}
}

// Name returns the module's canonical name.
func (m *PythonASTModule) Name() string { return "python_ast" }

// Category returns the module category (passive source-code scanner).
func (m *PythonASTModule) Category() model.ModuleCategory { return model.CategoryPassiveCode }

// ScanTargetType returns the target type this module handles.
func (m *PythonASTModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// SetFileReader injects an optional filesystem adapter (agentless scanning).
func (m *PythonASTModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

// FileStats returns the scanned and matched file counts from the last Scan.
func (m *PythonASTModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan performs two-phase Python AST crypto detection.
func (m *PythonASTModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Value == "" {
		return nil
	}

	var scanned, matched int64
	var allFiles []pyimport.FileImports
	var projectRoot string

	// Phase 1: Walk and parse .py files.
	wc := walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		reader:       m.reader,
		filesScanned: &scanned,
		filesMatched: &matched,
		matchFile:    isPythonFile,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			// Detect project root once from the first file encountered.
			if projectRoot == "" {
				projectRoot = pyimport.DetectProjectRoot(filepath.Dir(path))
			}

			data, err := reader.ReadFile(ctx, path)
			if err != nil {
				return nil // best-effort
			}

			pkg := pyimport.FileToPackage(path, projectRoot)
			fi, err := pyimport.ParseSource(path, pkg, bytes.NewReader(data))
			if err != nil {
				return nil // best-effort
			}

			allFiles = append(allFiles, *fi)
			return nil
		},
	}

	if err := walkTarget(wc); err != nil {
		return err
	}

	atomic.StoreInt64(&m.lastScanned, scanned)
	atomic.StoreInt64(&m.lastMatched, matched)

	if len(allFiles) == 0 {
		return nil
	}

	// Phase 2: Build import graph and classify crypto matches.
	graph := pyimport.BuildGraph(allFiles)
	matches := pyimport.ClassifyCrypto(graph, allFiles)

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

		asset := &model.CryptoAsset{
			ID:             uuid.Must(uuid.NewV7()).String(),
			Algorithm:      entry.Algorithm,
			Function:       entry.Function,
			KeySize:        entry.KeySize,
			Library:        libraryFromImport(match.ImportPath),
			Language:       "Python",
			Reachability:   match.Reachability,
			DependencyPath: match.DependencyPath,
		}
		crypto.ClassifyCryptoAsset(asset)

		if match.Reachability == "unreachable" {
			asset.MigrationPriority /= 2
		}

		finding := &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 6, // Source code analysis
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
		case findings <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// isPythonFile returns true for files with a .py extension.
func isPythonFile(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".py"
}

// libraryFromImport maps a Python import path to a canonical library name.
// It recognises the main crypto library namespaces; anything unrecognised
// returns the top-level module name.
func libraryFromImport(importPath string) string {
	switch {
	case strings.HasPrefix(importPath, "cryptography."):
		return "cryptography"
	case strings.HasPrefix(importPath, "Crypto."),
		strings.HasPrefix(importPath, "Cryptodome."):
		return "pycryptodome"
	case strings.HasPrefix(importPath, "hashlib"),
		strings.HasPrefix(importPath, "hmac"),
		strings.HasPrefix(importPath, "ssl"),
		strings.HasPrefix(importPath, "secrets"):
		return "stdlib"
	default:
		// Return the top-level module name.
		if idx := strings.IndexByte(importPath, '.'); idx >= 0 {
			return importPath[:idx]
		}
		return importPath
	}
}
