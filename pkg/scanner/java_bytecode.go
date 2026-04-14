package scanner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/scanner/internal/javaclass"
	"github.com/amiryahaya/triton/pkg/store"
)

// JavaBytecodeModule scans compiled Java artifacts (.class, .jar, .war, .ear)
// for crypto-API string literals embedded in the constant pool. Complements
// the source-code scanner (webapp.go) by reaching into artifacts where
// source was stripped, obfuscated, or never shipped.
//
// Detection method: "java-bytecode". Gated to the comprehensive profile in
// internal/scannerconfig because JAR walking + class-file parsing is IO/CPU
// heavy on large application servers.
type JavaBytecodeModule struct {
	cfg    *scannerconfig.Config
	store  store.Store
	reader fsadapter.FileReader
}

// NewJavaBytecodeModule constructs the module.
func NewJavaBytecodeModule(cfg *scannerconfig.Config) *JavaBytecodeModule {
	return &JavaBytecodeModule{cfg: cfg}
}

// Name returns the module's canonical name.
func (m *JavaBytecodeModule) Name() string { return "java_bytecode" }

// Category returns the module category (passive file scanner).
func (m *JavaBytecodeModule) Category() model.ModuleCategory { return model.CategoryPassiveFile }

// ScanTargetType returns the target type this module handles.
func (m *JavaBytecodeModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// SetStore wires the incremental-scan store (StoreAware).
func (m *JavaBytecodeModule) SetStore(s store.Store) { m.store = s }

// SetFileReader wires an agentless filesystem adapter (FileReaderAware).
func (m *JavaBytecodeModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

// Scan walks target.Value, matching .class/.jar/.war/.ear files and extracting
// classified crypto literals from each.
func (m *JavaBytecodeModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Value == "" {
		return nil
	}
	return walkTarget(walkerConfig{
		ctx:       ctx,
		target:    target,
		config:    m.cfg,
		matchFile: looksLikeJavaArtifact,
		store:     m.store,
		reader:    m.reader,
		processFile: func(_ context.Context, _ fsadapter.FileReader, path string) error {
			m.scanArtifact(ctx, path, findings)
			return nil
		},
	})
}

func (m *JavaBytecodeModule) scanArtifact(ctx context.Context, path string, findings chan<- *model.Finding) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".class"):
		data, err := readFileBytes(path)
		if err != nil {
			return
		}
		strs, err := javaclass.ParseClass(data)
		if err != nil {
			return
		}
		m.classifyAndEmit(ctx, path, "", strs, findings)

	case strings.HasSuffix(lower, ".jar"),
		strings.HasSuffix(lower, ".war"),
		strings.HasSuffix(lower, ".ear"):
		hits, err := javaclass.ScanJAR(path)
		if err != nil {
			return
		}
		// Group by class path for cleaner evidence trail. Sort class paths
		// before emission so diff/trend comparisons and test assertions see
		// a deterministic finding order (Go map iteration is randomized).
		byClass := map[string][]string{}
		for _, h := range hits {
			byClass[h.ClassPath] = append(byClass[h.ClassPath], h.Value)
		}
		classPaths := make([]string, 0, len(byClass))
		for cp := range byClass {
			classPaths = append(classPaths, cp)
		}
		sort.Strings(classPaths)
		for _, classPath := range classPaths {
			m.classifyAndEmit(ctx, path, classPath, byClass[classPath], findings)
		}
	}
}

// classifyAndEmit classifies each string literal; unclassified strings are
// silently dropped. De-duplicates by (path, classPath, algorithm) — each
// unique crypto surface produces at most one finding per source.
func (m *JavaBytecodeModule) classifyAndEmit(
	ctx context.Context,
	path, classPath string,
	strs []string,
	findings chan<- *model.Finding,
) {
	seen := map[string]bool{}
	for _, s := range strs {
		entry, ok := crypto.LookupJavaAlgorithm(s)
		if !ok {
			continue
		}
		if seen[entry.Algorithm] {
			continue
		}
		seen[entry.Algorithm] = true
		select {
		case <-ctx.Done():
			return
		case findings <- buildJavaFinding(path, classPath, s, entry):
		}
	}
}

func buildJavaFinding(path, classPath, literal string, e crypto.JavaAlgEntry) *model.Finding {
	evidence := literal
	if classPath != "" {
		evidence = classPath + ": " + literal
	}
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: e.Algorithm,
		Library:   filepath.Base(path),
		Language:  "Java",
		Function:  functionForFamily(e.Family),
		PQCStatus: string(e.Status),
	}
	return &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "java-bytecode",
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.90, // literal match is high-confidence; not as strict as OID
		Module:      "java_bytecode",
		Timestamp:   time.Now().UTC(),
	}
}

// looksLikeJavaArtifact matches extension-based pre-filtering for the walker.
// The walker calls this cheaply on every file; actual format validation
// happens in scanArtifact (zip.OpenReader / ParseClass do the real checks).
func looksLikeJavaArtifact(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".class") ||
		strings.HasSuffix(lower, ".jar") ||
		strings.HasSuffix(lower, ".war") ||
		strings.HasSuffix(lower, ".ear")
}

// readFileBytes reads the entire file for .class parsing. Walker already
// enforces MaxFileSize so runaway reads are bounded at the walk layer.
func readFileBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
