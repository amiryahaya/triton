package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/scanner/internal/cli"
	"github.com/amiryahaya/triton/pkg/store"
)

// DotNetILModule scans .NET assemblies (.exe, .dll) for crypto type-references
// and string literals embedded in CLI metadata. Mirrors java_bytecode for the
// .NET ecosystem. Comprehensive profile + Pro+ tier.
type DotNetILModule struct {
	cfg   *scannerconfig.Config
	store store.Store
}

// NewDotNetILModule constructs the module.
func NewDotNetILModule(cfg *scannerconfig.Config) *DotNetILModule {
	return &DotNetILModule{cfg: cfg}
}

// Name returns the canonical module name.
func (m *DotNetILModule) Name() string { return "dotnet_il" }

// Category returns the module category.
func (m *DotNetILModule) Category() model.ModuleCategory { return model.CategoryPassiveFile }

// ScanTargetType returns the target type.
func (m *DotNetILModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// SetStore wires the incremental-scan store (StoreAware).
func (m *DotNetILModule) SetStore(s store.Store) { m.store = s }

// Scan walks target.Value and processes every PE assembly.
func (m *DotNetILModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Value == "" {
		return nil
	}
	return walkTarget(walkerConfig{
		ctx:       ctx,
		target:    target,
		config:    m.cfg,
		matchFile: looksLikeDotNetAssembly,
		store:     m.store,
		processFile: func(_ context.Context, _ fsadapter.FileReader, path string) error {
			m.scanFile(ctx, path, findings)
			return nil
		},
	})
}

func (m *DotNetILModule) scanFile(ctx context.Context, path string, findings chan<- *model.Finding) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	asm, err := cli.ReadAssembly(f)
	if err == nil {
		m.classifyAndEmit(ctx, path, "", asm, findings)
	}

	bundled, err := cli.ScanBundle(path)
	if err != nil {
		return
	}
	for _, ba := range bundled {
		m.classifyAndEmit(ctx, path, ba.Path, ba.Assembly, findings)
	}
}

func (m *DotNetILModule) classifyAndEmit(
	ctx context.Context,
	hostPath, bundledPath string,
	asm *cli.Assembly,
	findings chan<- *model.Finding,
) {
	if asm == nil {
		return
	}
	seen := map[string]bool{}
	emit := func(token string) {
		entry, ok := crypto.LookupDotNetAlgorithm(token)
		if !ok {
			return
		}
		key := strings.ToLower(token)
		if seen[key] {
			return
		}
		seen[key] = true
		select {
		case <-ctx.Done():
			return
		case findings <- buildDotNetFinding(hostPath, bundledPath, token, entry):
		}
	}
	for _, t := range asm.TypeRefs {
		emit(t)
	}
	for _, s := range asm.UserStrings {
		emit(s)
	}
}

func buildDotNetFinding(hostPath, bundledPath, token string, e crypto.DotNetAlgEntry) *model.Finding {
	evidence := token
	if bundledPath != "" {
		evidence = "bundled in " + bundledPath + ": " + token
	}
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: e.Algorithm,
		Library:   filepath.Base(hostPath),
		Language:  ".NET",
		Function:  functionForFamily(e.Family),
		PQCStatus: string(e.Status),
	}
	return &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            hostPath,
			DetectionMethod: "dotnet-il",
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "dotnet_il",
		Timestamp:   time.Now().UTC(),
	}
}

func looksLikeDotNetAssembly(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".exe")
}
