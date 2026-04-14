package scanner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// Module is the interface that all scanner modules must implement.
type Module interface {
	Name() string
	Category() model.ModuleCategory
	ScanTargetType() model.ScanTargetType
	Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error
}

// FileMetrics is implemented by modules that track file scan counts.
type FileMetrics interface {
	FileStats() (scanned, matched int64)
}

// StoreAware is implemented by modules that support incremental scanning.
type StoreAware interface {
	SetStore(s store.Store)
}

// FileReaderAware is implemented by modules that support agentless scanning
// over an injected filesystem adapter.
//
// CONTRACT: implementing SetFileReader means the module MUST route all file
// I/O for scan targets through the injected reader. Modules that call
// os.Open, os.ReadFile, zip.OpenReader, or os.Readlink directly for target
// paths MUST NOT implement this interface — engine injection would be a
// silent no-op and remote scans would miss files.
//
// If you implement this, ensure EVERY file read path uses the reader,
// including helpers called from the module's Scan loop.
type FileReaderAware interface {
	SetFileReader(r fsadapter.FileReader)
}

// CommandRunnerAware is implemented by modules that need to execute
// commands on the target. Reserved for future agentless Tier 2 work;
// no module implements this in v1.
type CommandRunnerAware interface {
	SetCommandRunner(r netadapter.CommandRunner)
}

// Engine orchestrates concurrent module execution and finding collection.
type Engine struct {
	config           *scannerconfig.Config
	modules          []Module
	store            store.Store
	reader           fsadapter.FileReader
	commandRunner    netadapter.CommandRunner
	hostnameOverride string
}

// Progress reports scan progress to the UI.
type Progress struct {
	Percent  float64
	Status   string
	Complete bool
	Error    error
	Result   *model.ScanResult
}

// New creates a new Engine with an empty module list.
func New(cfg *scannerconfig.Config) *Engine {
	return &Engine{
		config: cfg,
	}
}

// SetStore sets the persistence store for incremental scanning and result storage.
func (e *Engine) SetStore(s store.Store) {
	e.store = s
}

// SetFileReader sets the FileReader injected into FileReaderAware modules.
func (e *Engine) SetFileReader(r fsadapter.FileReader) { e.reader = r }

// SetCommandRunner sets the CommandRunner injected into CommandRunnerAware modules.
func (e *Engine) SetCommandRunner(r netadapter.CommandRunner) { e.commandRunner = r }

// SetHostnameOverride sets a hostname used in scan metadata instead of os.Hostname().
func (e *Engine) SetHostnameOverride(h string) { e.hostnameOverride = h }

// Store returns the engine's store, or nil if none is set.
func (e *Engine) Store() store.Store {
	return e.store
}

// RegisterModule adds a module to the engine.
func (e *Engine) RegisterModule(m Module) {
	e.modules = append(e.modules, m)
}

// defaultModuleFactories enumerates every Module constructor registered by
// the engine on startup. Adding a new scanner: append its factory here and
// add a profile entry in internal/scannerconfig/config.go. Engine dispatch
// (getTargetsForModule + shouldRunModule) handles per-profile / per-tier
// filtering, so registration itself is a pure enumeration.
//
// Registration order is preserved for deterministic iteration in tests;
// concurrent execution at scan time means runtime ordering is not observable
// to users.
var defaultModuleFactories = []func(*scannerconfig.Config) Module{
	func(c *scannerconfig.Config) Module { return NewCertificateModule(c) },
	func(c *scannerconfig.Config) Module { return NewKeyModule(c) },
	func(c *scannerconfig.Config) Module { return NewPackageModule(c) },
	func(c *scannerconfig.Config) Module { return NewLibraryModule(c) },
	func(c *scannerconfig.Config) Module { return NewBinaryModule(c) },
	func(c *scannerconfig.Config) Module { return NewKernelModule(c) },
	func(c *scannerconfig.Config) Module { return NewConfigModule(c) },
	func(c *scannerconfig.Config) Module { return NewScriptModule(c) },
	func(c *scannerconfig.Config) Module { return NewWebAppModule(c) },
	func(c *scannerconfig.Config) Module { return NewProcessModule(c) },
	func(c *scannerconfig.Config) Module { return NewNetworkModule(c) },
	func(c *scannerconfig.Config) Module { return NewProtocolModule(c) },
	func(c *scannerconfig.Config) Module { return NewContainerModule(c) },
	func(c *scannerconfig.Config) Module { return NewCertStoreModule(c) },
	func(c *scannerconfig.Config) Module { return NewDatabaseModule(c) },
	func(c *scannerconfig.Config) Module { return NewHSMModule(c) },
	func(c *scannerconfig.Config) Module { return NewLDAPModule(c) },
	func(c *scannerconfig.Config) Module { return NewCodeSignModule(c) },
	func(c *scannerconfig.Config) Module { return NewDepsModule(c) },
	func(c *scannerconfig.Config) Module { return NewWebServerModule(c) },
	func(c *scannerconfig.Config) Module { return NewVPNModule(c) },
	func(c *scannerconfig.Config) Module { return NewContainerSignaturesModule(c) },
	func(c *scannerconfig.Config) Module { return NewPasswordHashModule(c) },
	func(c *scannerconfig.Config) Module { return NewAuthMaterialModule(c) },
	func(c *scannerconfig.Config) Module { return NewDepsEcosystemsModule(c) },
	func(c *scannerconfig.Config) Module { return NewServiceMeshModule(c) },
	func(c *scannerconfig.Config) Module { return NewXMLDSigModule(c) },
	func(c *scannerconfig.Config) Module { return NewMailServerModule(c) },
	func(c *scannerconfig.Config) Module { return NewOCIImageModule(c) },
	func(c *scannerconfig.Config) Module { return NewOIDCProbeModule(c) },
	func(c *scannerconfig.Config) Module { return NewK8sLiveModule(c) },
	func(c *scannerconfig.Config) Module { return NewDNSSECModule(c) },
	func(c *scannerconfig.Config) Module { return NewVPNRuntimeModule(c) },
	func(c *scannerconfig.Config) Module { return NewNetInfraModule(c) },
	func(c *scannerconfig.Config) Module { return NewFirmwareModule(c) },
	func(c *scannerconfig.Config) Module { return NewMessagingModule(c) },
	func(c *scannerconfig.Config) Module { return NewDBAtRestModule(c) },
	func(c *scannerconfig.Config) Module { return NewSecretsMgrModule(c) },
	func(c *scannerconfig.Config) Module { return NewSupplyChainModule(c) },
	func(c *scannerconfig.Config) Module { return NewKerberosRuntimeModule(c) },
	func(c *scannerconfig.Config) Module { return NewEnrollmentModule(c) },
	func(c *scannerconfig.Config) Module { return NewFIDO2Module(c) },
	func(c *scannerconfig.Config) Module { return NewBlockchainModule(c) },
	func(c *scannerconfig.Config) Module { return NewHelmChartModule(c) },
	func(c *scannerconfig.Config) Module { return NewASN1OIDModule(c) },
	func(c *scannerconfig.Config) Module { return NewJavaBytecodeModule(c) },
}

// RegisterDefaultModules registers every factory in defaultModuleFactories.
// Per-profile / per-tier filtering happens later in the dispatch pipeline.
func (e *Engine) RegisterDefaultModules() {
	for _, factory := range defaultModuleFactories {
		e.RegisterModule(factory(e.config))
	}
}

// Scan executes all registered modules against configured targets.
func (e *Engine) Scan(ctx context.Context, progressCh chan<- Progress) *model.ScanResult {
	defer close(progressCh)

	start := time.Now()

	hostname := e.hostnameOverride
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	result := &model.ScanResult{
		ID: uuid.Must(uuid.NewV7()).String(),
		Metadata: model.ScanMetadata{
			Timestamp:   start,
			Hostname:    hostname,
			OS:          runtime.GOOS,
			ScanProfile: e.config.Profile,
			Targets:     e.config.ScanTargets,
			ToolVersion: version.Version,
		},
	}

	findings := make(chan *model.Finding, 100)

	// Collector goroutine — single consumer, no mutex needed.
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for f := range findings {
			result.Findings = append(result.Findings, *f)
		}
	}()

	// Inject store into modules that support incremental scanning.
	if e.store != nil {
		for _, m := range e.modules {
			if sa, ok := m.(StoreAware); ok {
				sa.SetStore(e.store)
			}
		}
	}
	if e.reader != nil {
		for _, m := range e.modules {
			if fa, ok := m.(FileReaderAware); ok {
				fa.SetFileReader(e.reader)
			}
		}
	}
	if e.commandRunner != nil {
		for _, m := range e.modules {
			if ca, ok := m.(CommandRunnerAware); ok {
				ca.SetCommandRunner(e.commandRunner)
			}
		}
	}

	result.Metadata.IncrementalMode = e.config.Incremental

	// Build module-target pairs
	type moduleTarget struct {
		module Module
		target model.ScanTarget
	}
	var pairs []moduleTarget
	for _, m := range e.modules {
		if !e.shouldRunModule(m) {
			continue
		}
		targets := e.getTargetsForModule(m)
		for _, t := range targets {
			pairs = append(pairs, moduleTarget{module: m, target: t})
		}
	}

	totalPairs := len(pairs)
	collectMetrics := e.config.Metrics

	// Metrics collection (only when enabled)
	var metrics []model.ModuleMetric
	var metricsMu sync.Mutex

	// Execute with semaphore for concurrency control
	var wg sync.WaitGroup
	workers := e.config.Workers
	if workers < 1 {
		workers = 1
	}
	semaphore := make(chan struct{}, workers)

	for i, pair := range pairs {
		wg.Add(1)
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			continue
		}

		go func(idx int, mt moduleTarget) {
			defer wg.Done()
			defer func() { <-semaphore }()

			var err error

			if collectMetrics {
				// --- Metrics path: counting channel + timing + memory ---
				pairFindings := make(chan *model.Finding, 50)
				findingsCount := 0
				var pairWg sync.WaitGroup
				pairWg.Add(1)
				go func() {
					defer pairWg.Done()
					for f := range pairFindings {
						findingsCount++
						findings <- f
					}
				}()

				var memBefore runtime.MemStats
				runtime.ReadMemStats(&memBefore)

				scanStart := time.Now()
				err = mt.module.Scan(ctx, mt.target, pairFindings)
				close(pairFindings)
				pairWg.Wait()
				duration := time.Since(scanStart)

				var memAfter runtime.MemStats
				runtime.ReadMemStats(&memAfter)

				var scanned, matched int64
				if fm, ok := mt.module.(FileMetrics); ok {
					scanned, matched = fm.FileStats()
				}

				metric := model.ModuleMetric{
					Module:        mt.module.Name(),
					Target:        mt.target.Value,
					Duration:      duration,
					FilesScanned:  scanned,
					FilesMatched:  matched,
					Findings:      findingsCount,
					MemoryDeltaMB: float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / (1024 * 1024),
				}
				if err != nil {
					metric.Error = err.Error()
				}

				metricsMu.Lock()
				metrics = append(metrics, metric)
				metricsMu.Unlock()
			} else {
				// --- Fast path: no metrics overhead ---
				err = mt.module.Scan(ctx, mt.target, findings)
			}

			if totalPairs > 0 {
				p := Progress{
					Percent: float64(idx+1) / float64(totalPairs),
					Status:  mt.module.Name() + ": " + mt.target.Value,
				}
				if err != nil {
					p.Error = fmt.Errorf("module %s failed on %s: %w", mt.module.Name(), mt.target.Value, err)
				}
				select {
				case progressCh <- p:
				case <-ctx.Done():
				}
			}
		}(i, pair)
	}

	wg.Wait()
	close(findings)
	collectorWg.Wait()

	result.Metadata.Duration = time.Since(start)

	if collectMetrics {
		result.Metadata.ModuleMetrics = metrics
		var peakMem runtime.MemStats
		runtime.ReadMemStats(&peakMem)
		result.Metadata.PeakMemoryMB = float64(peakMem.Sys) / (1024 * 1024)
	}

	result.Summary = model.ComputeSummary(result.Findings)

	select {
	case progressCh <- Progress{
		Percent:  1.0,
		Status:   "Scan complete",
		Complete: true,
		Result:   result,
	}:
	case <-ctx.Done():
	}

	return result
}

// getTargetsForModule filters config targets by the module's ScanTargetType.
func (e *Engine) getTargetsForModule(m Module) []model.ScanTarget {
	var targets []model.ScanTarget
	for _, t := range e.config.ScanTargets {
		if t.Type == m.ScanTargetType() {
			targets = append(targets, t)
		}
	}
	return targets
}

// shouldRunModule checks if a module should run based on config.Modules filter.
func (e *Engine) shouldRunModule(m Module) bool {
	if len(e.config.Modules) == 0 {
		return true
	}
	for _, name := range e.config.Modules {
		if name == m.Name() {
			return true
		}
	}
	return false
}
