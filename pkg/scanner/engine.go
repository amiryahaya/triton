package scanner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/model"
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

// Engine orchestrates concurrent module execution and finding collection.
type Engine struct {
	config  *config.Config
	modules []Module
	store   store.Store
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
func New(cfg *config.Config) *Engine {
	return &Engine{
		config: cfg,
	}
}

// SetStore sets the persistence store for incremental scanning and result storage.
func (e *Engine) SetStore(s store.Store) {
	e.store = s
}

// Store returns the engine's store, or nil if none is set.
func (e *Engine) Store() store.Store {
	return e.store
}

// RegisterModule adds a module to the engine.
func (e *Engine) RegisterModule(m Module) {
	e.modules = append(e.modules, m)
}

// RegisterDefaultModules registers the built-in scanner modules.
func (e *Engine) RegisterDefaultModules() {
	// Phase 1 & 2: Passive file scanners (Categories 2-5)
	e.RegisterModule(NewCertificateModule(e.config))
	e.RegisterModule(NewKeyModule(e.config))
	e.RegisterModule(NewPackageModule(e.config))
	e.RegisterModule(NewLibraryModule(e.config))
	e.RegisterModule(NewBinaryModule(e.config))
	e.RegisterModule(NewKernelModule(e.config))
	e.RegisterModule(NewConfigModule(e.config))

	// Phase 3: Code analysis (Categories 6-7)
	e.RegisterModule(NewScriptModule(e.config))
	e.RegisterModule(NewWebAppModule(e.config))

	// Phase 3: Runtime & network (Categories 1, 8, 9)
	e.RegisterModule(NewProcessModule(e.config))
	e.RegisterModule(NewNetworkModule(e.config))
	e.RegisterModule(NewProtocolModule(e.config))

	// Phase 8: Container & OS certificate store
	e.RegisterModule(NewContainerModule(e.config))
	e.RegisterModule(NewCertStoreModule(e.config))
}

// Scan executes all registered modules against configured targets.
func (e *Engine) Scan(ctx context.Context, progressCh chan<- Progress) *model.ScanResult {
	defer close(progressCh)

	start := time.Now()

	hostname, _ := os.Hostname()
	result := &model.ScanResult{
		ID: uuid.New().String(),
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
	var mu sync.Mutex

	// Collector goroutine
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for f := range findings {
			mu.Lock()
			result.Findings = append(result.Findings, *f)
			mu.Unlock()
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
		semaphore <- struct{}{}

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
				progressCh <- p
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

	progressCh <- Progress{
		Percent:  1.0,
		Status:   "Scan complete",
		Complete: true,
		Result:   result,
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
