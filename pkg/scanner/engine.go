package scanner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
)

// Module is the interface that all scanner modules must implement.
type Module interface {
	Name() string
	Category() model.ModuleCategory
	ScanTargetType() model.ScanTargetType
	Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error
}

// Engine orchestrates concurrent module execution and finding collection.
type Engine struct {
	config  *config.Config
	modules []Module
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

// RegisterModule adds a module to the engine.
func (e *Engine) RegisterModule(m Module) {
	e.modules = append(e.modules, m)
}

// RegisterDefaultModules registers the built-in scanner modules.
func (e *Engine) RegisterDefaultModules() {
	e.RegisterModule(NewCertificateModule(e.config))
	e.RegisterModule(NewKeyModule(e.config))
	e.RegisterModule(NewPackageModule(e.config))
	e.RegisterModule(NewLibraryModule(e.config))
	e.RegisterModule(NewBinaryModule(e.config))
	e.RegisterModule(NewKernelModule(e.config))
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
			ToolVersion: "0.1.0",
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

			err := mt.module.Scan(ctx, mt.target, findings)

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
