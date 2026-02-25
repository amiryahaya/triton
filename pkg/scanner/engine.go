package scanner

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

type Engine struct {
	config  *config.Config
	modules []Module
	results *Results
}

type Module interface {
	Name() string
	Scan(ctx context.Context, target string, findings chan<- *model.Finding) error
}

type Results struct {
	SBOM     *model.SBOM
	CBOM     *model.CBOM
	Findings []*model.Finding
	Stats    ScanStats
	mu       sync.RWMutex
}

type ScanStats struct {
	FilesScanned      int64
	CertificatesFound int64
	KeysFound         int64
	LibrariesFound    int64
	ServicesFound     int64
	StartTime         int64
	EndTime           int64
}

type Progress struct {
	Percent  float64
	Status   string
	Complete bool
	Error    error
	Results  *Results
}

type Finding struct {
	Type        string
	Path        string
	Component   *model.Component
	CryptoAsset *model.CryptoAsset
	Confidence  float64
}

func New(cfg *config.Config) *Engine {
	return &Engine{
		config:  cfg,
		results: &Results{},
		modules: []Module{
			NewCertificateModule(cfg),
			NewKeyModule(cfg),
			NewPackageModule(cfg),
		},
	}
}

func (e *Engine) Scan(progressCh chan<- Progress) {
	defer close(progressCh)

	targets := e.getScanTargets()
	totalTargets := len(targets)

	ctx := context.Background()
	findings := make(chan *model.Finding, 100)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, e.config.Workers)

	// Collector goroutine
	go func() {
		for f := range findings {
			e.results.AddFinding(f)
		}
	}()

	// Scan targets
	for i, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			for _, module := range e.modules {
				if e.shouldRunModule(module.Name()) {
					module.Scan(ctx, t, findings)
				}
			}

			progressCh <- Progress{
				Percent: float64(idx+1) / float64(totalTargets),
				Status:  filepath.Base(t),
			}
		}(i, target)
	}

	wg.Wait()
	close(findings)

	// Generate SBOM/CBOM from findings
	e.results.SBOM = e.generateSBOM()
	e.results.CBOM = e.generateCBOM()

	progressCh <- Progress{
		Percent:  1.0,
		Status:   "Scan complete",
		Complete: true,
		Results:  e.results,
	}
}

func (e *Engine) getScanTargets() []string {
	// TODO: Implement proper target discovery based on OS
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications",
			"/System/Library",
			"/usr/local",
			"/etc",
		}
	case "linux":
		return []string{
			"/usr",
			"/etc",
			"/opt",
		}
	case "windows":
		return []string{
			`C:\Program Files`,
			`C:\ProgramData`,
			`C:\Windows\System32`,
		}
	default:
		return []string{"."}
	}
}

func (e *Engine) shouldRunModule(name string) bool {
	if len(e.config.Modules) == 0 {
		return true
	}
	for _, m := range e.config.Modules {
		if m == name {
			return true
		}
	}
	return false
}

func (e *Engine) generateSBOM() *model.SBOM {
	// TODO: Generate CycloneDX SBOM from findings
	return &model.SBOM{}
}

func (e *Engine) generateCBOM() *model.CBOM {
	// TODO: Generate CycloneDX CBOM from findings
	return &model.CBOM{}
}

func (r *Results) AddFinding(f *model.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)

	switch f.Type {
	case "certificate":
		r.Stats.CertificatesFound++
	case "key":
		r.Stats.KeysFound++
	case "library":
		r.Stats.LibrariesFound++
	}
}
