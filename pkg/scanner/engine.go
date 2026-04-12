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
	config  *scannerconfig.Config
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
func New(cfg *scannerconfig.Config) *Engine {
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

	// Phase 9: Database encryption auditing & HSM scanning
	e.RegisterModule(NewDatabaseModule(e.config))
	e.RegisterModule(NewHSMModule(e.config))

	// Phase 10: P-Cert-inspired features
	e.RegisterModule(NewLDAPModule(e.config))
	e.RegisterModule(NewCodeSignModule(e.config))

	// Phase 12: Dependency crypto reachability
	e.RegisterModule(NewDepsModule(e.config))

	// Sprint A1+A3+C1: web server TLS configs, VPN configs,
	// container supply-chain signatures. Each is a config-file
	// scanner targeting TargetFilesystem; they share the
	// walker/finding pipeline used by the older config module.
	e.RegisterModule(NewWebServerModule(e.config))
	e.RegisterModule(NewVPNModule(e.config))
	e.RegisterModule(NewContainerSignaturesModule(e.config))

	// Fast Wins sprint: password hashing posture and
	// miscellaneous auth material (Kerberos keytabs, GPG keys,
	// Tor v3 onion keys, DNSSEC zone-signing keys, 802.1X
	// supplicant configs, systemd encrypted credentials).
	// certstore gains Windows Root store + Java cacerts
	// support via internal extensions (no new module).
	e.RegisterModule(NewPasswordHashModule(e.config))
	e.RegisterModule(NewAuthMaterialModule(e.config))

	// Enterprise sprint: multi-language dependency reachability
	// (Python/Node/Java), service mesh workload identity certs
	// (Istio/Linkerd/Consul Connect), XML DSig (SAML IdP/SP
	// metadata), mail server crypto (Postfix/Sendmail/Exim/DKIM).
	e.RegisterModule(NewDepsEcosystemsModule(e.config))
	e.RegisterModule(NewServiceMeshModule(e.config))
	e.RegisterModule(NewXMLDSigModule(e.config))
	e.RegisterModule(NewMailServerModule(e.config))

	// Wave 0 — OCI image scanner. Not in any profile's default module
	// list; only runs when --image is supplied, which adds TargetOCIImage
	// entries to cfg.ScanTargets. Engine dispatch naturally skips it
	// when no OCI targets exist.
	e.RegisterModule(NewOCIImageModule(e.config))

	// Wave 2 — OIDC/JWKS discovery probe. Not in any profile's
	// default module list; only runs when --oidc-endpoint is supplied,
	// which adds TargetNetwork entries to cfg.ScanTargets. Engine
	// dispatch naturally skips it when no OIDC targets exist.
	e.RegisterModule(NewOIDCProbeModule(e.config))

	// Sprint 1b — live Kubernetes cluster scanner. Enterprise-only.
	// Only runs when --kubeconfig is supplied, which adds a
	// TargetKubernetesCluster entry to cfg.ScanTargets. Engine
	// dispatch naturally skips it when no Kubernetes targets exist.
	e.RegisterModule(NewK8sLiveModule(e.config))

	// Wave 2 §6.1 — DNSSEC zone file scanner. Parses BIND/NSD/Knot
	// zone files for DNSKEY/DS/RRSIG algorithm inventory. Pro tier.
	e.RegisterModule(NewDNSSECModule(e.config))

	// Wave 2 §6.3 — Live VPN state scanner. Runs ipsec statusall,
	// wg show, openvpn status to capture negotiated algorithms.
	// Pro tier, TargetProcess.
	e.RegisterModule(NewVPNRuntimeModule(e.config))

	// Wave 2 §6.5 — Network infrastructure config scanner. Parses
	// SNMPv3, BGP, NTS, syslog-TLS, 802.1X/RADIUS configs. Pro tier.
	e.RegisterModule(NewNetInfraModule(e.config))

	// Wave 2 §6.4 — Firmware / Secure Boot scanner. EFI variables,
	// MOK chain, TPM version. Linux-first, Pro tier.
	e.RegisterModule(NewFirmwareModule(e.config))
}

// Scan executes all registered modules against configured targets.
func (e *Engine) Scan(ctx context.Context, progressCh chan<- Progress) *model.ScanResult {
	defer close(progressCh)

	start := time.Now()

	hostname, _ := os.Hostname()
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
