package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// HelmChartModule scans Helm chart files for crypto-relevant
// configuration:
//
//   - Chart.yaml: chart identity (name, version) for crypto-related
//     charts like cert-manager, istio, vault
//   - values.yaml: TLS configuration blocks, cipher suites, cert-manager
//     ACME references, mTLS settings
//
// Line-oriented heuristic parsing — does not render templates with
// `helm template` (deferred to a follow-up that would need the helm
// binary). Scans the static values for crypto signals.
type HelmChartModule struct {
	config      *scannerconfig.Config
	store       store.Store
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

// NewHelmChartModule constructs a HelmChartModule.
func NewHelmChartModule(cfg *scannerconfig.Config) *HelmChartModule {
	return &HelmChartModule{config: cfg}
}

func (m *HelmChartModule) Name() string                         { return "helm_chart" }
func (m *HelmChartModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *HelmChartModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *HelmChartModule) SetStore(s store.Store)               { m.store = s }
func (m *HelmChartModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func (m *HelmChartModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree for Helm chart files.
func (m *HelmChartModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isHelmChartFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			data, err := reader.ReadFile(ctx, path)
			if err != nil {
				return nil
			}
			results := m.parseFile(path, data)
			for _, f := range results {
				if f == nil {
					continue
				}
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isHelmChartFile matches Helm chart Chart.yaml and values.yaml files.
// Requires a Helm-related path context to avoid matching random YAML.
func isHelmChartFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	isChartOrValues := base == "Chart.yaml" || base == "values.yaml" || base == "values.yml"
	if !isChartOrValues {
		return false
	}

	// Require Helm-related directory context
	return strings.Contains(lower, "/charts/") ||
		strings.Contains(lower, "/helm/") ||
		strings.Contains(lower, "/.helm/")
}

// parseFile dispatches to the right sub-parser.
func (m *HelmChartModule) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	switch base {
	case "Chart.yaml":
		return m.parseChartYAML(path, data)
	case "values.yaml", "values.yml":
		return m.parseValuesYAML(path, data)
	}
	return nil
}

// --- Chart.yaml ---

// cryptoRelatedCharts lists chart names that are inherently crypto-relevant.
var cryptoRelatedCharts = map[string]string{
	"cert-manager":   "X.509 certificate management",
	"vault":          "HashiCorp Vault secrets",
	"istio":          "Service mesh mTLS",
	"linkerd":        "Service mesh mTLS",
	"traefik":        "Ingress TLS termination",
	"nginx-ingress":  "Ingress TLS termination",
	"ingress-nginx":  "Ingress TLS termination",
	"external-dns":   "DNS management",
	"sealed-secrets": "Bitnami sealed secrets encryption",
}

// parseChartYAML extracts chart identity for crypto-relevant charts.
func (m *HelmChartModule) parseChartYAML(path string, data []byte) []*model.Finding {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "helm-chart", sc.Err()) }()

	var chartName, chartVersion string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "name:") {
			chartName = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			chartName = strings.Trim(chartName, `"'`)
		}
		if strings.HasPrefix(line, "version:") {
			chartVersion = strings.TrimSpace(strings.TrimPrefix(line, "version:"))
			chartVersion = strings.Trim(chartVersion, `"'`)
		}
	}

	if chartName == "" {
		return nil
	}

	purpose := fmt.Sprintf("Helm chart %s", chartName)
	if chartVersion != "" {
		purpose += " v" + chartVersion
	}

	// Check if this is a known crypto-relevant chart
	algo := "Helm-managed"
	if desc, ok := cryptoRelatedCharts[strings.ToLower(chartName)]; ok {
		algo = desc
	}

	return []*model.Finding{m.helmFinding(path, "Helm chart", algo, purpose)}
}

// --- values.yaml ---

// parseValuesYAML scans values.yaml for TLS, cipher, and cert-manager references.
func (m *HelmChartModule) parseValuesYAML(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "helm-values", sc.Err()) }()

	base := filepath.Base(path)
	hasTLS := false
	hasACME := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)

		// TLS configuration blocks
		if !hasTLS && (strings.Contains(lower, "tls:") ||
			strings.Contains(lower, "ssl-ciphers") ||
			strings.Contains(lower, "ciphersuites") ||
			strings.Contains(lower, "minversion") && strings.Contains(lower, "tls")) {
			hasTLS = true
		}

		// ACME / cert-manager references
		if !hasACME && (strings.Contains(lower, "acme") ||
			strings.Contains(lower, "cert-manager") ||
			strings.Contains(lower, "certmanager") ||
			strings.Contains(lower, "letsencrypt")) {
			hasACME = true
		}
	}

	if hasTLS {
		out = append(out, m.helmFinding(path, "Helm TLS configuration", "TLS",
			fmt.Sprintf("TLS config in %s", base)))
	}
	if hasACME {
		out = append(out, m.helmFinding(path, "Helm ACME/cert-manager reference", "ACME",
			fmt.Sprintf("ACME/cert-manager reference in %s", base)))
	}

	return out
}

// --- finding builder ---

func (m *HelmChartModule) helmFinding(path, function, algorithm, purpose string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algorithm,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algorithm

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryConfig,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceMedium,
		Module:      "helm_chart",
		Timestamp:   time.Now(),
	}
}
