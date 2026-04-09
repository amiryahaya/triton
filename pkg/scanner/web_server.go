package scanner

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// logScannerErr logs a bufio.Scanner error from a parser loop.
// Called after every Scan loop so operators see partial parses
// (e.g., a single line >1 MB hitting bufio.ErrTooLong). No-op
// on nil to keep call sites clean.
func logScannerErr(path, parser string, err error) {
	if err != nil {
		log.Printf("%s parser: partial parse of %s: %v", parser, path, err)
	}
}

// WebServerModule scans HTTP/web-tier configuration files for TLS
// crypto posture: protocols, cipher suites, ECDH curves, HSTS.
// Sprint coverage gap closer for nginx, Apache, haproxy, Caddy.
//
// We deliberately do not parse the rest of the directives — only
// the crypto-relevant ones — so the parser stays small and is
// resilient to vendor-specific syntax we don't recognize. Anything
// we don't understand is silently skipped, never an error.
type WebServerModule struct {
	config      *config.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewWebServerModule wires a WebServerModule with the engine config.
func NewWebServerModule(cfg *config.Config) *WebServerModule {
	return &WebServerModule{config: cfg}
}

func (m *WebServerModule) Name() string                         { return "web_server" }
func (m *WebServerModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *WebServerModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *WebServerModule) SetStore(s store.Store)               { m.store = s }

func (m *WebServerModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target filesystem and parses every file matching
// isWebServerConfigFile. Errors from individual file reads are
// swallowed (operator file permissions on production servers vary
// wildly and we don't want a single ENOENT to abort the scan).
func (m *WebServerModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isWebServerConfigFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			results := m.parseConfig(path, data)
			for _, f := range results {
				// B1 — a parser may return nil for degenerate
				// tokens (e.g., a lone `!` in an OpenSSL cipher
				// list). The engine collector dereferences the
				// finding pointer, so a nil here would panic
				// the whole scan. Drop them silently.
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

// parseConfig dispatches to the right parser based on the path.
// Path-based dispatch (rather than content sniffing) keeps the
// parser table flat and matches operator mental models — they
// know "Caddyfile is at /etc/caddy/Caddyfile".
func (m *WebServerModule) parseConfig(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)
	switch {
	case base == "haproxy.cfg":
		return m.parseHaproxy(path, data)
	case base == "Caddyfile":
		return m.parseCaddyfile(path, data)
	case strings.Contains(lower, "/apache2/") || strings.Contains(lower, "/httpd/"):
		return m.parseApache(path, data)
	case strings.Contains(lower, "/nginx/") || base == "nginx.conf":
		return m.parseNginx(path, data)
	}
	// Unknown layout but matched the matcher — fall back to nginx
	// (most common). Worst case it produces zero findings.
	return m.parseNginx(path, data)
}

// isWebServerConfigFile decides whether a file is in scope. Path-
// based; cheaper than reading file contents and good enough for
// the canonical install layouts. Custom installs that put nginx
// configs in /opt/myorg/configs/ won't be matched, but operators
// can point a target at that directory and the matcher catches
// it via the .conf extension + nginx layout test.
func isWebServerConfigFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Caddy uses a single canonical filename.
	if base == "Caddyfile" {
		return true
	}
	// haproxy uses a single canonical filename.
	if base == "haproxy.cfg" {
		return true
	}
	// nginx and Apache: any .conf under their config tree.
	if filepath.Ext(base) != ".conf" {
		return false
	}
	if strings.Contains(lower, "/nginx/") ||
		strings.Contains(lower, "/apache2/") ||
		strings.Contains(lower, "/httpd/") {
		return true
	}
	return false
}

// --- nginx ---

// nginxDirectiveRE captures `directive arg1 arg2 …;` lines after
// stripping leading whitespace. nginx allows the value to span a
// single line (we don't support backslash continuation — rare in
// the directives we care about).
var nginxDirectiveRE = regexp.MustCompile(`^\s*([a-zA-Z_]+)\s+(.+?);\s*(?:#.*)?$`)

func (m *WebServerModule) parseNginx(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		m.matchNginxLine(path, stripped, &out)
	}
	// S2 — log bufio scanner errors so an over-long line
	// (>1 MB) doesn't silently truncate the scan. We don't
	// fail the scan because the findings we already collected
	// are still useful.
	logScannerErr(path, "nginx", scanner.Err())
	return out
}

// matchNginxLine processes one nginx directive line. The
// nginxDirectiveRE captures the standard `directive value;`
// shape including HSTS lines like
// `add_header Strict-Transport-Security "..." always;` so
// there is no non-regex fallback path — S3 review finding.
func (m *WebServerModule) matchNginxLine(path, line string, out *[]*model.Finding) {
	match := nginxDirectiveRE.FindStringSubmatch(line)
	if match == nil {
		return
	}
	directive := strings.ToLower(match[1])
	value := strings.TrimSpace(match[2])
	value = strings.Trim(value, `"`)

	switch directive {
	case "ssl_protocols":
		for _, p := range fields(value) {
			appendNonNil(out, m.tlsVersionFinding(path, "nginx", p))
		}
	case "ssl_ciphers":
		for _, c := range cipherList(value) {
			appendNonNil(out, m.cipherFinding(path, "nginx", c))
		}
	case "ssl_ecdh_curve":
		for _, c := range strings.Split(value, ":") {
			appendNonNil(out, m.curveFinding(path, "nginx", c))
		}
	case "add_header":
		if strings.Contains(strings.ToLower(value), "strict-transport-security") {
			appendNonNil(out, m.hstsFinding(path, "nginx", value))
		}
	}
}

// --- Apache ---

func (m *WebServerModule) parseApache(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		stripped := strings.TrimSpace(scanner.Text())
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		m.matchApacheLine(path, stripped, &out)
	}
	logScannerErr(path, "apache", scanner.Err())
	return out
}

// matchApacheLine processes one Apache directive. Apache uses
// space-separated `Directive value` syntax (no trailing
// semicolons), and SSLProtocol/SSLCipherSuite values are
// space-separated lists with optional `+`/`-` prefixes for
// add/remove semantics relative to the build defaults.
func (m *WebServerModule) matchApacheLine(path, line string, out *[]*model.Finding) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	directive := strings.ToLower(parts[0])
	switch directive {
	case "sslprotocol":
		for _, raw := range parts[1:] {
			// Strip the +/- modifier; we want to know what the
			// operator's policy mentions, not whether they
			// added or removed it.
			v := strings.TrimLeft(raw, "+-")
			if v == "" {
				continue
			}
			appendNonNil(out, m.tlsVersionFinding(path, "apache", v))
		}
	case "sslciphersuite":
		// Apache uses ":" or " " to separate ciphers; the value
		// can be multi-word. Re-join everything after the
		// directive and split on : / space.
		//
		// B4 review — Apache permits `SSLCipherSuite "HIGH:!NULL"`
		// with outer double-quotes. Without stripping them,
		// the first and last cipher tokens carry literal `"`
		// characters that survive TrimLeft("!-+") and pollute
		// the algorithm name in every finding. Mirror the
		// nginx parser which strips outer quotes before
		// cipher-list splitting.
		raw := strings.Trim(strings.Join(parts[1:], " "), `"`)
		for _, c := range cipherList(raw) {
			appendNonNil(out, m.cipherFinding(path, "apache", c))
		}
	case "header":
		if strings.Contains(strings.ToLower(line), "strict-transport-security") {
			appendNonNil(out, m.hstsFinding(path, "apache", line))
		}
	}
}

// --- haproxy ---

func (m *WebServerModule) parseHaproxy(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		stripped := strings.TrimSpace(scanner.Text())
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		m.matchHaproxyLine(path, stripped, &out)
	}
	logScannerErr(path, "haproxy", scanner.Err())
	return out
}

func (m *WebServerModule) matchHaproxyLine(path, line string, out *[]*model.Finding) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	directive := strings.ToLower(parts[0])
	switch directive {
	case "ssl-default-bind-ciphers", "ssl-default-server-ciphers":
		for _, c := range cipherList(parts[1]) {
			appendNonNil(out, m.cipherFinding(path, "haproxy", c))
		}
	case "ssl-default-bind-options", "ssl-default-server-options":
		// Format: `ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets …`
		for i := 1; i < len(parts); i++ {
			if strings.EqualFold(parts[i], "ssl-min-ver") && i+1 < len(parts) {
				appendNonNil(out, m.tlsVersionFinding(path, "haproxy", parts[i+1]))
			}
		}
	}
}

// --- Caddy ---

// parseCaddyfile is a tiny structural parser. Caddy uses a
// brace-delimited block syntax; we don't model the AST, we just
// look for known directives wherever they appear. This loses
// scope (we'd report a `protocols` line under any block as a
// general finding) but it's the right tradeoff for a config
// scanner where presence-of-weak-crypto is the question, not
// per-site enforcement details.
func (m *WebServerModule) parseCaddyfile(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "caddy", scanner.Err()) }()
	for scanner.Scan() {
		stripped := strings.TrimSpace(scanner.Text())
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		parts := strings.Fields(stripped)
		if len(parts) < 2 {
			continue
		}
		directive := strings.ToLower(parts[0])
		switch directive {
		case "protocols":
			for _, p := range parts[1:] {
				appendNonNil(&out, m.tlsVersionFinding(path, "caddy", p))
			}
		case "ciphers":
			for _, c := range parts[1:] {
				appendNonNil(&out, m.cipherFinding(path, "caddy", c))
			}
		case "curves":
			for _, c := range parts[1:] {
				appendNonNil(&out, m.curveFinding(path, "caddy", c))
			}
		case "header":
			if strings.Contains(strings.ToLower(stripped), "strict-transport-security") {
				appendNonNil(&out, m.hstsFinding(path, "caddy", stripped))
			}
		}
	}
	return out
}

// --- finding builders (shared across all parsers) ---

// tlsVersionMap normalizes the many spellings of TLS versions
// across web servers into the registry's canonical names.
var tlsVersionMap = map[string]string{
	"sslv2":   "SSL 2.0",
	"sslv3":   "SSL 3.0",
	"tlsv1":   "TLS 1.0",
	"tlsv1.0": "TLS 1.0",
	"tls1":    "TLS 1.0",
	"tls1.0":  "TLS 1.0",
	"tlsv1.1": "TLS 1.1",
	"tls1.1":  "TLS 1.1",
	"tlsv1.2": "TLS 1.2",
	"tls1.2":  "TLS 1.2",
	"tlsv1.3": "TLS 1.3",
	"tls1.3":  "TLS 1.3",
}

func (m *WebServerModule) tlsVersionFinding(path, server, raw string) *model.Finding {
	key := strings.ToLower(raw)
	canonical, ok := tlsVersionMap[key]
	if !ok {
		// Unknown spelling like "all" or a custom modifier — emit
		// a finding tagged with the raw value so operators see
		// non-canonical pinning instead of silently dropping it.
		canonical = raw + " (no version pinning)"
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TLS protocol version",
		Algorithm: canonical,
		Purpose:   server + " ssl_protocols / SSLProtocol / protocols",
	}
	crypto.ClassifyCryptoAsset(asset)
	return webServerFinding(path, asset)
}

func (m *WebServerModule) cipherFinding(path, server, raw string) *model.Finding {
	if raw == "" {
		return nil
	}
	// Strip OpenSSL list operators (`!`, `-`, `+`).
	cleaned := strings.TrimLeft(raw, "!-+")
	if cleaned == "" {
		return nil
	}
	info := crypto.ClassifyAlgorithm(cleaned, 0)
	algoName := info.Name
	if algoName == "" {
		algoName = cleaned
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TLS cipher suite",
		Algorithm: algoName,
		KeySize:   info.KeySize,
		Purpose:   server + " ssl_ciphers / SSLCipherSuite / ciphers",
	}
	crypto.ClassifyCryptoAsset(asset)
	return webServerFinding(path, asset)
}

func (m *WebServerModule) curveFinding(path, server, raw string) *model.Finding {
	if raw == "" {
		return nil
	}
	info := crypto.ClassifyAlgorithm(raw, 0)
	algoName := info.Name
	if algoName == "" {
		algoName = raw
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TLS ECDH curve",
		Algorithm: algoName,
		KeySize:   info.KeySize,
		Purpose:   server + " ssl_ecdh_curve / curves",
	}
	crypto.ClassifyCryptoAsset(asset)
	return webServerFinding(path, asset)
}

func (m *WebServerModule) hstsFinding(path, server, raw string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "HTTP Strict Transport Security",
		Algorithm: "HSTS",
		Purpose:   server + " HSTS header: " + truncate(raw, 120),
		PQCStatus: "TRANSITIONAL",
	}
	return webServerFinding(path, asset)
}

// webServerFinding wraps a CryptoAsset into a Finding with the
// fields the rest of the pipeline expects (Module, Source,
// Confidence, Timestamp). Centralized so every parser path
// produces a uniform Finding. The vendor name is already
// embedded in asset.Purpose by the caller, so we don't take a
// separate vendor parameter here.
func webServerFinding(path string, asset *model.CryptoAsset) *model.Finding {
	if asset == nil {
		return nil
	}
	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryConfig,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceHigh,
		Module:      "web_server",
		Timestamp:   time.Now(),
	}
}

// --- helpers ---

// fields splits a whitespace-separated value, trimming each piece.
func fields(s string) []string {
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cipherList splits an OpenSSL cipher list ("A:B:!C") into
// individual cipher names. Honors both colon and space separators
// because Apache and haproxy disagree.
func cipherList(s string) []string {
	// Replace spaces with colons so we have a single separator.
	s = strings.ReplaceAll(s, " ", ":")
	parts := strings.Split(s, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// truncate caps a string at n bytes, appending an ellipsis when
// it actually shortens. Used so HSTS finding Purpose lines stay
// readable in the report UI.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
