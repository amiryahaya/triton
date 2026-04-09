package scanner

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// MailServerModule scans mail-related TLS and DKIM config on
// Postfix, Sendmail, Exim, and OpenDKIM installations:
//
//   - Postfix `main.cf` / `master.cf`: smtpd_tls_*, smtp_tls_*
//   - Sendmail `sendmail.cf` / `submit.cf`: TLS_SRV_OPTIONS etc.
//   - Exim `exim4.conf`: tls_require_ciphers, tls_advertise_hosts
//   - OpenDKIM `KeyTable` (lists signing keys per domain)
//   - OpenDKIM / opendkim.conf (global signing config)
//   - DKIM private key files under /etc/dkim/*.private
//
// Email infrastructure is the most crypto-heavy surface in a
// typical Linux host and nobody bothers to scan it. NACSA-2030
// and EU NIS2 both call DKIM out explicitly as a PQC-transition
// item, which makes this a direct compliance deliverable.
type MailServerModule struct {
	config      *config.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

func NewMailServerModule(cfg *config.Config) *MailServerModule {
	return &MailServerModule{config: cfg}
}

func (m *MailServerModule) Name() string                         { return "mail_server" }
func (m *MailServerModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *MailServerModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *MailServerModule) SetStore(s store.Store)               { m.store = s }

func (m *MailServerModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *MailServerModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if ctx == nil {
		ctx = context.Background()
	}
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isMailServerConfigFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			for _, f := range m.parseFile(path) {
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

// isMailServerConfigFile matches every mail-server config file we
// know how to parse. The DKIM private-key match happens by suffix
// alone since these files are always named `.private` under the
// DKIM key directory.
func isMailServerConfigFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch base {
	case "main.cf", "master.cf":
		return strings.Contains(lower, "/postfix/")
	case "sendmail.cf", "submit.cf":
		return true
	case "exim4.conf", "exim.conf":
		return true
	case "opendkim.conf", "KeyTable":
		return true
	}
	// DKIM private keys live under /etc/dkim/ or /etc/opendkim/keys/
	// and have a .private extension.
	if strings.HasSuffix(base, ".private") && (strings.Contains(lower, "/dkim/") || strings.Contains(lower, "/opendkim/")) {
		return true
	}
	return false
}

func (m *MailServerModule) parseFile(path string) []*model.Finding {
	base := filepath.Base(path)
	switch {
	case base == "main.cf" || base == "master.cf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return m.parsePostfix(path, data)
	case base == "sendmail.cf" || base == "submit.cf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return m.parseSendmail(path, data)
	case base == "exim4.conf" || base == "exim.conf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return m.parseExim(path, data)
	case base == "KeyTable":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return m.parseDKIMKeyTable(path, data)
	case base == "opendkim.conf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return m.parseOpenDKIMConf(path, data)
	case strings.HasSuffix(base, ".private"):
		return m.parseDKIMKeyFile(path)
	}
	return nil
}

// --- Postfix ---

// postfixTLSDirectives lists the directives we surface. Each maps
// to a finding Function label describing what the directive
// controls. We surface the operator's declared policy as-is
// (space-split tokens) rather than interpreting Postfix's
// `high`/`medium`/`low` abstraction, because the abstraction
// means different things across OpenSSL versions.
var postfixTLSDirectives = map[string]string{
	"smtpd_tls_security_level":      "Postfix inbound TLS security level",
	"smtp_tls_security_level":       "Postfix outbound TLS security level",
	"smtpd_tls_mandatory_protocols": "Postfix inbound mandatory TLS protocols",
	"smtp_tls_mandatory_protocols":  "Postfix outbound mandatory TLS protocols",
	"smtpd_tls_protocols":           "Postfix inbound TLS protocols",
	"smtp_tls_protocols":            "Postfix outbound TLS protocols",
	"smtpd_tls_mandatory_ciphers":   "Postfix inbound mandatory cipher grade",
	"smtp_tls_mandatory_ciphers":    "Postfix outbound mandatory cipher grade",
	"smtpd_tls_ciphers":             "Postfix inbound cipher grade",
	"smtp_tls_ciphers":              "Postfix outbound cipher grade",
	"smtpd_tls_cipher_suites":       "Postfix inbound cipher list",
	"smtp_tls_cipher_suites":        "Postfix outbound cipher list",
}

// joinPostfixContinuations merges Postfix main.cf continuation
// lines into their parent directive. Postfix allows a value to
// span multiple lines when the continuation lines start with
// whitespace (spaces or tabs). Without this join, a directive
// like:
//
//	smtpd_tls_mandatory_protocols =
//	    !SSLv2, !SSLv3
//
// would parse as a directive with an empty value plus a
// standalone `!SSLv3` line that has no `=` and gets dropped.
// Sprint-review SF6 regression.
func joinPostfixContinuations(data []byte) []string {
	var joined []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			joined = append(joined, raw)
			continue
		}
		// Leading whitespace means this line is a continuation
		// of the previous one.
		if len(joined) > 0 && (strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")) {
			joined[len(joined)-1] += " " + strings.TrimSpace(raw)
			continue
		}
		joined = append(joined, raw)
	}
	return joined
}

func (m *MailServerModule) parsePostfix(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	lines := joinPostfixContinuations(data)
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		value := strings.TrimSpace(line[eq+1:])
		function, known := postfixTLSDirectives[key]
		if !known {
			continue
		}
		// Split the value on commas and spaces and emit one
		// finding per token. Postfix protocol lists use `!` to
		// exclude — we strip the `!` and emit the bare protocol
		// name because the operator clearly knows about it.
		tokens := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		for _, tok := range tokens {
			tok = strings.TrimLeft(tok, "!-+")
			if tok == "" {
				continue
			}
			display := mailTLSNormalize(tok)
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  function,
				Algorithm: display,
				Purpose:   "postfix " + key + " = " + truncate(value, 80),
			}
			crypto.ClassifyCryptoAsset(asset)
			asset.Algorithm = display
			out = append(out, mailFinding(path, asset))
		}
	}
	return out
}

// mailTLSNormalize maps protocol / cipher tokens from mail server
// configs to canonical registry names. Anything unknown passes
// through unchanged.
func mailTLSNormalize(tok string) string {
	canonical, ok := tlsVersionMap[strings.ToLower(tok)]
	if ok {
		return canonical
	}
	return tok
}

// --- Sendmail + Exim (minimal — directive presence) ---

func (m *MailServerModule) parseSendmail(path string, data []byte) []*model.Finding {
	// Sendmail's config is opaque — we grep for TLS-related
	// directives and emit a presence finding. A full parser is
	// not worth the effort given how few sites still use it.
	var out []*model.Finding
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if lower == "" || strings.HasPrefix(lower, "#") {
			continue
		}
		if strings.Contains(lower, "tls_srv_options") || strings.Contains(lower, "cipherlist") ||
			strings.Contains(lower, "servercertfile") {
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  "Sendmail TLS directive",
				Algorithm: "Sendmail-TLS",
				Purpose:   "Sendmail TLS config: " + truncate(strings.TrimSpace(line), 80),
			}
			crypto.ClassifyCryptoAsset(asset)
			asset.Algorithm = "Sendmail-TLS"
			out = append(out, mailFinding(path, asset))
		}
	}
	return out
}

func (m *MailServerModule) parseExim(path string, data []byte) []*model.Finding {
	// Same approach as Sendmail: presence-based for the TLS
	// directives that matter.
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "tls_require_ciphers") || strings.HasPrefix(lower, "tls_advertise_hosts") ||
			strings.HasPrefix(lower, "openssl_options") {
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  "Exim TLS directive",
				Algorithm: "Exim-TLS",
				Purpose:   "Exim TLS config: " + truncate(line, 80),
			}
			crypto.ClassifyCryptoAsset(asset)
			asset.Algorithm = "Exim-TLS"
			out = append(out, mailFinding(path, asset))
		}
	}
	return out
}

// --- OpenDKIM KeyTable + conf ---

// parseDKIMKeyTable walks an OpenDKIM KeyTable file. Each line is:
//
//	<signer-name> <domain>:<selector>:<keyfile-path>
//
// We emit one finding per entry. The keyfile path is extracted
// into the purpose so operators can correlate with the key file
// itself.
func (m *MailServerModule) parseDKIMKeyTable(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		signer := fields[0]
		spec := fields[1]
		// Break the `domain:selector:keyfile` triple.
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) < 3 {
			continue
		}
		domain, selector, keyfile := parts[0], parts[1], parts[2]
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "DKIM signing key entry",
			Algorithm: "DKIM-key",
			Purpose:   "DKIM KeyTable signer=" + signer + " domain=" + domain + " selector=" + selector + " keyfile=" + keyfile,
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = "DKIM-key"
		out = append(out, mailFinding(path, asset))
	}
	return out
}

func (m *MailServerModule) parseOpenDKIMConf(path string, data []byte) []*model.Finding {
	// Look for SignatureAlgorithm lines which set the DKIM
	// signature algorithm globally (rsa-sha256 by default).
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "signaturealgorithm") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		algo := parts[1]
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "DKIM signature algorithm",
			Algorithm: algo,
			Purpose:   "OpenDKIM SignatureAlgorithm = " + algo,
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = algo
		out = append(out, mailFinding(path, asset))
	}
	return out
}

// parseDKIMKeyFile emits a presence finding for a DKIM private
// key file. We don't parse the PEM — certificate.go / key.go
// already do that for generic PEM files. This module's job is
// just to tag the file with the DKIM context so reports can
// group it.
func (m *MailServerModule) parseDKIMKeyFile(path string) []*model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "DKIM private signing key",
		Algorithm: "DKIM-private-key",
		Purpose:   "DKIM key file " + filepath.Base(path),
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = "DKIM-private-key"
	return []*model.Finding{mailFinding(path, asset)}
}

// --- finding builder ---

func mailFinding(path string, asset *model.CryptoAsset) *model.Finding {
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
		Module:      "mail_server",
		Timestamp:   time.Now(),
	}
}
