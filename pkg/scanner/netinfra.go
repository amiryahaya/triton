package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// NetInfraModule scans network infrastructure configuration files
// for cryptographic posture:
//
//   - SNMPv3: auth/priv algorithms in createUser directives
//   - BGP: TCP-MD5 password presence (bird, FRR, Quagga)
//   - NTS: Network Time Security in chrony/ntpsec
//   - syslog-TLS: rsyslog gtls driver, syslog-ng transport("tls")
//   - 802.1X/RADIUS: EAP method, shared secret presence
//
// Config-parse only — no network probes. RPKI is deferred to a
// follow-up since rpki-client output format varies by version.
type NetInfraModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewNetInfraModule constructs a NetInfraModule.
func NewNetInfraModule(cfg *scannerconfig.Config) *NetInfraModule {
	return &NetInfraModule{config: cfg}
}

func (m *NetInfraModule) Name() string                         { return "netinfra" }
func (m *NetInfraModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *NetInfraModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *NetInfraModule) SetStore(s store.Store)               { m.store = s }

func (m *NetInfraModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and parses every matching config file.
func (m *NetInfraModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isNetInfraConfigFile,
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

// isNetInfraConfigFile matches network infrastructure config files.
func isNetInfraConfigFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// SNMPv3
	if strings.Contains(lower, "/snmp/") && strings.HasSuffix(base, ".conf") {
		return true
	}

	// BGP — bird, FRR, Quagga
	if base == "bird.conf" || (strings.Contains(lower, "/bird/") && strings.HasSuffix(base, ".conf")) {
		return true
	}
	if strings.Contains(lower, "/frr/") && strings.HasSuffix(base, ".conf") {
		return true
	}
	if strings.Contains(lower, "/quagga/") && strings.HasSuffix(base, ".conf") {
		return true
	}

	// RPKI
	if base == "routinator.conf" || base == "rpki-client.conf" {
		return true
	}

	// 802.1X / RADIUS — FreeRADIUS config dirs
	if strings.Contains(lower, "/raddb/") || strings.Contains(lower, "/freeradius/") {
		if strings.HasSuffix(base, ".conf") || strings.Contains(lower, "/mods-enabled/") {
			return true
		}
	}

	// NTS — chrony, ntp
	if base == "chrony.conf" || (strings.Contains(lower, "/chrony/") && strings.HasSuffix(base, ".conf")) {
		return true
	}
	if base == "ntp.conf" || (strings.Contains(lower, "/ntpsec/") && strings.HasSuffix(base, ".conf")) {
		return true
	}

	// syslog-TLS — rsyslog, syslog-ng
	if base == "rsyslog.conf" || (strings.Contains(lower, "/rsyslog") && strings.HasSuffix(base, ".conf")) {
		return true
	}
	if strings.Contains(lower, "/syslog-ng/") && strings.HasSuffix(base, ".conf") {
		return true
	}

	return false
}

// parseConfig dispatches to the right sub-parser based on path.
func (m *NetInfraModule) parseConfig(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "/snmp/"):
		return m.parseSNMPConfig(path, data)
	case strings.Contains(lower, "/bird/") || base == "bird.conf" ||
		strings.Contains(lower, "/frr/") ||
		strings.Contains(lower, "/quagga/"):
		return m.parseBGPConfig(path, data)
	case strings.Contains(lower, "/raddb/") || strings.Contains(lower, "/freeradius/"):
		return m.parseRADIUSConfig(path, data)
	case base == "chrony.conf" || strings.Contains(lower, "/chrony/") ||
		base == "ntp.conf" || strings.Contains(lower, "/ntpsec/"):
		return m.parseNTSConfig(path, data)
	case strings.Contains(lower, "rsyslog") || strings.Contains(lower, "syslog-ng"):
		return m.parseSyslogTLSConfig(path, data)
	}
	return nil
}

// --- SNMPv3 ---

// snmpAuthMap maps SNMPv3 authentication protocol names to canonical names.
var snmpAuthMap = map[string]string{
	"md5":     "MD5",
	"sha":     "SHA-1",
	"sha-224": "SHA-224",
	"sha-256": "SHA-256",
	"sha-384": "SHA-384",
	"sha-512": "SHA-512",
}

// snmpPrivMap maps SNMPv3 privacy protocol names to canonical names.
var snmpPrivMap = map[string]string{
	"des":     "DES",
	"aes":     "AES-128",
	"aes-128": "AES-128",
	"aes-192": "AES-192",
	"aes-256": "AES-256",
	"3des":    "3DES",
}

// parseSNMPConfig extracts auth/priv algorithms from createUser directives.
// Format: createUser <username> <authProto> [authPass] [<privProto> [privPass]]
func (m *NetInfraModule) parseSNMPConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "snmpv3", sc.Err()) }()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], "createuser") {
			continue
		}
		// fields[1] = username, fields[2] = auth proto
		authProto := strings.ToLower(fields[2])
		if canonical, ok := snmpAuthMap[authProto]; ok {
			out = append(out, m.netInfraFinding(path, "SNMPv3 authentication", canonical,
				fmt.Sprintf("SNMPv3 user auth in %s", filepath.Base(path))))
		}

		// Privacy proto: skip authPass (which may or may not be quoted),
		// look for a known priv proto keyword.
		for i := 3; i < len(fields); i++ {
			privProto := strings.ToLower(fields[i])
			if canonical, ok := snmpPrivMap[privProto]; ok {
				out = append(out, m.netInfraFinding(path, "SNMPv3 privacy", canonical,
					fmt.Sprintf("SNMPv3 user privacy in %s", filepath.Base(path))))
				break
			}
		}
	}
	return out
}

// --- BGP ---

// parseBGPConfig looks for BGP neighbor password directives.
// When present, BGP uses TCP-MD5 for session authentication.
func (m *NetInfraModule) parseBGPConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "bgp", sc.Err()) }()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		lower := strings.ToLower(line)

		// FRR/Quagga: "neighbor X.X.X.X password ..."
		// Bird: 'password "..."'
		if strings.Contains(lower, "password") {
			out = append(out, m.netInfraFinding(path, "BGP session authentication", "MD5",
				fmt.Sprintf("BGP neighbor TCP-MD5 in %s", filepath.Base(path))))
		}
	}
	return out
}

// --- NTS ---

// parseNTSConfig looks for NTS-enabled time sources in chrony/ntpsec configs.
// NTS uses TLS 1.3 with AEAD ciphers for time synchronization security.
func (m *NetInfraModule) parseNTSConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "nts", sc.Err()) }()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		if directive != "server" && directive != "pool" {
			continue
		}
		// Check if "nts" appears as a flag
		for _, f := range fields[2:] {
			if strings.EqualFold(f, "nts") {
				out = append(out, m.netInfraFinding(path, "NTS-secured time source", "TLS-1.3",
					fmt.Sprintf("NTS time source %s in %s", fields[1], filepath.Base(path))))
				break
			}
		}
	}
	return out
}

// --- syslog-TLS ---

// parseSyslogTLSConfig detects TLS transport in rsyslog and syslog-ng configs.
func (m *NetInfraModule) parseSyslogTLSConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "syslog-tls", sc.Err()) }()

	base := filepath.Base(path)
	lower := strings.ToLower(filepath.Dir(path) + "/" + base)
	isRsyslog := strings.Contains(lower, "rsyslog")
	isSyslogNG := strings.Contains(lower, "syslog-ng")

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineLower := strings.ToLower(line)

		if isRsyslog {
			// rsyslog: $DefaultNetstreamDriver gtls
			// or: StreamDriver="gtls"
			if strings.Contains(lineLower, "gtls") ||
				strings.Contains(lineLower, "streamdrivermode") && strings.Contains(line, "1") {
				out = append(out, m.netInfraFinding(path, "syslog TLS transport", "TLS",
					fmt.Sprintf("rsyslog TLS in %s", base)))
				return out // one finding per file is enough
			}
		}

		if isSyslogNG {
			// syslog-ng: transport("tls")
			if strings.Contains(lineLower, `transport("tls")`) || strings.Contains(lineLower, `transport(tls)`) {
				out = append(out, m.netInfraFinding(path, "syslog TLS transport", "TLS",
					fmt.Sprintf("syslog-ng TLS in %s", base)))
				return out
			}
		}
	}
	return out
}

// --- 802.1X / RADIUS ---

// parseRADIUSConfig extracts EAP method and shared secret presence from FreeRADIUS configs.
func (m *NetInfraModule) parseRADIUSConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "radius", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// EAP default type
		if strings.Contains(line, "default_eap_type") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				eapType := strings.TrimSpace(parts[1])
				eapType = strings.ToUpper(eapType)
				out = append(out, m.netInfraFinding(path, "EAP method", eapType,
					fmt.Sprintf("RADIUS EAP type in %s", base)))
			}
		}

		// Shared secret (redacted — only report presence)
		if strings.Contains(strings.ToLower(line), "secret") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" {
					out = append(out, m.netInfraFinding(path, "RADIUS shared secret", "MD5",
						fmt.Sprintf("RADIUS shared secret present in %s (value redacted)", base)))
					// Only report once per file
					break
				}
			}
		}
	}
	return out
}

// --- finding builder ---

func (m *NetInfraModule) netInfraFinding(path, function, algorithm, purpose string) *model.Finding {
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
		Confidence:  ConfidenceHigh,
		Module:      "netinfra",
		Timestamp:   time.Now(),
	}
}
