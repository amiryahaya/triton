package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// DNSSECModule scans BIND/NSD/Knot zone files for DNSKEY, DS, and
// RRSIG records and extracts the DNSSEC signing algorithm from each.
// This is a content-based zone file parser — the existing
// AuthMaterialModule handles DNSSEC *key files* by filename only;
// this module reads zone file bodies to inventory the full set of
// algorithms deployed in a zone.
//
// The algorithm number→name mapping reuses dnssecAlgoMap from
// auth_material.go (same package).
type DNSSECModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewDNSSECModule constructs a DNSSECModule wired to the engine config.
func NewDNSSECModule(cfg *scannerconfig.Config) *DNSSECModule {
	return &DNSSECModule{config: cfg}
}

func (m *DNSSECModule) Name() string                         { return "dnssec" }
func (m *DNSSECModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *DNSSECModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *DNSSECModule) SetStore(s store.Store)               { m.store = s }

func (m *DNSSECModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree for zone files and optionally runs active
// dig queries for zones specified via --dnssec-zone.
func (m *DNSSECModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)

	// Phase 1: passive zone file walk.
	err := walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isDNSSECZoneFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			results := m.parseZoneFile(path, data)
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
	if err != nil {
		return err
	}

	// Phase 2: active dig queries for --dnssec-zone targets.
	if m.config != nil {
		for _, zone := range m.config.DNSSECZones {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			results := m.queryDNSKEY(ctx, zone)
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
		}
	}

	return nil
}

// digRunner abstracts `dig` execution for testability.
var digRunner = func(ctx context.Context, zone string) ([]byte, error) {
	return exec.CommandContext(ctx, "dig", "+dnssec", "+noall", "+answer", "DNSKEY", zone).Output()
}

// queryDNSKEY runs `dig +dnssec +noall +answer DNSKEY <zone>` and
// parses the answer section for DNSKEY records.
func (m *DNSSECModule) queryDNSKEY(ctx context.Context, zone string) []*model.Finding {
	out, err := digRunner(ctx, zone)
	if err != nil {
		log.Printf("dnssec: dig DNSKEY %s failed: %v", zone, err)
		return nil
	}
	return m.parseDigOutput(zone, out)
}

// parseDigOutput parses dig answer-section output for DNSKEY records.
// Each line: <name> <TTL> IN DNSKEY <flags> <protocol> <algorithm> <key>
func (m *DNSSECModule) parseDigOutput(zone string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		// Expect: name TTL IN DNSKEY flags proto algo key...
		// Find DNSKEY keyword
		dnskeyIdx := -1
		for i, f := range fields {
			if strings.EqualFold(f, "DNSKEY") {
				dnskeyIdx = i
				break
			}
		}
		if dnskeyIdx < 0 || dnskeyIdx+3 >= len(fields) {
			continue
		}
		rdata := fields[dnskeyIdx+1:]
		flags, err := strconv.Atoi(rdata[0])
		if err != nil {
			continue
		}
		algoNum := rdata[2]
		algoName := resolveAlgo(algoNum)

		function := "DNSKEY"
		switch flags {
		case 257:
			function = "DNSKEY (KSK)"
		case 256:
			function = "DNSKEY (ZSK)"
		}

		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  function,
			Algorithm: algoName,
			Purpose:   fmt.Sprintf("dig DNSKEY %s", zone),
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = algoName

		appendNonNil(&out, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: CategoryConfig,
			Source: model.FindingSource{
				Type:            "network",
				Endpoint:        zone,
				DetectionMethod: "dns-query",
			},
			CryptoAsset: asset,
			Confidence:  ConfidenceDefinitive,
			Module:      "dnssec",
			Timestamp:   time.Now(),
		})
	}
	return out
}

// isDNSSECZoneFile decides whether a path looks like a DNS zone file.
// We match by extension (.zone) or by the BIND convention of db.<name>
// prefix. Only files under well-known DNS directories or with the
// .zone extension are matched to avoid false positives.
func isDNSSECZoneFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(base))

	// .zone extension — unambiguous
	if ext == ".zone" {
		return true
	}

	// BIND db.<something> convention — only under DNS-related paths
	// to avoid matching random database files.
	if strings.HasPrefix(base, "db.") {
		if strings.Contains(lower, "/bind/") ||
			strings.Contains(lower, "/named/") ||
			strings.Contains(lower, "/nsd/") ||
			strings.Contains(lower, "/knot/") ||
			strings.Contains(lower, "/zones/") {
			return true
		}
	}

	return false
}

// parseZoneFile scans a zone file for DNSKEY, DS, and RRSIG records
// and emits one Finding per algorithm instance found.
func (m *DNSSECModule) parseZoneFile(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "dnssec", sc.Err()) }()

	for sc.Scan() {
		line := sc.Text()
		// Strip inline comments.
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "$") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Find the record type keyword and its position.
		// Zone records: <name> [TTL] [class] <type> <rdata...>
		// The type keyword is the first non-numeric, non-class token
		// after the owner name.
		typeIdx := findRecordType(fields)
		if typeIdx < 0 {
			continue
		}

		rtype := strings.ToUpper(fields[typeIdx])
		rdata := fields[typeIdx+1:]

		switch rtype {
		case "DNSKEY":
			f := m.parseDNSKEY(path, rdata)
			appendNonNil(&out, f)
		case "DS":
			for _, f := range m.parseDS(path, rdata) {
				appendNonNil(&out, f)
			}
		case "RRSIG":
			f := m.parseRRSIG(path, rdata)
			appendNonNil(&out, f)
		}
	}
	return out
}

// findRecordType returns the index of the record type keyword in
// a zone file line's fields. The owner name is always fields[0].
// After that come optional TTL (numeric) and class (IN/CH/HS/ANY),
// then the type.
func findRecordType(fields []string) int {
	for i := 1; i < len(fields); i++ {
		tok := strings.ToUpper(fields[i])
		// Skip TTL (numeric)
		if _, err := strconv.Atoi(tok); err == nil {
			continue
		}
		// Skip DNS class
		if tok == "IN" || tok == "CH" || tok == "HS" || tok == "ANY" {
			continue
		}
		return i
	}
	return -1
}

// parseDNSKEY handles: <flags> <protocol> <algorithm> <pubkey...>
func (m *DNSSECModule) parseDNSKEY(path string, rdata []string) *model.Finding {
	// Need at least flags + protocol + algorithm
	if len(rdata) < 3 {
		return nil
	}
	flags, err := strconv.Atoi(rdata[0])
	if err != nil {
		return nil
	}
	algoNum := rdata[2]
	algoName := resolveAlgo(algoNum)

	function := "DNSKEY"
	switch flags {
	case 257:
		function = "DNSKEY (KSK)"
	case 256:
		function = "DNSKEY (ZSK)"
	}

	return m.dnssecFinding(path, function, algoName, fmt.Sprintf("DNSKEY record in %s", filepath.Base(path)))
}

// dsDigestMap maps DS digest type numbers to algorithm names.
var dsDigestMap = map[string]string{
	"1": "SHA-1",
	"2": "SHA-256",
	"3": "GOST-R-34.11-94",
	"4": "SHA-384",
}

// parseDS handles: <keytag> <algorithm> <digest-type> <digest...>
// Returns two findings: one for the signing algorithm and one for
// the digest algorithm, since both are PQC-relevant.
func (m *DNSSECModule) parseDS(path string, rdata []string) []*model.Finding {
	if len(rdata) < 3 {
		return nil
	}
	base := filepath.Base(path)
	algoNum := rdata[1]
	algoName := resolveAlgo(algoNum)

	// Emit a separate finding for the digest algorithm.
	digestType := rdata[2]
	digestName, ok := dsDigestMap[digestType]
	if !ok {
		digestName = fmt.Sprintf("DNSSEC-DS-digest-%s", digestType)
	}

	return []*model.Finding{
		m.dnssecFinding(path, "DNSSEC DS record", algoName, fmt.Sprintf("DS signing algorithm in %s", base)),
		m.dnssecFinding(path, "DNSSEC DS digest", digestName, fmt.Sprintf("DS digest type in %s", base)),
	}
}

// parseRRSIG handles: <type-covered> <algorithm> <labels> <orig-ttl> ...
func (m *DNSSECModule) parseRRSIG(path string, rdata []string) *model.Finding {
	if len(rdata) < 2 {
		return nil
	}
	typeCovered := strings.ToUpper(rdata[0])
	algoNum := rdata[1]
	algoName := resolveAlgo(algoNum)

	function := fmt.Sprintf("DNSSEC RRSIG (%s)", typeCovered)
	return m.dnssecFinding(path, function, algoName, fmt.Sprintf("RRSIG record in %s", filepath.Base(path)))
}

// resolveAlgo maps a DNSSEC algorithm number string to its canonical
// name via the shared dnssecAlgoMap. Falls back to "DNSSEC-algo-<n>".
func resolveAlgo(numStr string) string {
	// dnssecAlgoMap uses zero-padded 3-digit keys (e.g. "013").
	// Normalize the input.
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return "DNSSEC-algo-" + numStr
	}
	key := fmt.Sprintf("%03d", n)
	if name, ok := dnssecAlgoMap[key]; ok {
		return name
	}
	return fmt.Sprintf("DNSSEC-algo-%d", n)
}

// dnssecFinding produces one DNSSEC-tagged Finding.
func (m *DNSSECModule) dnssecFinding(path, function, algorithm, purpose string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algorithm,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	// Preserve the DNSSEC-specific algorithm name after classification
	// (ClassifyCryptoAsset may normalize to a broader family name).
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
		Confidence:  ConfidenceDefinitive,
		Module:      "dnssec",
		Timestamp:   time.Now(),
	}
}
