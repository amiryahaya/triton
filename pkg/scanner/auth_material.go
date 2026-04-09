package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
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

// AuthMaterialModule discovers miscellaneous authentication material
// scattered around a typical Linux host: Kerberos keytabs, GPG
// keyrings, 802.1X supplicant configs, Tor hidden service keys,
// DNSSEC zone-signing keys, and systemd encrypted credential
// directives. Everything with a well-defined file name or binary
// magic that nobody else is bothering to scan.
//
// Every sub-parser reports ONLY metadata — algorithm name, key
// size where known, owner/subject where the format exposes it.
// Actual key material is never read into a finding's Purpose or
// Source fields. For binary formats (keytab), we parse just enough
// of the header to extract the enctype and principal name, then
// stop.
type AuthMaterialModule struct {
	config      *config.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewAuthMaterialModule wires an AuthMaterialModule with the engine config.
func NewAuthMaterialModule(cfg *config.Config) *AuthMaterialModule {
	return &AuthMaterialModule{config: cfg}
}

func (m *AuthMaterialModule) Name() string                         { return "auth_material" }
func (m *AuthMaterialModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *AuthMaterialModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *AuthMaterialModule) SetStore(s store.Store)               { m.store = s }

func (m *AuthMaterialModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and dispatches each matching file to
// the right sub-parser.
func (m *AuthMaterialModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isAuthMaterialFile,
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

// isAuthMaterialFile decides whether a file is in scope. Uses
// purely path-based matching so the walker can skip expensive
// content reads for files that don't match.
func isAuthMaterialFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Kerberos keytabs — either the canonical /etc/krb5.keytab or
	// per-service keytabs (httpd, nfs, ldap) which are commonly
	// named <service>.keytab.
	if strings.HasSuffix(base, ".keytab") {
		return true
	}

	// Tor v3 hidden service keys and hostnames. The key file name
	// is fixed; the hostname file lives alongside it.
	if base == "hs_ed25519_secret_key" || base == "hs_ed25519_public_key" {
		return true
	}
	if base == "hostname" && strings.Contains(lower, "hidden_service") {
		return true
	}

	// 802.1X supplicant configurations.
	if base == "wpa_supplicant.conf" {
		return true
	}
	// NetworkManager per-connection profiles. The file extension
	// is the ONLY reliable marker.
	if strings.HasSuffix(base, ".nmconnection") {
		return true
	}

	// DNSSEC key files — `K<name>.+<algo>+<tag>.private` or `.key`.
	// Simpler: match the K* prefix + .private / .key suffix.
	if strings.HasPrefix(base, "K") && (strings.HasSuffix(base, ".private") || strings.HasSuffix(base, ".key")) {
		// Discriminate from random K-prefixed files by requiring
		// the `+<algo>+<tag>` infix.
		if strings.Count(base, "+") >= 2 {
			return true
		}
	}

	// systemd unit files (service, socket, timer, target) that may
	// contain encrypted credential directives.
	if strings.Contains(lower, "/systemd/") && (strings.HasSuffix(base, ".service") ||
		strings.HasSuffix(base, ".socket") || strings.HasSuffix(base, ".timer") ||
		strings.HasSuffix(base, ".target")) {
		return true
	}

	return false
}

// parseFile dispatches to the right sub-parser. Some sub-parsers
// need file contents (keytab, wpa_supplicant, systemd); others
// work purely from the filename (DNSSEC keys) or just check for
// sibling files (Tor). Each path is individually fault-tolerant.
func (m *AuthMaterialModule) parseFile(path string) []*model.Finding {
	base := filepath.Base(path)

	// DNSSEC: filename alone tells us the algorithm.
	if strings.HasPrefix(base, "K") && strings.Count(base, "+") >= 2 {
		return m.parseDNSSECKey(base)
	}

	// Tor hidden service: just the presence is the signal.
	if base == "hs_ed25519_secret_key" || base == "hs_ed25519_public_key" || (base == "hostname" && strings.Contains(path, "hidden_service")) {
		return m.parseTorHiddenServiceKey(path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	switch {
	case strings.HasSuffix(base, ".keytab"):
		return m.parseKeytab(path, data)
	case base == "wpa_supplicant.conf":
		return m.parseWPASupplicant(path, data)
	case strings.HasSuffix(base, ".nmconnection"):
		return m.parseNMConnection(path, data)
	case strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".socket") ||
		strings.HasSuffix(base, ".timer") || strings.HasSuffix(base, ".target"):
		return m.parseSystemdUnit(path, data)
	}
	return nil
}

// --- Kerberos keytab binary parser ---

// keytabEnctype maps Kerberos enctype codes (RFC 3961) to a
// canonical algorithm name. Codes not in this map are emitted
// as raw numeric identifiers so nothing is silently dropped.
var keytabEnctype = map[uint16]string{
	1:  "DES-CBC-CRC",
	2:  "DES-CBC-MD4",
	3:  "DES-CBC-MD5",
	5:  "DES3-CBC-MD5",
	7:  "DES3-CBC-SHA1-KD",
	16: "DES3-CBC-SHA1",
	17: "AES-128-CTS-HMAC-SHA1-96",
	18: "AES-256-CTS-HMAC-SHA1-96",
	19: "AES-128-CTS-HMAC-SHA256-128",
	20: "AES-256-CTS-HMAC-SHA384-192",
	23: "RC4-HMAC",
	24: "RC4-HMAC-EXP",
}

// parseKeytab walks an MIT krb5 keytab v2 blob and emits one
// finding per key entry. Format reference:
// https://web.mit.edu/kerberos/krb5-1.12/doc/formats/keytab_file_format.html
//
// The parser is deliberately conservative — any byte past the
// declared entry length is skipped rather than re-interpreted,
// so a corrupted file stops parsing cleanly without panicking.
//
// Safety notes from sprint review (B1):
//
//   - entry length is read as uint32 and compared against the
//     high bit for the "deleted entry" encoding rather than
//     cast to int32 (which overflows on MinInt32 and is
//     architecture-dependent on 32-bit Go).
//   - the magnitude of a deleted-entry skip is computed in
//     uint32 arithmetic (two's-complement negation) before
//     being safely widened to int — this cannot overflow on
//     any GOARCH and cannot produce a negative int.
//   - version byte 1 is explicitly checked for 0x01 or 0x02;
//     any other value rejects the file.
func (m *AuthMaterialModule) parseKeytab(path string, data []byte) []*model.Finding {
	if len(data) < 2 {
		return nil
	}
	// Version byte 1 should be 0x05; byte 2 is 0x02 for v2 (big-
	// endian rest-of-file) or 0x01 for v1 (little-endian).
	if data[0] != 0x05 {
		return nil
	}
	order := binary.ByteOrder(binary.BigEndian)
	switch data[1] {
	case 0x02:
		// big-endian (v2)
	case 0x01:
		order = binary.LittleEndian
	default:
		// Unknown version byte — reject rather than guess.
		return nil
	}

	var out []*model.Finding
	pos := 2
	for pos+4 <= len(data) {
		rawLen := order.Uint32(data[pos : pos+4])
		pos += 4
		if rawLen == 0 {
			// Explicit terminator (or corrupt zero-length entry);
			// stop walking either way.
			break
		}
		// RFC: the high bit indicates a deleted-entry slot whose
		// body should be skipped. Compute the magnitude in uint32
		// to avoid the int32(-entryLen) overflow that reviewer
		// B1 flagged as an infinite-loop vector on 32-bit Go.
		if rawLen&0x80000000 != 0 {
			skip := ^rawLen + 1 // two's-complement magnitude (uint32)
			if skip == 0 || uint64(pos)+uint64(skip) > uint64(len(data)) {
				break
			}
			pos += int(skip)
			continue
		}
		entryLen := rawLen // safe: high bit is 0, fits in int on every arch
		if uint64(pos)+uint64(entryLen) > uint64(len(data)) {
			break
		}
		entry := data[pos : pos+int(entryLen)]
		pos += int(entryLen)

		principal, enctype, ok := parseKeytabEntry(entry, order)
		if !ok {
			continue
		}
		algo, known := keytabEnctype[enctype]
		if !known {
			algo = fmt.Sprintf("Kerberos-enctype-%d", enctype)
		}
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "Kerberos keytab key",
			Algorithm: algo,
			Purpose:   "Kerberos principal " + principal,
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = algo // restore; see password_hash.go
		out = append(out, authMatFinding(path, asset))
	}
	return out
}

// parseKeytabEntry walks a single keytab entry body and returns
// the principal string ("component/component@REALM") and the
// enctype code. Returns ok=false on any truncation.
func parseKeytabEntry(entry []byte, order binary.ByteOrder) (principal string, enctype uint16, ok bool) {
	p := 0
	readU16 := func() (uint16, bool) {
		if p+2 > len(entry) {
			return 0, false
		}
		v := order.Uint16(entry[p : p+2])
		p += 2
		return v, true
	}
	readString := func() (string, bool) {
		n, ok := readU16()
		if !ok {
			return "", false
		}
		if p+int(n) > len(entry) {
			return "", false
		}
		s := string(entry[p : p+int(n)])
		p += int(n)
		return s, true
	}

	numComponents, ok2 := readU16()
	if !ok2 {
		return "", 0, false
	}
	realm, ok2 := readString()
	if !ok2 {
		return "", 0, false
	}
	components := make([]string, 0, numComponents)
	for i := uint16(0); i < numComponents; i++ {
		c, ok2 := readString()
		if !ok2 {
			return "", 0, false
		}
		components = append(components, c)
	}
	// name_type (u32) + timestamp (u32) + vno8 (u8)
	if p+4+4+1 > len(entry) {
		return "", 0, false
	}
	p += 4 + 4 + 1

	// enctype (u16)
	ec, ok2 := readU16()
	if !ok2 {
		return "", 0, false
	}

	principal = strings.Join(components, "/") + "@" + realm
	return principal, ec, true
}

// --- GPG keyring (colon-separated parser) ---

// gpgPubkeyAlgoMap maps the GPG numeric pubkey algorithm ID (as
// emitted in the colon-separated `gpg --with-colons` output)
// to a canonical name. RFC 4880 section 9.1 is the authoritative
// list; we cover every ID GPG has shipped.
var gpgPubkeyAlgoMap = map[string]string{
	"1":  "RSA",
	"2":  "RSA-Encrypt",
	"3":  "RSA-Sign",
	"16": "ElGamal",
	"17": "DSA",
	"18": "ECDH",
	"19": "ECDSA",
	"20": "ElGamal",
	"22": "EdDSA (Ed25519)",
}

// parseGPGList parses the colon-separated output of
// `gpg --list-keys --with-colons`. Each `pub:` record is one key
// with fields (RFC: https://github.com/gpg/gnupg/blob/master/doc/DETAILS):
//
//	pub : type
//	[1] : validity
//	[2] : key length (bits)
//	[3] : pubkey algo
//	[4] : keyid
//	[5] : creation date
//	...
func (m *AuthMaterialModule) parseGPGList(data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "pub:") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		keyBits := fields[2]
		pkAlgoID := fields[3]
		keyID := fields[4]
		algoName, known := gpgPubkeyAlgoMap[pkAlgoID]
		if !known {
			algoName = "GPG-pkalgo-" + pkAlgoID
		}
		size := 0
		if keyBits != "" {
			// Atoi-free parse to keep imports flat; GPG field is
			// always digits when present.
			n := 0
			valid := true
			for _, c := range keyBits {
				if c < '0' || c > '9' {
					valid = false
					break
				}
				n = n*10 + int(c-'0')
			}
			if valid {
				size = n
			}
		}
		display := algoName
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "GPG public key",
			Algorithm: display,
			KeySize:   size,
			Purpose:   "GPG keyring entry " + keyID,
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = display // restore
		out = append(out, authMatFinding("gpg:keyring", asset))
	}
	return out
}

// --- 802.1X supplicant ---

// wpaKeyMgmtMap normalizes key_mgmt values to findings. Includes
// the open/weak cases because that's exactly what operators
// want to see flagged.
var wpaKeyMgmtMap = map[string]string{
	"WPA-EAP":         "WPA-EAP",
	"WPA-EAP-SHA256":  "WPA-EAP-SHA256",
	"WPA-EAP-SUITE-B": "WPA-EAP-SUITE-B (CNSA)",
	"WPA-PSK":         "WPA-PSK",
	"WPA-PSK-SHA256":  "WPA-PSK-SHA256",
	"FT-EAP":          "WPA2-FT-EAP",
	"FT-PSK":          "WPA2-FT-PSK",
	"SAE":             "WPA3-SAE",
	"NONE":            "OPEN (no authentication)",
}

// parseWPASupplicant walks a wpa_supplicant.conf looking at every
// network={...} block's key_mgmt value. If key_mgmt is WPA-EAP
// and eap=TLS/TTLS/PEAP is set, the finding reports the EAP method
// specifically (EAP-TLS, EAP-TTLS, EAP-PEAP) so CNSA-compliant
// deployments and legacy PEAP leaks are both visible.
func (m *AuthMaterialModule) parseWPASupplicant(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)

	// Simple state machine: track whether we're inside a
	// network={...} block and accumulate its key_mgmt + eap.
	inBlock := false
	keyMgmt := ""
	eap := ""
	ssid := ""
	emit := func() {
		if keyMgmt == "" && eap == "" {
			return
		}
		display := "Unknown"
		switch {
		case strings.EqualFold(keyMgmt, "WPA-EAP") && eap != "":
			display = "EAP-" + strings.ToUpper(eap)
		case keyMgmt != "":
			if mapped, ok := wpaKeyMgmtMap[strings.ToUpper(keyMgmt)]; ok {
				display = mapped
			} else {
				display = keyMgmt
			}
		}
		purpose := "wpa_supplicant network"
		if ssid != "" {
			purpose = "wpa_supplicant ssid=" + ssid
		}
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "802.1X / Wi-Fi authentication",
			Algorithm: display,
			Purpose:   purpose,
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = display
		out = append(out, authMatFinding(path, asset))
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "network=") {
			inBlock = true
			keyMgmt, eap, ssid = "", "", ""
			continue
		}
		if !inBlock {
			continue
		}
		if line == "}" {
			emit()
			inBlock = false
			continue
		}
		// Strip value quotes.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:eq]))
		v := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
		switch k {
		case "key_mgmt":
			keyMgmt = v
		case "eap":
			eap = v
		case "ssid":
			ssid = v
		}
	}
	// If the file is missing a trailing `}` for some reason, emit
	// what we collected in the last block.
	if inBlock {
		emit()
	}
	return out
}

// parseNMConnection handles NetworkManager's per-connection INI
// files. Unlike wpa_supplicant.conf it uses INI sections; we look
// in [wifi-security] for `key-mgmt` and in [802-1x] for `eap`.
func (m *AuthMaterialModule) parseNMConnection(path string, data []byte) []*model.Finding {
	// Preallocate for the single finding we typically emit —
	// one per connection file.
	out := make([]*model.Finding, 0, 1)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)

	section := ""
	keyMgmt := ""
	eap := ""
	ssid := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:eq]))
		v := strings.TrimSpace(line[eq+1:])
		switch section {
		case "wifi":
			if k == "ssid" {
				ssid = v
			}
		case "wifi-security":
			if k == "key-mgmt" {
				keyMgmt = v
			}
		case "802-1x":
			if k == "eap" {
				eap = v
			}
		}
	}
	if keyMgmt == "" && eap == "" {
		return nil
	}
	display := "Unknown"
	switch {
	case strings.EqualFold(keyMgmt, "wpa-eap") && eap != "":
		display = "EAP-" + strings.ToUpper(eap)
	case keyMgmt != "":
		if mapped, ok := wpaKeyMgmtMap[strings.ToUpper(keyMgmt)]; ok {
			display = mapped
		} else {
			display = keyMgmt
		}
	}
	purpose := "NetworkManager connection"
	if ssid != "" {
		purpose = "NetworkManager ssid=" + ssid
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "802.1X / Wi-Fi authentication",
		Algorithm: display,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = display
	out = append(out, authMatFinding(path, asset))
	return out
}

// --- Tor v3 hidden service ---

// parseTorHiddenServiceKey emits a finding for a Tor v3 hidden
// service signing key. Tor v3 is hardcoded to Ed25519 so we don't
// need to inspect the file contents — the filename alone tells
// us everything.
func (m *AuthMaterialModule) parseTorHiddenServiceKey(path string) []*model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Tor hidden service identity key",
		Algorithm: "Ed25519",
		Purpose:   "Tor v3 onion service key (" + filepath.Base(path) + ")",
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = "Ed25519"
	return []*model.Finding{authMatFinding(path, asset)}
}

// --- DNSSEC ---

// dnssecAlgoMap maps DNSSEC algorithm numbers (IANA DNSKEY
// registry) to canonical algorithm names. Keeps the deprecated
// entries (1, 3, 5, 6, 7) intact so operators running old
// signers see them flagged.
var dnssecAlgoMap = map[string]string{
	"001": "RSA-MD5",  // deprecated
	"003": "DSA-SHA1", // deprecated
	"005": "RSA-SHA1", // deprecated
	"006": "DSA-NSEC3-SHA1",
	"007": "RSA-SHA1-NSEC3",
	"008": "RSA-SHA-256",
	"010": "RSA-SHA-512",
	"012": "ECC-GOST",
	"013": "ECDSA-P256-SHA-256",
	"014": "ECDSA-P384-SHA-384",
	"015": "Ed25519",
	"016": "Ed448",
}

// dnssecKeyFileRE extracts the algorithm number from a BIND-style
// key filename: `K<zone>.+<algo>+<tag>.{private,key}`.
var dnssecKeyFileRE = regexp.MustCompile(`^K.+\.\+(\d{3})\+\d+\.(?:private|key)$`)

func (m *AuthMaterialModule) parseDNSSECKey(filename string) []*model.Finding {
	match := dnssecKeyFileRE.FindStringSubmatch(filename)
	if match == nil {
		return nil
	}
	algoNum := match[1]
	algoName, ok := dnssecAlgoMap[algoNum]
	if !ok {
		algoName = "DNSSEC-algo-" + algoNum
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "DNSSEC zone signing key",
		Algorithm: algoName,
		Purpose:   "DNSSEC key file " + filename,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algoName
	return []*model.Finding{authMatFinding(filename, asset)}
}

// --- systemd ---

// systemdCredRE matches LoadCredentialEncrypted= and
// SetCredentialEncrypted= directives in systemd unit files. Both
// directives drive systemd's encrypted credential store, which
// uses AES-256-GCM under the hood.
var systemdCredRE = regexp.MustCompile(`(?i)^\s*(LoadCredentialEncrypted|SetCredentialEncrypted)=([^\s#]+)`)

// parseSystemdUnit walks a systemd unit file looking for encrypted
// credential directives. Each `LoadCredentialEncrypted=NAME:PATH`
// or `SetCredentialEncrypted=NAME:BLOB` line produces one finding.
func (m *AuthMaterialModule) parseSystemdUnit(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		match := systemdCredRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		directive := match[1]
		payload := match[2]
		// Payload is `NAME:VALUE_OR_PATH`; we only surface NAME
		// so no secret material gets into the report.
		name := payload
		if i := strings.IndexByte(payload, ':'); i >= 0 {
			name = payload[:i]
		}
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "systemd encrypted credential",
			Algorithm: "AES-256-GCM",
			Purpose:   directive + " " + name,
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = "AES-256-GCM"
		out = append(out, authMatFinding(path, asset))
	}
	return out
}

// --- finding builder ---

func authMatFinding(path string, asset *model.CryptoAsset) *model.Finding {
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
		Module:      "auth_material",
		Timestamp:   time.Now(),
	}
}
