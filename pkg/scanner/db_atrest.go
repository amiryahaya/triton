package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
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
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// DBAtRestModule scans for database and disk encryption-at-rest
// key material and configuration:
//
//   - Oracle Wallet: ewallet.p12 (PKCS#12), cwallet.sso (3DES auto-login)
//   - MySQL keyring: keyring_file, keyring_encrypted_file plugin configs
//   - MSSQL: mssql.conf TLS/forced encryption directives
//   - PostgreSQL: pg_tde extension, ssl_* directives
//   - LUKS: /etc/crypttab entries, optional cryptsetup luksDump
//
// BitLocker and FileVault are Windows/macOS-specific and deferred
// to a follow-up (Linux-first approach per roadmap).
type DBAtRestModule struct {
	config      *scannerconfig.Config
	store       store.Store
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

// NewDBAtRestModule constructs a DBAtRestModule.
func NewDBAtRestModule(cfg *scannerconfig.Config) *DBAtRestModule {
	return &DBAtRestModule{config: cfg}
}

func (m *DBAtRestModule) Name() string                         { return "db_atrest" }
func (m *DBAtRestModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *DBAtRestModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *DBAtRestModule) SetStore(s store.Store)               { m.store = s }
func (m *DBAtRestModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func (m *DBAtRestModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// dbAtRestCmdRunner abstracts command execution for testability (luksDump).
var dbAtRestCmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// Scan walks the target tree and parses matching config/wallet files.
func (m *DBAtRestModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isDBAtRestFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			results := m.parseFile(ctx, reader, path)
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

// isDBAtRestFile matches database encryption and LUKS config files.
func isDBAtRestFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Oracle Wallet
	if base == "ewallet.p12" || base == "cwallet.sso" {
		return true
	}

	// MySQL keyring
	if strings.Contains(lower, "mysql") && (base == "keyring" || strings.HasPrefix(base, "keyring") ||
		strings.Contains(lower, "keyring")) {
		if base == "keyring" || strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, "-encrypted") {
			return true
		}
	}

	// Percona keyring config
	if strings.Contains(lower, "percona") && strings.HasSuffix(base, ".conf") && strings.Contains(lower, "keyring") {
		return true
	}

	// MSSQL config
	if base == "mssql.conf" {
		return true
	}

	// PostgreSQL config
	if base == "postgresql.conf" {
		return true
	}

	// LUKS crypttab
	if base == "crypttab" {
		return true
	}

	return false
}

// parseFile dispatches to the right sub-parser.
func (m *DBAtRestModule) parseFile(ctx context.Context, reader fsadapter.FileReader, path string) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Oracle Wallet — binary files, report presence only
	if base == "ewallet.p12" || base == "cwallet.sso" {
		return m.parseOracleWallet(path)
	}

	// LUKS crypttab
	if base == "crypttab" {
		data, err := reader.ReadFile(ctx, path)
		if err != nil {
			return nil
		}
		findings, devices := m.parseCrypttab(path, data)
		// For LUKS entries, try luksDump to get precise cipher + key size.
		// Requires cryptsetup and read access to the device (typically root).
		for i, f := range findings {
			if f.CryptoAsset.Algorithm == "LUKS" && i < len(devices) && devices[i] != "" {
				luksFindings := m.parseLuksDump(ctx, devices[i])
				findings = append(findings, luksFindings...)
			}
		}
		return findings
	}

	// Read config files
	data, err := reader.ReadFile(ctx, path)
	if err != nil {
		return nil
	}

	switch {
	case strings.Contains(lower, "mysql") || strings.Contains(lower, "percona"):
		return m.parseMySQLKeyringConfig(path, data)
	case base == "mssql.conf":
		return m.parseMSSQLConfig(path, data)
	case base == "postgresql.conf":
		return m.parsePostgreSQLConfig(path, data)
	}
	return nil
}

// --- Oracle Wallet ---

func (m *DBAtRestModule) parseOracleWallet(path string) []*model.Finding {
	base := filepath.Base(path)
	var function, algo string

	switch base {
	case "ewallet.p12":
		function = "Oracle Wallet (PKCS#12)"
		algo = "PKCS#12"
	case "cwallet.sso":
		function = "Oracle Wallet (SSO auto-login)"
		algo = "3DES" // Oracle SSO wallets use 3DES obfuscation
	default:
		return nil
	}

	return []*model.Finding{m.dbAtRestFinding(path, function, algo,
		fmt.Sprintf("Oracle Wallet at %s", path))}
}

// --- MySQL keyring ---

// mysqlKeyringPlugins maps plugin names to their encryption algorithms.
var mysqlKeyringPlugins = map[string]string{
	"keyring_encrypted_file.so": "AES-256",
	"keyring_encrypted_file":    "AES-256",
	"keyring_file.so":           "plaintext",
	"keyring_file":              "plaintext",
	"keyring_hashicorp":         "Vault-managed",
	"keyring_aws":               "AWS-KMS",
	"keyring_okv":               "Oracle-KMS",
}

func (m *DBAtRestModule) parseMySQLKeyringConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "mysql-keyring", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Look for early-plugin-load or plugin-load with keyring
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "keyring") {
			continue
		}

		// Extract plugin name from "early-plugin-load=keyring_encrypted_file.so" etc.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		if val == "" {
			continue
		}

		for plugin, algo := range mysqlKeyringPlugins {
			if strings.Contains(val, plugin) {
				out = append(out, m.dbAtRestFinding(path, "MySQL keyring plugin", algo,
					fmt.Sprintf("MySQL keyring %s in %s", plugin, base)))
				break
			}
		}
	}
	return out
}

// --- MSSQL ---

func (m *DBAtRestModule) parseMSSQLConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "mssql", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		if val == "" {
			continue
		}

		switch key {
		case "tlsprotocols":
			out = append(out, m.dbAtRestFinding(path, "MSSQL TLS protocol", "TLS-"+val,
				fmt.Sprintf("MSSQL tlsprotocols in %s", base)))
		case "forceencryption":
			if val == "1" || strings.EqualFold(val, "true") {
				out = append(out, m.dbAtRestFinding(path, "MSSQL forced encryption", "TLS",
					fmt.Sprintf("MSSQL forceencryption enabled in %s", base)))
			}
		}
	}
	return out
}

// --- PostgreSQL ---

func (m *DBAtRestModule) parsePostgreSQLConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "postgresql", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, "'\"")
		if val == "" {
			continue
		}

		switch key {
		case "shared_preload_libraries":
			if strings.Contains(val, "pg_tde") {
				out = append(out, m.dbAtRestFinding(path, "PostgreSQL TDE", "AES-256",
					fmt.Sprintf("pg_tde extension in %s", base)))
			}
		case "ssl_min_protocol_version":
			out = append(out, m.dbAtRestFinding(path, "PostgreSQL TLS protocol", val,
				fmt.Sprintf("PostgreSQL ssl_min_protocol_version in %s", base)))
		case "ssl_ciphers":
			out = append(out, m.dbAtRestFinding(path, "PostgreSQL TLS cipher list", val,
				fmt.Sprintf("PostgreSQL ssl_ciphers in %s", base)))
		}
	}
	return out
}

// --- LUKS / crypttab ---

// crypttabCipherMap normalizes common LUKS/dm-crypt cipher strings.
var crypttabCipherMap = map[string]string{
	"aes-xts-plain64":                "AES-XTS",
	"aes-xts-plain":                  "AES-XTS",
	"aes-cbc-essiv:sha256":           "AES-CBC",
	"aes-cbc-plain64":                "AES-CBC",
	"serpent-xts-plain64":            "Serpent-XTS",
	"twofish-xts-plain64":            "Twofish-XTS",
	"aes-xts-benbi":                  "AES-XTS",
	"chacha20-plain64":               "ChaCha20",
	"xchacha12,aes-adiantum-plain64": "Adiantum",
}

// parseCrypttab returns findings and a parallel slice of source device
// paths (fields[1] from each crypttab line) for luksDump enrichment.
func (m *DBAtRestModule) parseCrypttab(path string, data []byte) (findings []*model.Finding, devicePaths []string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "crypttab", sc.Err()) }()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		target := fields[0] // volume name

		// Options field (4th column) may contain cipher= and luks
		options := ""
		if len(fields) >= 4 {
			options = fields[len(fields)-1] // last field is options
		}

		// Parse cipher from options
		algo := ""
		for _, opt := range strings.Split(options, ",") {
			opt = strings.TrimSpace(opt)
			if strings.HasPrefix(opt, "cipher=") {
				cipher := strings.TrimPrefix(opt, "cipher=")
				if canonical, ok := crypttabCipherMap[strings.ToLower(cipher)]; ok {
					algo = canonical
				} else {
					algo = cipher
				}
			}
		}

		// If no explicit cipher, check for luks keyword
		if algo == "" && strings.Contains(options, "luks") {
			algo = "LUKS" // default LUKS uses AES-XTS, but report as LUKS
		}

		// Skip entries with no crypto relevance (e.g., plain swap with /dev/urandom
		// and no cipher specification — the kernel default is used)
		if algo == "" && !strings.Contains(options, "swap") {
			continue
		}
		if algo == "" {
			continue
		}

		findings = append(findings, m.dbAtRestFinding(path, "Disk encryption volume", algo,
			fmt.Sprintf("crypttab volume %s", target)))
		devicePaths = append(devicePaths, fields[1]) // source device (e.g. UUID=... or /dev/sda2)
	}
	return findings, devicePaths
}

// parseLuksDump runs `cryptsetup luksDump <device>` and extracts cipher info.
func (m *DBAtRestModule) parseLuksDump(ctx context.Context, device string) []*model.Finding {
	out, err := dbAtRestCmdRunner(ctx, "cryptsetup", "luksDump", device)
	if err != nil {
		log.Printf("db_atrest: cryptsetup luksDump %s failed: %v", device, err)
		return nil
	}

	var findings []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		// "Cipher:     aes-xts-plain64"
		if strings.HasPrefix(line, "Cipher:") {
			cipher := strings.TrimSpace(strings.TrimPrefix(line, "Cipher:"))
			algo := cipher
			if canonical, ok := crypttabCipherMap[strings.ToLower(cipher)]; ok {
				algo = canonical
			}

			// Look for key size on next lines
			keySize := 0
			if sc.Scan() {
				ksLine := strings.TrimSpace(sc.Text())
				if strings.HasPrefix(ksLine, "Cipher key:") {
					ksPart := strings.TrimSpace(strings.TrimPrefix(ksLine, "Cipher key:"))
					ksPart = strings.TrimSuffix(ksPart, " bits")
					if ks, parseErr := strconv.Atoi(strings.TrimSpace(ksPart)); parseErr == nil {
						keySize = ks
					}
				}
			}

			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  "LUKS volume encryption",
				Algorithm: algo,
				KeySize:   keySize,
				Purpose:   fmt.Sprintf("cryptsetup luksDump %s", device),
			}
			crypto.ClassifyCryptoAsset(asset)
			asset.Algorithm = algo

			findings = append(findings, &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: CategoryConfig,
				Source: model.FindingSource{
					Type:            "process",
					DetectionMethod: "cryptsetup-luksdump",
				},
				CryptoAsset: asset,
				Confidence:  ConfidenceDefinitive,
				Module:      "db_atrest",
				Timestamp:   time.Now(),
			})
		}
	}
	return findings
}

// --- finding builder ---

func (m *DBAtRestModule) dbAtRestFinding(path, function, algorithm, purpose string) *model.Finding {
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
		Module:      "db_atrest",
		Timestamp:   time.Now(),
	}
}
