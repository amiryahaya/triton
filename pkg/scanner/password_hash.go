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

// PasswordHashModule inventories every password-hashing configuration
// a Linux/BSD host exposes:
//
//   - /etc/shadow — per-user password hashes, parsed by algorithm prefix
//   - /etc/gshadow — group password hashes (same format)
//   - /etc/pam.d/* — PAM stack config that picks the hash algorithm
//   - pg_hba.conf — PostgreSQL client authentication methods
//
// The module surfaces the per-user active algorithm (so operators see
// exactly who still has MD5-crypt or DES-crypt passwords), the PAM
// policy that drives future password changes, and the PostgreSQL
// SCRAM-vs-MD5 auth posture. All three produce findings that feed
// the PQC classifier and compliance scoring.
//
// Security: the hash VALUE itself is never stored in a finding —
// only the algorithm identifier (e.g. `$6$`) and whatever extra
// metadata the source file exposes (username, database name). No
// salt, no digest, no way to recover the plaintext.
type PasswordHashModule struct {
	config      *config.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewPasswordHashModule wires a PasswordHashModule with the engine config.
func NewPasswordHashModule(cfg *config.Config) *PasswordHashModule {
	return &PasswordHashModule{config: cfg}
}

func (m *PasswordHashModule) Name() string                         { return "password_hash" }
func (m *PasswordHashModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *PasswordHashModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *PasswordHashModule) SetStore(s store.Store)               { m.store = s }

func (m *PasswordHashModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and dispatches each matching file to
// the right parser. Individual file-read errors are swallowed
// (shadow requires root; operators running as a non-root agent
// should still get PAM and pg_hba findings).
func (m *PasswordHashModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isPasswordHashFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, f := range m.parseFile(path, data) {
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

// isPasswordHashFile decides whether a file is in scope.
func isPasswordHashFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	if base == "shadow" && strings.Contains(lower, "/etc/") {
		return true
	}
	if base == "gshadow" && strings.Contains(lower, "/etc/") {
		return true
	}
	if strings.Contains(lower, "/pam.d/") {
		// PAM stack files have no extension — accept any filename
		// under pam.d/.
		return true
	}
	if base == "pg_hba.conf" {
		return true
	}
	return false
}

// parseFile dispatches to the right per-format parser based on the
// path. Returns a slice of findings (possibly empty, never nil
// dereference on iteration).
func (m *PasswordHashModule) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	switch {
	case base == "shadow" || base == "gshadow":
		return m.parseShadow(path, data)
	case strings.Contains(path, "/pam.d/"):
		return m.parsePAM(path, data)
	case base == "pg_hba.conf":
		return m.parsePgHba(path, data)
	}
	return nil
}

// --- /etc/shadow ---

// shadowHashPrefixMap maps the `$<id>$` prefix in an /etc/shadow
// hash to a canonical algorithm name. Covers every scheme that
// has appeared in mainstream libc implementations:
//
//   $1$   — MD5-crypt (DEPRECATED — collision-weak, fast GPU attacks)
//   $2a$  — bcrypt (original variant)
//   $2b$  — bcrypt (bug-fixed 2014)
//   $2y$  — bcrypt (PHP passlib variant)
//   $5$   — SHA-256-crypt (TRANSITIONAL)
//   $6$   — SHA-512-crypt (TRANSITIONAL but widely used)
//   $7$   — scrypt
//   $y$   — yescrypt (libxcrypt, default on Debian 12+)
//   $gy$  — gost-yescrypt
//   $argon2i$ / $argon2d$ / $argon2id$ — Argon2 (SAFE)
//
// A plain 13-char hash with no prefix is DES-crypt, which is
// completely broken and MUST surface as a finding.
var shadowHashPrefixMap = map[string]string{
	"1":        "MD5-crypt",
	"2a":       "bcrypt",
	"2b":       "bcrypt",
	"2y":       "bcrypt",
	"5":        "SHA-256-crypt",
	"6":        "SHA-512-crypt",
	"7":        "scrypt",
	"y":        "yescrypt",
	"gy":       "gost-yescrypt",
	"argon2i":  "Argon2i",
	"argon2d":  "Argon2d",
	"argon2id": "Argon2id",
}

// parseShadow walks an /etc/shadow file and emits one finding per
// active user. Locked accounts (* / ! / !! / empty) are skipped
// because they have no password to classify.
func (m *PasswordHashModule) parseShadow(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 64*1024) // shadow lines are short
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: user:hash:lastchg:min:max:warn:inactive:expire:flag
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		user := parts[0]
		hash := parts[1]

		// Skip locked / disabled / empty accounts.
		if hash == "" || hash == "*" || hash == "!" || hash == "!!" {
			continue
		}
		// Explicitly-locked bcrypt with a `!` prefix on the whole
		// field (not just `!`) stays active to its LOCAL PAM but
		// cannot be authenticated against — still a locked account.
		if strings.HasPrefix(hash, "!") {
			continue
		}

		algo := classifyShadowHash(hash)
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "Password hash",
			Algorithm: algo,
			Purpose:   "/etc/shadow: user '" + user + "'",
		}
		// Run the classifier for PQCStatus / MigrationPriority,
		// then restore our display name because the registry's
		// substring matcher rewrites "yescrypt" -> "scrypt",
		// "bcrypt" -> "Bcrypt" (capitalized), etc. We want the
		// on-disk name in the report, not the registry's canonical.
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = algo
		out = append(out, pwdHashFinding(path, asset))
	}
	logScannerErr(path, "shadow", scanner.Err())
	return out
}

// classifyShadowHash returns the canonical algorithm name for a
// shadow-style hash field. Unknown prefixes fall back to
// "Unknown-crypt" so the finding surfaces but isn't claimed as
// classified.
func classifyShadowHash(hash string) string {
	// Argon2: $argon2id$... — the ID is the whole prefix before
	// the version segment.
	if strings.HasPrefix(hash, "$") {
		// Split on $ to find the identifier token.
		parts := strings.SplitN(hash, "$", 4)
		if len(parts) >= 2 {
			id := parts[1]
			if mapped, ok := shadowHashPrefixMap[id]; ok {
				return mapped
			}
		}
		return "Unknown-crypt"
	}
	// No leading $ means legacy DES-crypt (13 chars of
	// base64-ish data) or bigcrypt — both fundamentally broken.
	return "DES-crypt"
}

// --- PAM config ---

// parsePAM walks a PAM stack file. We only care about the
// `password` type lines that reference pam_unix or pam_pwquality
// and declare the hashing algorithm (md5, sha256, sha512, bigcrypt,
// blowfish, yescrypt, etc.). The value appears as a space-separated
// option on the module line.
func (m *PasswordHashModule) parsePAM(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		// Only lines of type `password` configure hashing.
		if !strings.HasPrefix(lower, "password") {
			continue
		}
		// Look for algorithm keywords in the options segment.
		algo := pamHashAlgo(lower)
		if algo == "" {
			continue
		}
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "PAM password hashing policy",
			Algorithm: algo,
			Purpose:   "PAM module configures password hashing: " + truncate(line, 80),
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = algo // restore — see parseShadow comment
		out = append(out, pwdHashFinding(path, asset))
	}
	logScannerErr(path, "pam", scanner.Err())
	return out
}

// pamHashAlgo extracts a hash algorithm token from a PAM
// `password` line. The tokens are case-insensitive by convention
// (libpam lowercases options) so the caller should pass a
// pre-lowered string.
func pamHashAlgo(line string) string {
	// Tokens are space-separated; check the line for any of the
	// known hashing option keywords.
	tokens := strings.Fields(line)
	for _, t := range tokens {
		switch t {
		case "md5":
			return "MD5-crypt"
		case "bigcrypt":
			return "DES-crypt"
		case "sha256":
			return "SHA-256-crypt"
		case "sha512":
			return "SHA-512-crypt"
		case "blowfish":
			return "bcrypt"
		case "yescrypt":
			return "yescrypt"
		}
	}
	return ""
}

// --- pg_hba.conf ---

// pgAuthMethodMap maps PostgreSQL authentication methods in
// pg_hba.conf to their cryptographic character. `trust` and
// `password` are particularly bad and deserve loud findings.
var pgAuthMethodMap = map[string]string{
	"trust":         "pg-trust (NO authentication)",
	"password":      "pg-password (plaintext over wire)",
	"md5":           "pg-md5 (MD5 challenge-response)",
	"scram-sha-256": "pg-scram-sha-256",
	"peer":          "pg-peer (OS uid)",
	"ident":         "pg-ident (OS uid)",
	"gss":           "pg-gssapi",
	"sspi":          "pg-sspi",
	"krb5":          "pg-krb5",
	"ldap":          "pg-ldap",
	"pam":           "pg-pam",
	"cert":          "pg-cert (TLS client cert)",
	"radius":        "pg-radius",
}

// parsePgHba walks pg_hba.conf and emits one finding per non-
// comment rule. The auth method column is the last non-option
// field before the key=value options; we split on whitespace and
// inspect field [len-1] (modulo the option suffix).
func (m *PasswordHashModule) parsePgHba(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// Minimum rule: TYPE DATABASE USER [ADDRESS] METHOD.
		// For local entries the ADDRESS column is absent so the
		// minimum is 4 fields; for host entries it's 5.
		if len(fields) < 4 {
			continue
		}
		typ := strings.ToLower(fields[0])
		if typ != "local" && typ != "host" && typ != "hostssl" && typ != "hostnossl" && typ != "hostgssenc" && typ != "hostnogssenc" {
			continue
		}
		// Find the method: scan fields right-to-left until we hit
		// one that isn't a key=value option. The first such field
		// is the method; everything after is method-specific
		// options.
		method := ""
		for i := len(fields) - 1; i >= 1; i-- {
			if !strings.Contains(fields[i], "=") {
				method = strings.ToLower(fields[i])
				break
			}
		}
		if method == "" {
			continue
		}
		display, known := pgAuthMethodMap[method]
		if !known {
			display = "pg-" + method
		}
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "PostgreSQL client authentication",
			Algorithm: display,
			Purpose:   "pg_hba.conf rule: " + truncate(line, 80),
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = display // restore — see parseShadow comment
		out = append(out, pwdHashFinding(path, asset))
	}
	logScannerErr(path, "pg_hba", scanner.Err())
	return out
}

// --- finding builder ---

// pwdHashFinding wraps a CryptoAsset in the standard finding
// envelope. Confidence is High (0.90) because every finding
// is a direct parse of operator-authored config, not a heuristic.
func pwdHashFinding(path string, asset *model.CryptoAsset) *model.Finding {
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
		Module:      "password_hash",
		Timestamp:   time.Now(),
	}
}
