package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// DepsEcosystemsModule extends Triton's Go-specific dependency
// reachability scanner (`deps`) to the three other ecosystems
// every enterprise application touches: Python, Node/JS, Java.
//
// Unlike `deps.go` which walks Go's AST to classify crypto calls
// as direct/transitive/unreachable, this module does LOCKFILE +
// MANIFEST parsing — extracting the declared dependencies and
// matching them against a curated per-ecosystem allowlist of
// crypto library names. Reachability beyond "declared" requires
// language-specific AST walking (Python's `ast` module, Node's
// `acorn`, Java's `javaparser`) that belongs in its own sprint.
//
// The tradeoff: we get crypto-library inventory across every
// enterprise stack for ~600 LOC instead of ~6k. For customers
// doing PQC migration planning, knowing "app X uses
// org.bouncycastle, app Y uses crypto-js" is the first question;
// the "does it actually reach a weak primitive at runtime" follow-
// up comes later.
type DepsEcosystemsModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewDepsEcosystemsModule wires a DepsEcosystemsModule with the
// engine config.
func NewDepsEcosystemsModule(cfg *scannerconfig.Config) *DepsEcosystemsModule {
	return &DepsEcosystemsModule{config: cfg}
}

func (m *DepsEcosystemsModule) Name() string                         { return "deps_ecosystems" }
func (m *DepsEcosystemsModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *DepsEcosystemsModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *DepsEcosystemsModule) SetStore(s store.Store)               { m.store = s }

func (m *DepsEcosystemsModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and dispatches every matching
// lockfile / manifest to the right per-ecosystem parser.
func (m *DepsEcosystemsModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isDepsEcosystemFile,
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

// isDepsEcosystemFile returns true for any lockfile/manifest we
// know how to parse. Path-based (no content sniff).
func isDepsEcosystemFile(path string) bool {
	base := filepath.Base(path)
	switch base {
	// Python
	case "requirements.txt", "pyproject.toml", "Pipfile.lock", "poetry.lock":
		return true
	// Node
	case "package.json", "package-lock.json", "yarn.lock":
		return true
	// Java
	case "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile":
		return true
	}
	return false
}

// parseFile dispatches on filename.
func (m *DepsEcosystemsModule) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	switch base {
	case "requirements.txt":
		return m.parsePythonRequirements(path, data)
	case "pyproject.toml":
		return m.parsePyProjectToml(path, data)
	case "Pipfile.lock", "poetry.lock":
		// Same shape as pyproject for our purposes — we only care
		// about package names and don't walk the lock pins.
		return m.parsePyProjectToml(path, data)
	case "package.json":
		return m.parseNodePackageJSON(path, data)
	case "package-lock.json", "yarn.lock":
		return m.parseNodePackageJSON(path, data)
	case "pom.xml":
		return m.parseJavaPomXML(path, data)
	case "build.gradle", "build.gradle.kts", "gradle.lockfile":
		return m.parseJavaBuildGradle(path, data)
	}
	return nil
}

// --- Python ---

// pythonCryptoPkgs is the allowlist of Python package names that
// indicate crypto usage. Lowercased; lookup is case-insensitive
// because PEP 503 normalizes package names to lowercase.
//
// Comments mark the deprecated/dangerous ones that should always
// surface as findings regardless of compliance policy.
var pythonCryptoPkgs = map[string]string{
	"cryptography": "Python cryptography library (modern, recommended)",
	"pynacl":       "Python NaCl bindings (modern)",
	"pyca":         "Python Cryptographic Authority",
	"bcrypt":       "bcrypt password hashing",
	"passlib":      "Password hashing library (wraps multiple backends)",
	"pyjwt":        "JSON Web Token library",
	"python-jose":  "JOSE (JWT/JWS/JWE) implementation",
	"authlib":      "OAuth/JWT authentication library",
	"certifi":      "Mozilla CA bundle",
	"paramiko":     "SSH2 protocol implementation",
	"fabric":       "Remote execution over SSH (wraps paramiko)",
	"python-gnupg": "GPG keyring wrapper",
	"scrypt":       "scrypt KDF binding",
	"argon2-cffi":  "Argon2 binding",
	"hashids":      "Hash-based ID encoder (NOT cryptographic)",
	"itsdangerous": "Flask signed token library",
	// Deprecated / broken — flag loudly.
	"pycrypto": "DEPRECATED pycrypto (unmaintained since 2013, known CVEs)",
	"m2crypto": "DEPRECATED m2crypto (unmaintained OpenSSL wrapper)",
	"crypto":   "Ambiguous 'crypto' package — often the abandoned PyPI squatter",
}

// pythonReqLineRE captures a package name from a requirements.txt
// line. Handles: `name`, `name==version`, `name>=version`,
// `name[extra]==version`, `name @ git+https://...`. The regex
// grabs the leading identifier only.
var pythonReqLineRE = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)`)

func (m *DepsEcosystemsModule) parsePythonRequirements(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			// Skip blank lines, comments, and pip options (-e, -r, -i, --extra-index-url).
			continue
		}
		match := pythonReqLineRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pkg := strings.ToLower(match[1])
		if f := m.matchPythonPkg(path, pkg); f != nil {
			out = append(out, f)
		}
	}
	logScannerErr(path, "python-requirements", scanner.Err())
	return out
}

// pyProjectDepRE finds package references inside pyproject.toml or
// poetry.lock. We don't TOML-parse — the format is verbose and a
// regex is sufficient for extracting names from lines like:
//
//	"cryptography>=41.0.0",
//	"pyjwt[crypto]>=2.0",
//	cryptography = "^41.0"
//	name = "pyjwt"
//
// The quoted-form match captures only the leading identifier
// characters because the rest of the quoted content may contain
// version specifiers, extras brackets, or URL references.
var pyProjectDepRE = regexp.MustCompile(`"([A-Za-z0-9_.\-]+)[^"]*"|^([A-Za-z0-9_.\-]+)\s*=`)

func (m *DepsEcosystemsModule) parsePyProjectToml(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Find every bracketed reference AND the `name = "version"`
		// form used by poetry. Multiple matches per line are
		// possible in inline tables.
		matches := pyProjectDepRE.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			var pkg string
			if match[1] != "" {
				pkg = strings.ToLower(match[1])
			} else if match[2] != "" {
				pkg = strings.ToLower(match[2])
			}
			if pkg == "" || seen[pkg] {
				continue
			}
			seen[pkg] = true
			if f := m.matchPythonPkg(path, pkg); f != nil {
				out = append(out, f)
			}
		}
	}
	logScannerErr(path, "pyproject", scanner.Err())
	return out
}

// matchPythonPkg checks a package name against the allowlist and
// returns a finding when it matches. Handles the `pyjwt[crypto]`
// bracket-extra case by stripping the extras before lookup.
func (m *DepsEcosystemsModule) matchPythonPkg(path, pkg string) *model.Finding {
	// Strip extras: `pyjwt[crypto]` -> `pyjwt`.
	if i := strings.IndexByte(pkg, '['); i > 0 {
		pkg = pkg[:i]
	}
	purpose, ok := pythonCryptoPkgs[pkg]
	if !ok {
		return nil
	}
	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     "Python dependency",
		Algorithm:    pkg,
		Purpose:      "Python package: " + purpose,
		Reachability: "direct",
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = pkg // restore
	return depsEcoFinding(path, asset)
}

// --- Node / JavaScript ---

// nodeCryptoPkgs is the allowlist of npm package names for crypto
// libraries. Same conventions as pythonCryptoPkgs.
var nodeCryptoPkgs = map[string]string{
	"crypto-js":          "Pure-JS crypto primitives (browser-compatible)",
	"node-forge":         "TLS / PKCS / OID toolkit",
	"bcryptjs":           "Pure-JS bcrypt",
	"bcrypt":             "Native bcrypt binding",
	"argon2":             "Native Argon2 binding",
	"jsonwebtoken":       "JSON Web Token library",
	"jose":               "JOSE (JWT/JWS/JWE/JWK) implementation",
	"tweetnacl":          "TweetNaCl signing/encryption",
	"libsodium-wrappers": "libsodium high-level bindings",
	"sodium-native":      "libsodium low-level bindings",
	"elliptic":           "Pure-JS elliptic curve cryptography",
	"noble-secp256k1":    "Audited secp256k1 implementation",
	"noble-ed25519":      "Audited Ed25519 implementation",
	"bn.js":              "Arbitrary-precision arithmetic (used by crypto libs)",
	"hash.js":            "Pure-JS hash functions",
	"openpgp":            "OpenPGP.js",
	"node-rsa":           "Pure-JS RSA",
	"jsrsasign":          "Pure-JS RSA/X.509/ASN.1 suite",
	// Deprecated / dangerous.
	"md5":  "DEPRECATED md5 pure-JS (compromised hash)",
	"sha1": "DEPRECATED sha1 pure-JS (compromised hash)",
}

func (m *DepsEcosystemsModule) parseNodePackageJSON(path string, data []byte) []*model.Finding {
	// Try JSON parse first — package.json is always JSON. For
	// package-lock.json and yarn.lock we fall back to substring
	// extraction because those formats vary.
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	var out []*model.Finding
	seen := make(map[string]bool)

	if err := json.Unmarshal(data, &pj); err == nil {
		for _, depMap := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.PeerDependencies, pj.OptionalDependencies} {
			for name := range depMap {
				if seen[name] {
					continue
				}
				seen[name] = true
				if f := m.matchNodePkg(path, name); f != nil {
					out = append(out, f)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	// Fallback: regex-scan the blob for known package names. This
	// handles package-lock.json (which has deeper nesting) and
	// yarn.lock (which is a custom format entirely).
	blob := string(data)
	for name := range nodeCryptoPkgs {
		// Look for the name inside quotes to avoid matching it as
		// a substring of another identifier.
		needle := `"` + name + `"`
		if strings.Contains(blob, needle) && !seen[name] {
			seen[name] = true
			if f := m.matchNodePkg(path, name); f != nil {
				out = append(out, f)
			}
		}
	}
	return out
}

func (m *DepsEcosystemsModule) matchNodePkg(path, pkg string) *model.Finding {
	purpose, ok := nodeCryptoPkgs[pkg]
	if !ok {
		return nil
	}
	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     "Node.js dependency",
		Algorithm:    pkg,
		Purpose:      "Node package: " + purpose,
		Reachability: "direct",
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = pkg
	return depsEcoFinding(path, asset)
}

// --- Java ---

// javaCryptoArtifacts maps Maven `groupId:artifactId` pairs to a
// description. Some entries use the group alone when the whole
// group is crypto-focused (e.g., `org.bouncycastle`).
var javaCryptoArtifacts = map[string]string{
	"org.bouncycastle":             "BouncyCastle (Java crypto provider)",
	"com.google.crypto.tink":       "Google Tink (audited crypto toolkit)",
	"io.jsonwebtoken":              "jjwt (JSON Web Token library)",
	"com.auth0:java-jwt":           "Auth0 Java JWT",
	"org.apache.santuario:xmlsec":  "Apache Santuario XML Security (XML-DSig)",
	"org.shiro":                    "Apache Shiro (security framework)",
	"org.springframework.security": "Spring Security",
	"com.google.crypto.tink:tink":  "Google Tink (main artifact)",
	"net.i2p.crypto":               "i2p native crypto bindings",
	"org.conscrypt":                "Conscrypt (BoringSSL JSSE provider)",
	// Legacy / dangerous
	"org.apache.commons:commons-crypto": "Apache Commons Crypto",
	"org.cryptacular":                   "Cryptacular (legacy crypto wrapper)",
}

// javaPomDepRE matches <dependency><groupId>X</groupId><artifactId>Y</artifactId>…
// as a flat regex across the collapsed XML. We don't DOM-parse;
// regex catches every real-world pom shape including the
// single-line / multi-line split the test uses.
var javaPomDepRE = regexp.MustCompile(`(?s)<groupId>\s*([^<\s]+)\s*</groupId>\s*<artifactId>\s*([^<\s]+)\s*</artifactId>`)

// javaPomDepMgmtRE matches the entire <dependencyManagement>…
// </dependencyManagement> block so we can strip it before the
// real dependency scan. DM entries declare version CONSTRAINTS,
// not active dependencies — a BouncyCastle entry under
// dependencyManagement is NOT a direct reference. Sprint-review
// SF3 regression.
var javaPomDepMgmtRE = regexp.MustCompile(`(?s)<dependencyManagement>.*?</dependencyManagement>`)

// javaPomPluginMgmtRE does the same for <pluginManagement>.
var javaPomPluginMgmtRE = regexp.MustCompile(`(?s)<pluginManagement>.*?</pluginManagement>`)

func (m *DepsEcosystemsModule) parseJavaPomXML(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	seen := make(map[string]bool)

	// Strip management blocks before applying the dependency
	// regex so version-only constraints don't produce findings.
	cleaned := javaPomDepMgmtRE.ReplaceAll(data, []byte(""))
	cleaned = javaPomPluginMgmtRE.ReplaceAll(cleaned, []byte(""))

	matches := javaPomDepRE.FindAllSubmatch(cleaned, -1)
	for _, match := range matches {
		group := string(match[1])
		artifact := string(match[2])
		key := group + ":" + artifact
		if seen[key] {
			continue
		}
		seen[key] = true
		if f := m.matchJavaArtifact(path, group, artifact); f != nil {
			out = append(out, f)
		}
	}
	return out
}

// javaGradleDepRE captures gradle coordinate strings: either
// `'group:artifact:version'` or `"group:artifact:version"`.
var javaGradleDepRE = regexp.MustCompile(`["']([a-zA-Z0-9_.\-]+):([a-zA-Z0-9_.\-]+):([a-zA-Z0-9_.\-+]+)["']`)

func (m *DepsEcosystemsModule) parseJavaBuildGradle(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	seen := make(map[string]bool)

	matches := javaGradleDepRE.FindAllSubmatch(data, -1)
	for _, match := range matches {
		group := string(match[1])
		artifact := string(match[2])
		key := group + ":" + artifact
		if seen[key] {
			continue
		}
		seen[key] = true
		if f := m.matchJavaArtifact(path, group, artifact); f != nil {
			out = append(out, f)
		}
	}
	return out
}

// matchJavaArtifact looks up a Maven coordinate in the allowlist.
// Matches in two modes: exact `group:artifact` or group prefix
// alone (for groups whose every artifact is crypto).
func (m *DepsEcosystemsModule) matchJavaArtifact(path, group, artifact string) *model.Finding {
	// Exact coordinate match wins.
	if purpose, ok := javaCryptoArtifacts[group+":"+artifact]; ok {
		return m.buildJavaFinding(path, group+":"+artifact, purpose)
	}
	// Group-level match: the group is in the map AS A KEY without
	// a colon, meaning any artifact in that group counts.
	if purpose, ok := javaCryptoArtifacts[group]; ok {
		return m.buildJavaFinding(path, group+":"+artifact, purpose)
	}
	// Group prefix match for multi-level groups like
	// `org.bouncycastle` → matches `org.bouncycastle:bcprov-jdk18on`.
	for key, purpose := range javaCryptoArtifacts {
		if !strings.Contains(key, ":") && strings.HasPrefix(group, key) {
			return m.buildJavaFinding(path, group+":"+artifact, purpose)
		}
	}
	return nil
}

func (m *DepsEcosystemsModule) buildJavaFinding(path, coord, purpose string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     "Java dependency",
		Algorithm:    coord,
		Purpose:      "Java package: " + purpose,
		Reachability: "direct",
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = coord
	return depsEcoFinding(path, asset)
}

// --- finding builder ---

func depsEcoFinding(path string, asset *model.CryptoAsset) *model.Finding {
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
		Confidence:  ConfidenceMedium,
		Module:      "deps_ecosystems",
		Timestamp:   time.Now(),
	}
}
