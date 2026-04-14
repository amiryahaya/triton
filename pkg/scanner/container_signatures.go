package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// ContainerSignaturesModule scans for container supply-chain
// crypto material:
//
//   - Sigstore / cosign verification keys (cosign.pub, cosign.key)
//   - Notary v1 trust store (~/.docker/trust/private/*.key)
//   - Sigstore root metadata (~/.sigstore/root.json)
//   - Kubernetes service account token JWTs (header inspection)
//   - Kubernetes API server encryption-at-rest configuration
//
// Out of scope: actively pulling images and verifying signatures
// against a registry. That's a "probe" mode for a future sprint
// because it requires registry credentials and network access we
// don't want to assume the agent has.
type ContainerSignaturesModule struct {
	config      *scannerconfig.Config
	store       store.Store
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

// NewContainerSignaturesModule wires the module to the engine config.
func NewContainerSignaturesModule(cfg *scannerconfig.Config) *ContainerSignaturesModule {
	return &ContainerSignaturesModule{config: cfg}
}

func (m *ContainerSignaturesModule) Name() string                   { return "container_signatures" }
func (m *ContainerSignaturesModule) Category() model.ModuleCategory { return model.CategoryPassiveFile }
func (m *ContainerSignaturesModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}
func (m *ContainerSignaturesModule) SetStore(s store.Store)               { m.store = s }
func (m *ContainerSignaturesModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func (m *ContainerSignaturesModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and dispatches each matching file
// to the right per-format parser.
func (m *ContainerSignaturesModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isContainerSignatureFile,
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
				// B1 defense-in-depth — the container_signatures
				// parsers never return nil today, but the
				// interface allows it and a future edit could
				// regress. Drop here so the engine collector is
				// never asked to dereference a nil pointer.
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

// isContainerSignatureFile decides whether a path is in scope.
func isContainerSignatureFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// cosign keys live anywhere; the canonical filenames are
	// what we look for. Reject backups (.bak / .old).
	if base == "cosign.pub" || base == "cosign.key" {
		return true
	}
	// Sigstore client state (root metadata, fulcio chain, etc.)
	if strings.Contains(lower, "/.sigstore/") && strings.HasSuffix(base, ".json") {
		return true
	}
	// Docker Notary trust store.
	if strings.Contains(lower, "/.docker/trust/private/") && strings.HasSuffix(base, ".key") {
		return true
	}
	// Kubernetes service account tokens (in-pod default mount).
	if (strings.Contains(lower, "/var/run/secrets/kubernetes.io/serviceaccount/") ||
		strings.Contains(lower, "/run/secrets/kubernetes.io/serviceaccount/")) && base == "token" {
		return true
	}
	// Kubernetes API server encryption-at-rest config.
	if (base == "encryption-config.yaml" || base == "encryption-provider-config.yaml") &&
		strings.Contains(lower, "/kubernetes/") {
		return true
	}
	return false
}

// parseFile dispatches by filename. Each parser is independent
// and tolerates malformed input by returning nil — the agent
// must keep walking even if a single file is corrupt.
func (m *ContainerSignaturesModule) parseFile(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)
	switch {
	case base == "cosign.pub" || base == "cosign.key":
		return m.parseCosignKey(path, data)
	case strings.Contains(lower, "/.docker/trust/private/"):
		return m.parseNotaryKey(path, data)
	case strings.Contains(lower, "/.sigstore/"):
		return m.parseSigstoreMetadata(path, data)
	case base == "token" && strings.Contains(lower, "/serviceaccount/"):
		return m.parseK8sToken(path, data)
	case base == "encryption-config.yaml" || base == "encryption-provider-config.yaml":
		return m.parseK8sEncryptionConfig(path, data)
	}
	return nil
}

// --- cosign / Notary keys ---

// parseCosignKey emits a finding for a cosign signing key. We
// parse the PEM block to determine the algorithm (cosign defaults
// to ECDSA P-256 but supports RSA and Ed25519). When parsing
// fails we still emit a presence finding so the inventory shows
// the key exists.
func (m *ContainerSignaturesModule) parseCosignKey(path string, data []byte) []*model.Finding {
	algo, keySize := pemAlgorithm(data)
	if algo == "" {
		algo = "Unknown"
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Container image signature",
		Algorithm: algo,
		KeySize:   keySize,
		Purpose:   "cosign / Sigstore signing key",
	}
	crypto.ClassifyCryptoAsset(asset)
	return []*model.Finding{containerSigFinding(path, asset)}
}

// parseNotaryKey emits a presence finding for a Notary v1 trust
// key. The on-disk format is encrypted JSON; we don't decrypt
// (no passphrase) so we just record presence + canonical
// algorithm (Notary v1 uses ECDSA P-256).
func (m *ContainerSignaturesModule) parseNotaryKey(path string, _ []byte) []*model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Container image signature",
		Algorithm: "ECDSA-P256",
		Purpose:   "Docker Notary v1 trust signing key",
	}
	crypto.ClassifyCryptoAsset(asset)
	return []*model.Finding{containerSigFinding(path, asset)}
}

// parseSigstoreMetadata emits a presence finding for a sigstore
// client root metadata file. We don't validate the TUF
// signatures here — operators run `cosign initialize` for that.
func (m *ContainerSignaturesModule) parseSigstoreMetadata(path string, _ []byte) []*model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TUF root metadata",
		Algorithm: "Sigstore-TUF",
		Purpose:   "Sigstore client root.json — verifies the trust root for cosign",
		PQCStatus: "TRANSITIONAL",
	}
	return []*model.Finding{containerSigFinding(path, asset)}
}

// --- K8s service account token ---

// parseK8sToken inspects the JWT header without verifying the
// signature (we don't have the cluster's public key). The "alg"
// claim tells us which signing algorithm Kubernetes is using
// for this projected token, which is the compliance question.
func (m *ContainerSignaturesModule) parseK8sToken(path string, data []byte) []*model.Finding {
	tok := strings.TrimSpace(string(data))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil
	}
	if header.Alg == "" {
		return nil
	}

	// Map JWT alg names to registry algorithms.
	algoName := header.Alg
	switch strings.ToUpper(header.Alg) {
	case "RS256", "RS384", "RS512":
		algoName = "RSA"
	case "ES256":
		algoName = "ECDSA-P256"
	case "ES384":
		algoName = "ECDSA-P384"
	case "ES512":
		algoName = "ECDSA-P521"
	case "EDDSA":
		algoName = "Ed25519"
	}
	info := crypto.ClassifyAlgorithm(algoName, 0)
	if info.Name != "" {
		algoName = info.Name
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Service account token signature",
		Algorithm: algoName,
		Purpose:   "Kubernetes service account JWT (alg=" + header.Alg + ")",
	}
	crypto.ClassifyCryptoAsset(asset)
	return []*model.Finding{containerSigFinding(path, asset)}
}

// --- K8s encryption-config.yaml ---

// k8sKnownProviders is the closed set of provider names the K8s
// API server recognizes. Any `- <name>:` list item whose name
// isn't in this set is silently ignored — this prevents the
// YAML-by-substring walker from emitting false-positive findings
// for nested keys like `- name: key1` under an `aescbc.keys:`
// block.
var k8sKnownProviders = map[string]struct{}{
	"aescbc":    {},
	"aesgcm":    {},
	"secretbox": {},
	"kms":       {},
	"identity":  {},
}

// parseK8sEncryptionConfig walks the providers list under each
// resource entry and produces one finding per provider. Flags
// the case where `identity` is the FIRST provider for a resource
// — that means no encryption is being applied even though other
// providers are also listed (read-only migration mode).
//
// We don't pull in a YAML library to keep the binary flat. The
// walker has three guards against false positives from nested
// keys:
//
//  1. A `providers:` key starts a new block and resets the
//     providerCount + providerIndent to "unknown".
//  2. The first `- ` list item inside the block locks the
//     indent level for that block; subsequent items at a
//     DIFFERENT indent are not considered provider entries
//     (they belong to nested config like `aescbc.keys:`).
//  3. Only provider names in k8sKnownProviders produce a
//     finding. Unknown names are silently ignored rather than
//     being emitted as `algorithm=<unknown>` — the API server
//     would reject them anyway, so there's no compliance
//     signal in flagging them.
func (m *ContainerSignaturesModule) parseK8sEncryptionConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "k8s-encryption-config", scanner.Err()) }()

	inProviders := false
	providerCount := 0
	providerIndent := -1 // locked on first `- ` item inside the block

	for scanner.Scan() {
		line := scanner.Text()
		stripped := strings.TrimSpace(line)
		// Strip YAML line comments before detecting block
		// boundaries. B5 review — `providers: # managed by
		// kubeadm` must still enter the providers block. Be
		// careful to only strip comments, not `#` inside
		// quoted string values (which don't appear in
		// encryption-config.yaml but cost nothing to guard).
		if idx := strings.IndexByte(stripped, '#'); idx >= 0 && !quotedUpTo(stripped, idx) {
			stripped = strings.TrimSpace(stripped[:idx])
		}
		lower := strings.ToLower(stripped)

		// A new providers: key (re)starts the block. Reset.
		// Use HasPrefix on the trimmed-and-de-commented line so
		// `providers:` anywhere in the line structure counts.
		if strings.HasPrefix(lower, "providers:") {
			inProviders = true
			providerCount = 0
			providerIndent = -1
			continue
		}
		if !inProviders || stripped == "" {
			continue
		}
		indent := countLeadingSpaces(line)

		// A line that's shallower than the locked provider
		// indent ends the block.
		if providerIndent >= 0 && indent < providerIndent {
			inProviders = false
			continue
		}

		// We only care about list-item lines (`- <name>:`).
		if !strings.HasPrefix(stripped, "- ") {
			continue
		}

		// Lock the provider indent on the first list item we
		// see inside the block.
		if providerIndent < 0 {
			providerIndent = indent
		}
		// Items at a different indent than the locked level are
		// nested content (e.g., `- name: key1` under
		// aescbc.keys), not providers. Skip them.
		if indent != providerIndent {
			continue
		}

		// Parse provider name from `- aescbc:` / `- identity: {}`.
		body := strings.TrimSpace(strings.TrimPrefix(stripped, "-"))
		if i := strings.IndexByte(body, ':'); i >= 0 {
			body = body[:i]
		}
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		name := strings.ToLower(body)
		if _, known := k8sKnownProviders[name]; !known {
			// Unknown provider name — skip. The K8s API server
			// would reject an unknown provider at startup, so
			// an unknown name is almost certainly a nested YAML
			// key the line-based walker confused for a provider.
			continue
		}
		providerCount++

		var algoName, purpose string
		switch name {
		case "aescbc":
			algoName = "AES-256-CBC"
			purpose = "K8s encryption-at-rest provider: aescbc"
		case "aesgcm":
			algoName = "AES-256-GCM"
			purpose = "K8s encryption-at-rest provider: aesgcm"
		case "secretbox":
			algoName = "XSalsa20-Poly1305"
			purpose = "K8s encryption-at-rest provider: secretbox"
		case "kms":
			algoName = "External KMS"
			purpose = "K8s encryption-at-rest provider: KMS plugin (envelope encryption)"
		case "identity":
			algoName = "Identity (no encryption)"
			if providerCount == 1 {
				purpose = "K8s encryption-at-rest: identity is the first provider — secrets are stored in PLAINTEXT"
			} else {
				purpose = "K8s encryption-at-rest: identity provider used for read-fallback only"
			}
		}

		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "K8s encryption-at-rest",
			Algorithm: algoName,
			Purpose:   purpose,
		}
		crypto.ClassifyCryptoAsset(asset)
		out = append(out, containerSigFinding(path, asset))
	}
	return out
}

// quotedUpTo reports whether position idx in s falls inside a
// double-quoted substring. Used by the YAML comment-stripper
// to avoid cutting at a `#` that lives inside a quoted value.
// Simple scanner — does not honor escape sequences because
// encryption-config.yaml keys never contain embedded quotes.
func quotedUpTo(s string, idx int) bool {
	inQuote := false
	for i := 0; i < idx && i < len(s); i++ {
		if s[i] == '"' {
			inQuote = !inQuote
		}
	}
	return inQuote
}

// countLeadingSpaces counts the leading space characters in a
// line. YAML typically uses spaces not tabs; if operators mix
// tabs the indent lock will be fuzzy but won't produce false
// positives because tabs are not counted as space-indent.
func countLeadingSpaces(s string) int {
	n := 0
	for _, c := range s {
		if c != ' ' {
			return n
		}
		n++
	}
	return n
}

// --- shared helpers ---

// containerSigFinding wraps a CryptoAsset into a Finding with
// the standard envelope used by every container_signatures parser.
// The vendor name is already in asset.Purpose, so we don't take
// it as a separate parameter.
func containerSigFinding(path string, asset *model.CryptoAsset) *model.Finding {
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
		Module:      "container_signatures",
		Timestamp:   time.Now(),
	}
}

// publicKeyAlgo identifies an x509-parsed public key. Returns
// ("", 0) for unknown types — callers fall back to a presence
// finding rather than treating this as an error.
func publicKeyAlgo(pub interface{}) (algo string, keySize int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}

// pemAlgorithm best-effort identifies the algorithm and key size
// of a PEM-encoded key blob. Returns ("", 0) when parsing fails
// for any reason — callers should treat that as "unknown" rather
// than an error condition because cosign keys are sometimes
// stored in formats we don't enumerate.
func pemAlgorithm(data []byte) (algo string, keySize int) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", 0
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", 0
		}
		return publicKeyAlgo(pub)
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return "", 0
		}
		return "RSA", pub.N.BitLen()
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", 0
		}
		return "ECDSA-" + key.Curve.Params().Name, key.Curve.Params().BitSize
	}
	return "", 0
}
