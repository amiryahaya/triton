package scanner

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// Sprint C2 — extends the codesign module to PE Authenticode and
// JVM JAR/WAR/EAR archives. Both are cross-platform: osslsigncode
// runs on Linux/macOS/Windows, jarsigner ships with the JDK on
// every platform. Operators auditing Windows binaries from a
// Linux scanning host get coverage they did not have before.
//
// Each check method is a thin wrapper:
//
//  1. shell out to the external tool
//  2. parse the output for algorithm, hash type, signer subject
//  3. emit one finding per discovery
//
// On missing tools we emit a single "tool unavailable" finding
// instead of failing silently — operators must know that
// Authenticode coverage is gated on having osslsigncode installed.

// --- Authenticode ---

// authSigVerifyRE matches the "Signature verification: ok" /
// "Signature verification: failed" line that osslsigncode emits.
var authSigVerifyRE = regexp.MustCompile(`(?i)Signature verification:\s*(\S+)`)

// authHashRE captures the message digest algorithm from the
// `Message digest algorithm  : SHA256` line.
var authHashRE = regexp.MustCompile(`(?i)Message digest algorithm\s*:\s*(\S+)`)

// authSubjectRE captures the signer subject DN from the
// `Subject : /C=US/O=…/CN=…` line. The DN spans the rest of
// the line so we capture greedy.
var authSubjectRE = regexp.MustCompile(`(?i)\s+Subject\s*:\s*(.+)`)

// checkAuthenticode runs `osslsigncode verify -in <path>` and
// translates the output into findings. Returns a single
// "tool unavailable" finding when osslsigncode is not installed
// so operators see the gap in their report.
func (m *CodeSignModule) checkAuthenticode(ctx context.Context, path string) []*model.Finding {
	out, err := m.cmdRunner(ctx, "osslsigncode", "verify", "-in", path)
	output := string(out)

	// "exec: not found" or PATH miss → emit gap finding.
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		return []*model.Finding{m.toolMissingFinding(path, "Authenticode", "osslsigncode")}
	}

	combined := output
	if err != nil {
		combined += " " + err.Error()
	}

	// Determine signed vs unsigned.
	if strings.Contains(combined, "No signature found") {
		return []*model.Finding{m.unsignedFinding(path, "Authenticode (PE)")}
	}

	// Extract hash algorithm + subject.
	hashAlgo := ""
	if match := authHashRE.FindStringSubmatch(output); len(match) == 2 {
		hashAlgo = canonicalHashAlgo(match[1])
	}
	subject := ""
	if match := authSubjectRE.FindStringSubmatch(output); len(match) == 2 {
		subject = strings.TrimSpace(match[1])
	}

	verified := false
	if match := authSigVerifyRE.FindStringSubmatch(output); len(match) == 2 {
		verified = strings.EqualFold(match[1], "ok")
	}

	purpose := "Authenticode signature"
	if !verified {
		purpose = "Authenticode signature INVALID"
	}
	if subject != "" {
		purpose += " (" + subject + ")"
	}

	algo := hashAlgo
	if algo == "" {
		algo = "SHA-256" // canonical Authenticode default
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Code signing certificate",
		Algorithm: algo,
		Subject:   subject,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	return []*model.Finding{codesignFinding(path, asset)}
}

// --- JAR ---

// jarSignedRE matches the `jar verified.` success line.
var jarSignedRE = regexp.MustCompile(`(?i)\bjar verified\b`)

// jarUnsignedRE matches `jar is unsigned.`
var jarUnsignedRE = regexp.MustCompile(`(?i)\bjar is unsigned\b`)

// jarSignerRE captures `Signed by "CN=…"` lines.
var jarSignerRE = regexp.MustCompile(`(?i)Signed by\s+"([^"]+)"`)

// jarSigAlgoRE captures `Signature algorithm: SHA256withRSA, 2048-bit key`.
var jarSigAlgoRE = regexp.MustCompile(`(?i)Signature algorithm:\s*([A-Za-z0-9]+)(?:,\s*(\d+)-bit)?`)

// checkJARSignature runs `jarsigner -verify -verbose -certs <path>`
// and translates the output. Returns a tool-missing finding when
// jarsigner is not on PATH.
func (m *CodeSignModule) checkJARSignature(ctx context.Context, path string) []*model.Finding {
	out, err := m.cmdRunner(ctx, "jarsigner", "-verify", "-verbose", "-certs", path)
	output := string(out)

	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		return []*model.Finding{m.toolMissingFinding(path, "JAR", "jarsigner")}
	}

	if jarUnsignedRE.MatchString(output) {
		return []*model.Finding{m.unsignedFinding(path, "JAR archive")}
	}
	verified := jarSignedRE.MatchString(output)

	subject := ""
	if match := jarSignerRE.FindStringSubmatch(output); len(match) == 2 {
		subject = match[1]
	}

	// JVM signature algorithm is reported in the form
	// `SHA256withRSA` (hash + signing key in one token). For
	// the asset.Algorithm field we want JUST the signing key
	// algorithm — RSA, DSA, ECDSA, EdDSA — because that's the
	// key the certificate carries. We separately keep the raw
	// JVM token in Purpose so the report shows the hash too.
	algo := "RSA"
	rawAlgo := ""
	keySize := 0
	if match := jarSigAlgoRE.FindStringSubmatch(output); len(match) >= 2 {
		rawAlgo = match[1]
		if idx := strings.Index(strings.ToLower(rawAlgo), "with"); idx >= 0 && idx+4 < len(rawAlgo) {
			algo = rawAlgo[idx+4:]
		} else {
			algo = rawAlgo
		}
		if len(match) == 3 && match[2] != "" {
			// Tiny inline atoi to keep the import set flat.
			n := 0
			for _, c := range match[2] {
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + int(c-'0')
			}
			if n > 0 {
				keySize = n
			}
		}
	}

	purpose := "JAR signature"
	if !verified {
		purpose = "JAR signature INVALID"
	}
	if rawAlgo != "" {
		purpose += " (jarsigner: " + rawAlgo + ")"
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Code signing certificate",
		Algorithm: algo,
		KeySize:   keySize,
		Subject:   subject,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	return []*model.Finding{codesignFinding(path, asset)}
}

// --- shared finding builders ---

// unsignedFinding produces the canonical "this artifact carries
// no signature" finding. Algorithm is "none" so the report and
// policy engine can pivot on it.
func (m *CodeSignModule) unsignedFinding(path, what string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Code signing",
		Algorithm: "none",
		Purpose:   "Unsigned " + what + ": " + path,
	}
	crypto.ClassifyCryptoAsset(asset)
	return codesignFinding(path, asset)
}

// toolMissingFinding emits a notice that we could not check
// signatures because the verification tool was not on PATH.
// This is intentionally a finding (not a silent skip) so the
// gap is visible in the report.
func (m *CodeSignModule) toolMissingFinding(path, what, tool string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Code signing",
		Algorithm: "tool-unavailable",
		Purpose:   what + " verification skipped: " + tool + " not on PATH",
		PQCStatus: "TRANSITIONAL",
	}
	return codesignFinding(path, asset)
}

// codesignFinding wraps an asset into the codesign module's
// canonical Finding envelope.
func codesignFinding(path string, asset *model.CryptoAsset) *model.Finding {
	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryKernel, // codesign is part of CategoryKernel (4) historically
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "command",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceHigh,
		Module:      "codesign",
		Timestamp:   time.Now(),
	}
}

// canonicalHashAlgo normalizes spellings emitted by external
// tools (osslsigncode, jarsigner) into the registry's canonical
// names. Caller passes the raw token; we trim whitespace and
// upper-case before mapping.
func canonicalHashAlgo(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "SHA1", "SHA-1":
		return "SHA-1"
	case "SHA256", "SHA-256":
		return "SHA-256"
	case "SHA384", "SHA-384":
		return "SHA-384"
	case "SHA512", "SHA-512":
		return "SHA-512"
	case "MD5":
		return "MD5"
	}
	return raw
}
