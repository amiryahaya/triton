package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// CodeSignModule verifies code signing on executables, apps, and packages.
type CodeSignModule struct {
	config         *config.Config
	cmdRunner      cmdRunnerFunc
	cmdRunCombined cmdRunnerFunc // for commands that write to stderr
}

// NewCodeSignModule creates a new CodeSignModule.
func NewCodeSignModule(cfg *config.Config) *CodeSignModule {
	return &CodeSignModule{
		config:         cfg,
		cmdRunner:      defaultCmdRunner,
		cmdRunCombined: defaultCmdRunnerCombined,
	}
}

func (m *CodeSignModule) Name() string                         { return "codesign" }
func (m *CodeSignModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *CodeSignModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// Scan traverses the target filesystem looking for signed or unsigned binaries.
func (m *CodeSignModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return walkTarget(walkerConfig{
		ctx:       ctx,
		target:    target,
		config:    m.config,
		matchFile: isCodeSignCandidate,
		processFile: func(path string) error {
			found := m.checkCodeSign(ctx, path)
			for _, f := range found {
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

// isCodeSignCandidate checks if a file is a candidate for code signing verification.
// Only matches package files (.app, .pkg, .deb, .rpm) and skips extensionless files
// to avoid invoking codesign on thousands of non-binary files.
func isCodeSignCandidate(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))

	switch runtime.GOOS {
	case "darwin":
		switch ext {
		case ".app", ".pkg", ".dylib", ".framework", ".bundle":
			return true
		}
	case "linux":
		switch ext {
		case ".deb", ".rpm":
			return true
		}
	}

	return false
}

// checkCodeSign verifies code signing for a specific file.
func (m *CodeSignModule) checkCodeSign(ctx context.Context, path string) []*model.Finding {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	switch runtime.GOOS {
	case "darwin":
		return m.checkMacOSCodeSign(ctx, path)
	case "linux":
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".rpm":
			return m.checkRPMSignature(ctx, path)
		case ".deb":
			return m.checkDpkgSignature(ctx, path)
		default:
			return nil
		}
	default:
		return nil
	}
}

// --- macOS code signing ---

// macOSAuthorityRegex extracts the Authority field from codesign --display output.
var macOSAuthorityRegex = regexp.MustCompile(`Authority=(.+)`)

// macOSTeamIDRegex extracts the TeamIdentifier from codesign --display output.
var macOSTeamIDRegex = regexp.MustCompile(`TeamIdentifier=(.+)`)

// macOSSignAlgoRegex extracts the signature algorithm.
var macOSSignAlgoRegex = regexp.MustCompile(`Signature size=\d+|Hash type=(\S+)|CDHash=`)

// checkMacOSCodeSign verifies a macOS binary's code signature.
func (m *CodeSignModule) checkMacOSCodeSign(ctx context.Context, path string) []*model.Finding {
	// Step 1: Verify signature
	verifyOut, verifyErr := m.cmdRunner(ctx, "codesign", "--verify", "--deep", "--verbose=2", "--", path)

	// Step 2: Display detailed signature info (codesign --display writes to stderr)
	displayOut, displayErr := m.cmdRunCombined(ctx, "codesign", "--display", "--verbose=4", "--", path)

	return m.parseMacOSCodeSign(path, string(verifyOut), verifyErr, string(displayOut), displayErr)
}

// parseMacOSCodeSign interprets codesign output into findings.
func (m *CodeSignModule) parseMacOSCodeSign(path, verifyOut string, verifyErr error, displayOut string, displayErr error) []*model.Finding {
	var findings []*model.Finding

	// Determine validity
	var validity string
	if verifyErr != nil {
		errMsg := verifyErr.Error()
		combined := verifyOut + errMsg
		if strings.Contains(combined, "code object is not signed") ||
			strings.Contains(combined, "not signed at all") {
			validity = "unsigned"
		} else {
			validity = "invalid"
		}
	} else {
		validity = "valid"
	}

	// For unsigned binaries, emit an unsigned finding
	if validity == "unsigned" {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "Code signing",
			Algorithm: "none",
			Purpose:   fmt.Sprintf("Unsigned binary: %s", path),
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 4,
			Source: model.FindingSource{
				Type:            "file",
				Path:            path,
				DetectionMethod: "command",
			},
			CryptoAsset: asset,
			Confidence:  0.90,
			Module:      "codesign",
			Timestamp:   time.Now(),
		})
		return findings
	}

	// Parse display output for cert chain
	var authority string
	var teamID string
	var sigAlgo string

	if displayErr == nil && displayOut != "" {
		authority, teamID, sigAlgo = parseMacOSDisplayOutput(displayOut)
	}

	if sigAlgo == "" {
		sigAlgo = "SHA256withRSA" // default assumption for macOS code signing
	}

	purpose := fmt.Sprintf("Code signing: %s", validity)
	if authority != "" {
		purpose = fmt.Sprintf("Code signing: %s (%s)", validity, authority)
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Code signing certificate",
		Algorithm: sigAlgo,
		Subject:   authority,
		Purpose:   purpose,
	}
	if teamID != "" {
		asset.Purpose += fmt.Sprintf(" [Team: %s]", teamID)
	}
	crypto.ClassifyCryptoAsset(asset)

	findings = append(findings, &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 4,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "command",
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "codesign",
		Timestamp:   time.Now(),
	})

	return findings
}

// parseMacOSDisplayOutput extracts authority, team ID, and algorithm from codesign --display output.
func parseMacOSDisplayOutput(output string) (authority, teamID, sigAlgo string) {
	// Extract first Authority line (signing certificate)
	if matches := macOSAuthorityRegex.FindStringSubmatch(output); len(matches) > 1 {
		authority = matches[1]
	}

	// Extract TeamIdentifier
	if matches := macOSTeamIDRegex.FindStringSubmatch(output); len(matches) > 1 {
		teamID = matches[1]
		if teamID == "not set" {
			teamID = ""
		}
	}

	// Determine signature algorithm from hash type
	if matches := macOSSignAlgoRegex.FindStringSubmatch(output); len(matches) > 1 && matches[1] != "" {
		hashType := strings.ToLower(matches[1])
		switch {
		case strings.Contains(hashType, "sha256"):
			sigAlgo = "SHA256withRSA"
		case strings.Contains(hashType, "sha1"):
			sigAlgo = "SHA1withRSA"
		case strings.Contains(hashType, "sha384"):
			sigAlgo = "SHA384withECDSA"
		default:
			sigAlgo = "SHA256withRSA"
		}
	}

	return authority, teamID, sigAlgo
}

// --- Linux RPM signature verification ---

// rpmSigRegex parses rpm -K output.
var rpmSigRegex = regexp.MustCompile(`(?i)(rsa|dsa|ecdsa)[/ ]?(sha\d+)?`)

// checkRPMSignature verifies an RPM package signature.
func (m *CodeSignModule) checkRPMSignature(ctx context.Context, path string) []*model.Finding {
	out, err := m.cmdRunner(ctx, "rpm", "-K", "--", path)
	return m.parseRPMVerify(path, string(out), err)
}

// parseRPMVerify interprets rpm -K output into findings.
func (m *CodeSignModule) parseRPMVerify(path, output string, cmdErr error) []*model.Finding {
	if cmdErr != nil {
		return nil
	}

	var algo string
	var validity string

	upper := strings.ToUpper(output)
	switch {
	case strings.Contains(upper, "NOT OK") || strings.Contains(upper, "MISSING"):
		validity = "invalid"
	case strings.Contains(upper, "OK"):
		validity = "valid"
	default:
		validity = "unknown"
	}

	if matches := rpmSigRegex.FindStringSubmatch(output); len(matches) > 0 {
		sigType := strings.ToUpper(matches[1])
		hashType := "SHA256"
		if len(matches) > 2 && matches[2] != "" {
			hashType = strings.ToUpper(matches[2])
		}
		algo = hashType + "with" + sigType
	} else {
		algo = "GPG"
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Package signing",
		Algorithm: algo,
		Purpose:   fmt.Sprintf("RPM package signature: %s for %s", validity, path),
	}
	crypto.ClassifyCryptoAsset(asset)

	return []*model.Finding{{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 4,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "command",
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "codesign",
		Timestamp:   time.Now(),
	}}
}

// --- Linux dpkg signature verification ---

// checkDpkgSignature verifies a .deb package signature.
func (m *CodeSignModule) checkDpkgSignature(ctx context.Context, path string) []*model.Finding {
	out, err := m.cmdRunner(ctx, "dpkg-sig", "--verify", "--", path)
	return m.parseDpkgSigVerify(path, string(out), err)
}

// parseDpkgSigVerify interprets dpkg-sig output into findings.
func (m *CodeSignModule) parseDpkgSigVerify(path, output string, cmdErr error) []*model.Finding {
	if cmdErr != nil {
		return nil
	}

	var validity string
	upper := strings.ToUpper(output)
	switch {
	case strings.Contains(upper, "GOODSIG"):
		validity = "valid"
	case strings.Contains(upper, "BADSIG"):
		validity = "invalid"
	case strings.Contains(upper, "NOSIG"):
		validity = "unsigned"
	default:
		validity = "unknown"
	}

	algo := "GPG"

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Package signing",
		Algorithm: algo,
		Purpose:   fmt.Sprintf("Debian package signature: %s for %s", validity, path),
	}
	crypto.ClassifyCryptoAsset(asset)

	return []*model.Finding{{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 4,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "command",
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "codesign",
		Timestamp:   time.Now(),
	}}
}
