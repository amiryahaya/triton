package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// FirmwareModule scans firmware and Secure Boot state on Linux:
//
//   - EFI variable names under /sys/firmware/efi/efivars/ — detects
//     presence of PK, KEK, db, dbx (Secure Boot key databases)
//   - `mokutil --list-enrolled` — shim MOK chain signature algorithms
//   - /sys/class/tpm/tpm0/ — TPM version and PCR bank presence
//
// Linux-first. Windows Secure Boot deferred to Wave 4.
// BMC/Redfish HTTP probing deferred to follow-up.
type FirmwareModule struct {
	config *scannerconfig.Config
}

// NewFirmwareModule constructs a FirmwareModule.
func NewFirmwareModule(cfg *scannerconfig.Config) *FirmwareModule {
	return &FirmwareModule{config: cfg}
}

func (m *FirmwareModule) Name() string                         { return "firmware" }
func (m *FirmwareModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *FirmwareModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// Abstracted I/O for testability.
var firmwareCmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

var firmwareReadDir = func(name string) ([]string, error) {
	entries, err := os.ReadDir(name)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

var firmwareReadFile = func(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// Scan probes EFI variables, MOK chain, and TPM presence.
// This does NOT use walkTarget since it reads specific sysfs paths
// and runs commands, not a general filesystem walk.
func (m *FirmwareModule) Scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	// 1. EFI Secure Boot variables
	if names, err := firmwareReadDir("/sys/firmware/efi/efivars"); err == nil {
		for _, f := range m.parseEFIVarNames(names) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		log.Printf("firmware: EFI vars unavailable: %v", err)
	}

	// 2. MOK chain (shim Secure Boot)
	if out, err := firmwareCmdRunner(ctx, "mokutil", "--list-enrolled"); err == nil {
		for _, f := range m.parseMokutilOutput(string(out)) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		log.Printf("firmware: mokutil unavailable: %v", err)
	}

	// 3. TPM presence and version
	tpmVersion, _ := firmwareReadFile("/sys/class/tpm/tpm0/tpm_version_major")
	_, pcrErr := firmwareReadFile("/sys/class/tpm/tpm0/pcrs")
	hasPCR := pcrErr == nil
	for _, f := range m.parseTPMInfo(tpmVersion, hasPCR) {
		select {
		case findings <- f:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// --- EFI variables ---

// secureBootVarPrefixes maps EFI variable name prefixes to their
// Secure Boot function descriptions.
var secureBootVarPrefixes = map[string]string{
	"PK-":  "Secure Boot Platform Key (PK)",
	"KEK-": "Secure Boot Key Exchange Key (KEK)",
	"db-":  "Secure Boot signature database (db)",
	"dbx-": "Secure Boot forbidden signatures (dbx)",
}

// parseEFIVarNames examines EFI variable names for Secure Boot presence.
// We don't parse the binary EFI_SIGNATURE_LIST content (complex DER
// extraction) — variable presence alone confirms Secure Boot enrollment.
func (m *FirmwareModule) parseEFIVarNames(names []string) []*model.Finding {
	var out []*model.Finding
	for _, name := range names {
		for prefix, function := range secureBootVarPrefixes {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  function,
				Algorithm: "X.509",
				Purpose:   fmt.Sprintf("EFI variable %s present", name),
			}
			crypto.ClassifyCryptoAsset(asset)
			asset.Algorithm = "X.509"

			out = append(out, &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: CategoryConfig,
				Source: model.FindingSource{
					Type:            "file",
					Path:            "/sys/firmware/efi/efivars/" + name,
					DetectionMethod: "efi-variable",
				},
				CryptoAsset: asset,
				Confidence:  ConfidenceDefinitive,
				Module:      "firmware",
				Timestamp:   time.Now(),
			})
			break
		}
	}
	return out
}

// --- MOK chain ---

// parseMokutilOutput extracts signature algorithms from
// `mokutil --list-enrolled` output.
func (m *FirmwareModule) parseMokutilOutput(output string) []*model.Finding {
	var out []*model.Finding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Signature Algorithm:") {
			continue
		}
		sigAlgo := strings.TrimSpace(strings.TrimPrefix(line, "Signature Algorithm:"))
		if sigAlgo == "" {
			continue
		}

		// Normalize: "sha256WithRSAEncryption" → RSA,
		// "ecdsa-with-SHA256" → ECDSA
		canonical := normalizeMOKSigAlgo(sigAlgo)

		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "MOK enrolled key",
			Algorithm: canonical,
			Purpose:   fmt.Sprintf("mokutil: %s", sigAlgo),
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = canonical

		out = append(out, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: CategoryConfig,
			Source: model.FindingSource{
				Type:            "process",
				DetectionMethod: "mokutil",
			},
			CryptoAsset: asset,
			Confidence:  ConfidenceDefinitive,
			Module:      "firmware",
			Timestamp:   time.Now(),
		})
	}
	return out
}

// normalizeMOKSigAlgo extracts the key algorithm family from OpenSSL
// signature algorithm strings used in X.509 certificates.
func normalizeMOKSigAlgo(s string) string {
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "rsa"):
		return "RSA"
	case strings.Contains(lower, "ecdsa"):
		return "ECDSA"
	case strings.Contains(lower, "ed25519"):
		return "Ed25519"
	case strings.Contains(lower, "ed448"):
		return "Ed448"
	default:
		return s
	}
}

// --- TPM ---

// parseTPMInfo reports TPM version and PCR bank presence.
func (m *FirmwareModule) parseTPMInfo(versionMajor string, hasPCRs bool) []*model.Finding {
	if versionMajor == "" {
		return nil
	}

	tpmName := "TPM " + versionMajor + ".x"
	switch versionMajor {
	case "2":
		tpmName = "TPM 2.0"
	case "1":
		tpmName = "TPM 1.2"
	}

	purpose := "TPM present"
	if hasPCRs {
		purpose = "TPM present with PCR banks"
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Trusted Platform Module",
		Algorithm: tpmName,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = tpmName

	return []*model.Finding{{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryConfig,
		Source: model.FindingSource{
			Type:            "file",
			Path:            "/sys/class/tpm/tpm0/",
			DetectionMethod: "sysfs",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceDefinitive,
		Module:      "firmware",
		Timestamp:   time.Now(),
	}}
}
