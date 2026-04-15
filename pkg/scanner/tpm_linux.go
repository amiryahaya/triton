//go:build linux

package scanner

import (
	"context"
	stdx509 "crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/crypto/keyquality"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tpmfs"
)

// Default production paths; overridable via TPMSysRoot / TPMSecRoot config
// fields (left empty in production; tests inject fixtures).
const (
	defaultTPMSysRoot = "/sys/class/tpm"
	defaultTPMSecRoot = "/sys/kernel/security"
)

// scan walks /sys/class/tpm, emits one device finding per TPM, plus EK cert
// and event-log findings when those artefacts are available. Missing TPM
// (no /sys/class/tpm) is a silent no-op. Never hard-fails.
func (m *TPMModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	sysRoot := defaultTPMSysRoot
	secRoot := defaultTPMSecRoot
	if m.cfg != nil && m.cfg.TPMSysRoot != "" {
		sysRoot = m.cfg.TPMSysRoot
	}
	if m.cfg != nil && m.cfg.TPMSecRoot != "" {
		secRoot = m.cfg.TPMSecRoot
	}

	devs, err := tpmfs.DiscoverDevices(sysRoot)
	if err != nil {
		// Non-fatal: surface via a skipped finding.
		return emitTPMSkipped(ctx, findings, err.Error())
	}
	if len(devs) == 0 {
		return nil // no TPM present — silent success
	}

	for _, dev := range devs {
		if err := emitDeviceFinding(ctx, dev, findings); err != nil {
			return err
		}
		if dev.EKCertPath != "" {
			if err := emitEKCertFinding(ctx, dev, findings); err != nil {
				return err
			}
		}
		logPath := filepath.Join(secRoot, dev.Name, "binary_bios_measurements")
		if _, err := os.Stat(logPath); err == nil {
			if err := emitEventLogFinding(ctx, logPath, findings); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitDeviceFinding emits the top-level TPM device finding with CVE-derived
// quality warnings.
//
// Severity aggregation: we walk every matching CVE and track the worst-case
// severity. CRITICAL wins outright and forces UNSAFE; otherwise the first
// HIGH or MEDIUM we see seeds the PQCStatus. Later hits of equal-or-lower
// severity cannot downgrade what's already been set.
func emitDeviceFinding(ctx context.Context, dev tpmfs.Device, findings chan<- *model.Finding) error {
	cves := crypto.LookupTPMFirmwareCVEs(dev.Vendor, dev.FirmwareVersion)
	cves = append(cves, crypto.TPMSpecCVEs(dev.SpecVersion)...)
	status := "SAFE"
	severity := "" // aggregate worst-case severity across CVE hits
	qualityWarnings := make([]model.QualityWarning, 0, len(cves))
	for _, cve := range cves {
		qualityWarnings = append(qualityWarnings, model.QualityWarning{
			Code:     "FIRMWARE-CVE",
			Severity: cve.Severity,
			Message:  cve.Description,
			CVE:      cve.CVE,
		})
		switch cve.Severity {
		case "CRITICAL":
			status = "UNSAFE"
			severity = "CRITICAL"
		case "HIGH":
			if severity == "" {
				status = "DEPRECATED"
				severity = "HIGH"
			}
		case "MEDIUM":
			if severity == "" {
				status = "TRANSITIONAL"
				severity = "MEDIUM"
			}
		}
	}

	algo := "TPM" + dev.SpecVersion
	asset := &model.CryptoAsset{
		ID:              uuid.New().String(),
		Algorithm:       algo,
		Library:         dev.Vendor + " TPM firmware",
		Language:        "Firmware",
		Function:        "Hardware root of trust",
		PQCStatus:       status,
		QualityWarnings: qualityWarnings,
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            dev.Path,
			DetectionMethod: "sysfs",
			Evidence:        fmt.Sprintf("vendor=%s firmware=%s tcg-version=%s", dev.Vendor, dev.FirmwareVersion, dev.SpecVersion),
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "tpm",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

// emitEKCertFinding emits a finding for the endorsement-key certificate.
func emitEKCertFinding(ctx context.Context, dev tpmfs.Device, findings chan<- *model.Finding) error {
	ek, err := tpmfs.ReadEKCert(dev.EKCertPath)
	if err != nil || ek == nil {
		return nil // silently skip unparseable or missing EK cert
	}
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: ek.Algorithm,
		KeySize:   ek.KeySize,
		Subject:   ek.Subject,
		Issuer:    ek.Issuer,
		Function:  "TPM endorsement key",
		Language:  "Firmware",
	}
	crypto.ClassifyCryptoAsset(asset)
	// Reuse keyquality for material-level audits.
	pub := extractPubForQuality(ek.RawDER)
	if pub != nil {
		ws := keyquality.Analyze(pub, asset.Algorithm, asset.KeySize)
		if len(ws) > 0 {
			asset.QualityWarnings = keyquality.ToModel(ws)
		}
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            dev.EKCertPath,
			DetectionMethod: "sysfs",
			Evidence:        "TPM endorsement key certificate",
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "tpm",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

// extractPubForQuality re-parses the DER to pull the public key out.
// Duplicates some work from ReadEKCert but keeps that function's signature
// clean. Returns nil on parse failure so callers can silently skip quality
// analysis rather than fail the whole scan.
func extractPubForQuality(der []byte) interface{} {
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert.PublicKey
}

// emitEventLogFinding parses the TCG event log and emits a finding with its
// hash-algorithm classification.
func emitEventLogFinding(ctx context.Context, logPath string, findings chan<- *model.Finding) error {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil // silently skip — log presence is best-effort
	}
	log, err := tpmfs.ParseEventLog(data)
	if err != nil {
		return nil // degraded; log corruption surfaces in a future finding
	}
	pqc := classifyEventLog(log)
	evidence := formatLogEvidence(log)
	asset := &model.CryptoAsset{
		ID:        uuid.New().String(),
		Algorithm: "Measured-Boot-Log",
		Library:   "TCG PFP TPM 2.0",
		Language:  "Firmware",
		Function:  "Measured boot integrity",
		PQCStatus: pqc,
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            logPath,
			DetectionMethod: "tcg-pfp-log",
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "tpm",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

func formatLogEvidence(log *tpmfs.EventLog) string {
	parts := fmt.Sprintf("%d events", len(log.Entries))
	for _, a := range []tpmfs.HashAlgo{tpmfs.AlgSHA1, tpmfs.AlgSHA256, tpmfs.AlgSHA384, tpmfs.AlgSHA512, tpmfs.AlgSM3} {
		if n := log.AlgoCounts[a]; n > 0 {
			parts += fmt.Sprintf(", %d %s", n, a.String())
		}
	}
	return parts
}

// emitTPMSkipped emits a single skipped-finding with the given reason.
func emitTPMSkipped(ctx context.Context, findings chan<- *model.Finding, reason string) error {
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			DetectionMethod: "tpm-skipped",
			Evidence:        "tpm scan error: " + reason,
		},
		CryptoAsset: &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: "N/A",
			Language:  "Firmware",
		},
		Confidence: 0.0,
		Module:     "tpm",
		Timestamp:  time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}
