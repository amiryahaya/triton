//go:build linux

package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/crypto/keyquality"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/uefivars"
)

const defaultUEFIVarRoot = "/sys/firmware/efi/efivars"

func (m *UEFIModule) scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	varRoot := defaultUEFIVarRoot
	if m.cfg != nil && m.cfg.UEFIVarRoot != "" {
		varRoot = m.cfg.UEFIVarRoot
	}
	if _, err := os.Stat(varRoot); err != nil {
		return nil // no EFI -> silent no-op
	}

	// State findings.
	if err := m.emitStateFinding(ctx, varRoot, findings); err != nil {
		return err
	}

	// Cert findings for PK, KEK, db.
	for _, varName := range []string{"PK", "KEK", "db"} {
		if err := m.emitCertFindings(ctx, varRoot, varName, findings); err != nil {
			return err
		}
	}

	// dbx aggregate finding.
	if err := m.emitDbxFinding(ctx, varRoot, findings); err != nil {
		return err
	}
	return nil
}

func (m *UEFIModule) emitStateFinding(ctx context.Context, varRoot string, findings chan<- *model.Finding) error {
	sb, sbErr := uefivars.ReadBoolVariable(varRoot, "SecureBoot-"+uefivars.EFIGlobalGUID)
	if sbErr != nil {
		return emitUEFISkipped(ctx, findings, "read SecureBoot: "+sbErr.Error())
	}
	sm, smErr := uefivars.ReadBoolVariable(varRoot, "SetupMode-"+uefivars.EFIGlobalGUID)
	if smErr != nil {
		return emitUEFISkipped(ctx, findings, "read SetupMode: "+smErr.Error())
	}

	// SecureBoot finding.
	sbStatus := "SAFE"
	sbEvidence := "SecureBoot=enabled"
	if !sb {
		sbStatus = "TRANSITIONAL"
		sbEvidence = "SecureBoot=disabled"
	}
	if err := emitUEFIFinding(ctx, findings, varRoot, "SecureBoot-"+uefivars.EFIGlobalGUID,
		"efivars-state", sbEvidence, "Secure-Boot-State", sbStatus, "Boot integrity", nil); err != nil {
		return err
	}

	// SetupMode finding (paired severity).
	smStatus, smEvidence := classifySetupMode(sb, sm)
	var smWarnings []model.QualityWarning
	if sm {
		sev := "HIGH"
		msg := "SetupMode is enabled — unauthenticated key writes are possible"
		if sb {
			sev = "CRITICAL"
			msg = "SetupMode=1 AND SecureBoot=1 — logically impossible per spec; possible firmware bug or tampering"
		}
		smWarnings = []model.QualityWarning{{
			Code: "SETUP-MODE", Severity: sev, Message: msg,
		}}
	}
	return emitUEFIFinding(ctx, findings, varRoot, "SetupMode-"+uefivars.EFIGlobalGUID,
		"efivars-state", smEvidence, "Setup-Mode-State", smStatus, "Boot provisioning", smWarnings)
}

func classifySetupMode(secureBoot, setupMode bool) (status, evidence string) {
	switch {
	case secureBoot && !setupMode:
		return "SAFE", "SetupMode=0, SecureBoot=1 (production)"
	case !secureBoot && !setupMode:
		return "TRANSITIONAL", "SetupMode=0, SecureBoot=0 (locked but disabled)"
	case !secureBoot && setupMode:
		return "DEPRECATED", "SetupMode=1, SecureBoot=0 (unprovisioned)"
	case secureBoot && setupMode:
		return "UNSAFE", "SetupMode=1, SecureBoot=1 (anomalous)"
	}
	return "", ""
}

func (m *UEFIModule) emitCertFindings(ctx context.Context, varRoot, varName string, findings chan<- *model.Finding) error {
	fullName := varName + "-" + uefivars.EFIGlobalGUID
	data, err := uefivars.ReadVariable(varRoot, fullName)
	if err != nil {
		return emitUEFISkipped(ctx, findings, fmt.Sprintf("read %s: %s", fullName, err.Error()))
	}
	if data == nil {
		return nil // variable absent
	}
	entries, err := uefivars.ParseSignatureList(data)
	if err != nil {
		return emitUEFISkipped(ctx, findings, fmt.Sprintf("parse %s: %s", fullName, err.Error()))
	}
	for _, entry := range entries {
		if entry.Type != uefivars.SigTypeX509 {
			continue
		}
		cert, parseErr := stdx509.ParseCertificate(entry.Data)
		if parseErr != nil {
			continue // skip unparseable certs
		}
		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: &cert.NotBefore,
			NotAfter:  &cert.NotAfter,
			Function:  fmt.Sprintf("UEFI %s certificate", varName),
			Language:  "Firmware",
		}
		algoName, keySize := certAlgoAndSize(cert)
		asset.Algorithm = algoName
		asset.KeySize = keySize
		crypto.ClassifyCryptoAsset(asset)
		// Key quality analysis.
		if cert.PublicKey != nil {
			ws := keyquality.Analyze(cert.PublicKey, asset.Algorithm, asset.KeySize)
			if len(ws) > 0 {
				asset.QualityWarnings = keyquality.ToModel(ws)
			}
		}
		pathSuffix := fmt.Sprintf(" [list=%d, cert=%d]", entry.ListIndex, entry.EntryIndex)
		f := &model.Finding{
			ID:       uuid.New().String(),
			Category: int(model.CategoryPassiveFile),
			Source: model.FindingSource{
				Type:            "file",
				Path:            varRoot + "/" + fullName + pathSuffix,
				DetectionMethod: "efivars-cert",
				Evidence:        fmt.Sprintf("owner=%s subject=%s", entry.OwnerGUID, cert.Subject.String()),
			},
			CryptoAsset: asset,
			Confidence:  0.95,
			Module:      "uefi",
			Timestamp:   time.Now().UTC(),
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case findings <- f:
		}
	}
	return nil
}

// certAlgoAndSize derives the algorithm name and key size from an X.509 certificate.
func certAlgoAndSize(cert *stdx509.Certificate) (string, int) {
	switch cert.PublicKeyAlgorithm {
	case stdx509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return fmt.Sprintf("RSA-%d", pub.N.BitLen()), pub.N.BitLen()
		}
		return "RSA", 0
	case stdx509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return fmt.Sprintf("ECDSA-P%d", pub.Curve.Params().BitSize), pub.Curve.Params().BitSize
		}
		return "ECDSA", 0
	case stdx509.Ed25519:
		return "Ed25519", 256
	}
	return cert.PublicKeyAlgorithm.String(), 0
}

func (m *UEFIModule) emitDbxFinding(ctx context.Context, varRoot string, findings chan<- *model.Finding) error {
	fullName := "dbx-" + uefivars.EFIGlobalGUID
	data, err := uefivars.ReadVariable(varRoot, fullName)
	if err != nil {
		return emitUEFISkipped(ctx, findings, fmt.Sprintf("read %s: %s", fullName, err.Error()))
	}
	if data == nil {
		return nil
	}
	entries, err := uefivars.ParseSignatureList(data)
	if err != nil {
		return emitUEFISkipped(ctx, findings, fmt.Sprintf("parse %s: %s", fullName, err.Error()))
	}
	// Build hash set from SHA-256 entries.
	dbxHashes := map[string]bool{}
	for _, e := range entries {
		if e.Type == uefivars.SigTypeSHA256 && len(e.Data) == 32 {
			dbxHashes[hex.EncodeToString(e.Data)] = true
		}
	}
	missing := crypto.LookupMissingRevocations(dbxHashes)
	status := "SAFE"
	if len(missing) > 0 {
		status = worstRevocationSeverity(missing)
	}
	var qw []model.QualityWarning
	for _, r := range missing {
		qw = append(qw, model.QualityWarning{
			Code:     "DBX-MISSING",
			Severity: r.Severity,
			Message:  r.Description + " — revocation hash missing from dbx",
			CVE:      r.CVE,
		})
	}
	evidence := fmt.Sprintf("%d entries; missing %d CVE revocations", len(entries), len(missing))
	return emitUEFIFinding(ctx, findings, varRoot, fullName,
		"efivars-dbx", evidence, "UEFI-dbx", status, "Revocation list", qw)
}

func worstRevocationSeverity(missing []crypto.UEFIRevocation) string {
	rank := map[string]int{"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
	best := 0
	for _, r := range missing {
		if rank[r.Severity] > best {
			best = rank[r.Severity]
		}
	}
	switch best {
	case 3:
		return "UNSAFE"
	case 2:
		return "DEPRECATED"
	case 1:
		return "TRANSITIONAL"
	}
	return "SAFE"
}

func emitUEFIFinding(ctx context.Context, findings chan<- *model.Finding,
	varRoot, varName, method, evidence, algo, status, function string,
	qw []model.QualityWarning,
) error {
	asset := &model.CryptoAsset{
		ID:              uuid.New().String(),
		Algorithm:       algo,
		Library:         "UEFI",
		Language:        "Firmware",
		Function:        function,
		PQCStatus:       status,
		QualityWarnings: qw,
	}
	f := &model.Finding{
		ID:       uuid.New().String(),
		Category: int(model.CategoryPassiveFile),
		Source: model.FindingSource{
			Type:            "file",
			Path:            varRoot + "/" + varName,
			DetectionMethod: method,
			Evidence:        evidence,
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "uefi",
		Timestamp:   time.Now().UTC(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case findings <- f:
		return nil
	}
}

func emitUEFISkipped(ctx context.Context, findings chan<- *model.Finding, reason string) error {
	return emitUEFIFinding(ctx, findings, "", "", "uefi-skipped", "uefi scan error: "+reason,
		"N/A", "", "UEFI scanning", nil)
}
