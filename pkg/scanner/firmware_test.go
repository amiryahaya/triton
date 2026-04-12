package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- EFI variable parser tests ---

func TestParseEFIVars(t *testing.T) {
	// Simulate /sys/firmware/efi/efivars/ directory listing
	vars := []string{
		"PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		"KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		"db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
		"dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
	}
	m := &FirmwareModule{}
	findings := m.parseEFIVarNames(vars)
	require.Len(t, findings, 4)

	functions := make(map[string]bool)
	for _, f := range findings {
		functions[f.CryptoAsset.Function] = true
		assert.Equal(t, "firmware", f.Module)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "efi-variable", f.Source.DetectionMethod)
	}
	assert.True(t, functions["Secure Boot Platform Key (PK)"])
	assert.True(t, functions["Secure Boot Key Exchange Key (KEK)"])
	assert.True(t, functions["Secure Boot signature database (db)"])
	assert.True(t, functions["Secure Boot forbidden signatures (dbx)"])
}

func TestParseEFIVars_Empty(t *testing.T) {
	m := &FirmwareModule{}
	findings := m.parseEFIVarNames(nil)
	assert.Empty(t, findings)
}

func TestParseEFIVars_NonSecureBoot(t *testing.T) {
	// EFI vars that aren't Secure Boot related
	vars := []string{
		"BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		"Lang-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	}
	m := &FirmwareModule{}
	findings := m.parseEFIVarNames(vars)
	assert.Empty(t, findings)
}

// --- mokutil parser tests ---

func TestParseMokutil(t *testing.T) {
	output := `[key 1]
SHA1 Fingerprint: ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12
        Issuer: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Corporation UEFI CA 2011
        Subject: C = US, ST = Washington, L = Redmond, O = Microsoft Corporation, CN = Microsoft Windows Production PCA 2011
        Signature Algorithm: sha256WithRSAEncryption
[key 2]
SHA1 Fingerprint: 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44
        Issuer: CN = Custom MOK Signer
        Subject: CN = Custom MOK Signer
        Signature Algorithm: sha384WithRSAEncryption
`
	m := &FirmwareModule{}
	findings := m.parseMokutilOutput(output)
	require.Len(t, findings, 2)

	assert.Equal(t, "RSA", findings[0].CryptoAsset.Algorithm)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "sha256WithRSAEncryption")

	assert.Equal(t, "RSA", findings[1].CryptoAsset.Algorithm)
	assert.Contains(t, findings[1].CryptoAsset.Purpose, "sha384WithRSAEncryption")
}

func TestParseMokutil_ECDSA(t *testing.T) {
	output := `[key 1]
        Signature Algorithm: ecdsa-with-SHA256
`
	m := &FirmwareModule{}
	findings := m.parseMokutilOutput(output)
	require.Len(t, findings, 1)
	assert.Equal(t, "ECDSA", findings[0].CryptoAsset.Algorithm)
}

func TestParseMokutil_Empty(t *testing.T) {
	m := &FirmwareModule{}
	findings := m.parseMokutilOutput("")
	assert.Empty(t, findings)
}

// --- TPM parser tests ---

func TestParseTPMVersion(t *testing.T) {
	// /sys/class/tpm/tpm0/tpm_version_major contains "2" for TPM 2.0
	m := &FirmwareModule{}
	findings := m.parseTPMInfo("2", true)
	require.Len(t, findings, 1)
	assert.Equal(t, "TPM 2.0", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "Trusted Platform Module", findings[0].CryptoAsset.Function)
}

func TestParseTPMVersion_1_2(t *testing.T) {
	m := &FirmwareModule{}
	findings := m.parseTPMInfo("1", false)
	require.Len(t, findings, 1)
	assert.Equal(t, "TPM 1.2", findings[0].CryptoAsset.Algorithm)
}

func TestParseTPMVersion_None(t *testing.T) {
	m := &FirmwareModule{}
	findings := m.parseTPMInfo("", false)
	assert.Empty(t, findings)
}

// --- module interface tests ---

func TestFirmwareModuleInterface(t *testing.T) {
	m := NewFirmwareModule(nil)
	assert.Equal(t, "firmware", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}

// --- command runner mock tests ---

func TestFirmwareScan_MockAll(t *testing.T) {
	origCmd := firmwareCmdRunner
	origReadDir := firmwareReadDir
	origReadFile := firmwareReadFile
	defer func() {
		firmwareCmdRunner = origCmd
		firmwareReadDir = origReadDir
		firmwareReadFile = origReadFile
	}()

	firmwareCmdRunner = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "mokutil" {
			return []byte(`[key 1]
        Signature Algorithm: sha256WithRSAEncryption
`), nil
		}
		return nil, fmt.Errorf("not found")
	}

	firmwareReadDir = func(name string) ([]string, error) {
		if name == "/sys/firmware/efi/efivars" {
			return []string{"PK-8be4df61-93ca-11d2-aa0d-00e098032b8c"}, nil
		}
		return nil, fmt.Errorf("not found")
	}

	firmwareReadFile = func(name string) (string, error) {
		if name == "/sys/class/tpm/tpm0/tpm_version_major" {
			return "2", nil
		}
		return "", fmt.Errorf("not found")
	}

	m := NewFirmwareModule(nil)
	findings := make(chan *model.Finding, 100)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: "/"}, findings)
	close(findings)
	require.NoError(t, err)

	var all []*model.Finding
	for f := range findings {
		all = append(all, f)
	}
	// Should have: 1 EFI var + 1 MOK key + 1 TPM = 3
	require.Len(t, all, 3)
}

func TestFirmwareScan_NoEFI(t *testing.T) {
	origCmd := firmwareCmdRunner
	origReadDir := firmwareReadDir
	origReadFile := firmwareReadFile
	defer func() {
		firmwareCmdRunner = origCmd
		firmwareReadDir = origReadDir
		firmwareReadFile = origReadFile
	}()

	firmwareCmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}
	firmwareReadDir = func(_ string) ([]string, error) {
		return nil, fmt.Errorf("not found")
	}
	firmwareReadFile = func(_ string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	m := NewFirmwareModule(nil)
	findings := make(chan *model.Finding, 100)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: "/"}, findings)
	close(findings)
	require.NoError(t, err)

	var all []*model.Finding
	for f := range findings {
		all = append(all, f)
	}
	assert.Empty(t, all)
}
