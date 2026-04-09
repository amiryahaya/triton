package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*HSMModule)(nil)

func TestHSMModule_Name(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	assert.Equal(t, "hsm", m.Name())
}

func TestHSMModule_Category(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	assert.Equal(t, model.CategoryActiveRuntime, m.Category())
}

func TestHSMModule_ScanTargetType(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	assert.Equal(t, model.TargetHSM, m.ScanTargetType())
}

func TestHSMModule_ParseListSlots(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	output := `Available slots:
Slot 0 (0x0): SoftHSM slot ID 0x0
  token label        : My Token
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized
Slot 1 (0x1): SoftHSM slot ID 0x1
  token label        : HSM Token 2
  token manufacturer : Thales
  token model        : nShield
  token flags        : login required, rng, token initialized
`

	slots := m.parseListSlots(output)
	require.Len(t, slots, 2)

	assert.Equal(t, "0", slots[0].slotID)
	assert.Equal(t, "My Token", slots[0].tokenLabel)
	assert.Equal(t, "SoftHSM project", slots[0].manufacturer)
	assert.Equal(t, "SoftHSM v2", slots[0].model)

	assert.Equal(t, "1", slots[1].slotID)
	assert.Equal(t, "HSM Token 2", slots[1].tokenLabel)
	assert.Equal(t, "Thales", slots[1].manufacturer)
	assert.Equal(t, "nShield", slots[1].model)
}

func TestHSMModule_ParseListObjects_RSA(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	output := `Private Key Object; RSA
  label:      my-rsa-key
  ID:         01
  Usage:      decrypt, sign
  Access:     sensitive, always sensitive, never extractable
Public Key Object; RSA 2048 bits
  label:      my-rsa-key
  ID:         01
  Usage:      encrypt, verify
`

	objects := m.parseListObjects(output)
	require.Len(t, objects, 2)

	assert.Equal(t, "Private Key", objects[0].objectType)
	assert.Equal(t, "RSA", objects[0].algorithm)
	assert.Equal(t, "my-rsa-key", objects[0].label)
	assert.Equal(t, "01", objects[0].id)

	assert.Equal(t, "Public Key", objects[1].objectType)
	assert.Equal(t, "RSA", objects[1].algorithm)
	assert.Equal(t, 2048, objects[1].keySize)
	assert.Equal(t, "my-rsa-key", objects[1].label)
}

func TestHSMModule_ParseListObjects_EC(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	output := `Private Key Object; EC
  label:      my-ec-key
  ID:         02
  Usage:      sign
Public Key Object; EC 256 bits
  label:      my-ec-key
  ID:         02
  Usage:      verify
`

	objects := m.parseListObjects(output)
	require.Len(t, objects, 2)

	assert.Equal(t, "Private Key", objects[0].objectType)
	assert.Equal(t, "EC", objects[0].algorithm)

	assert.Equal(t, "Public Key", objects[1].objectType)
	assert.Equal(t, "EC", objects[1].algorithm)
	assert.Equal(t, 256, objects[1].keySize)
}

func TestHSMModule_ParseListObjects_AES(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	output := `Secret Key Object; AES
  label:      my-aes-key
  ID:         03
  Usage:      encrypt, decrypt
  Access:     sensitive, always sensitive, never extractable
`

	objects := m.parseListObjects(output)
	require.Len(t, objects, 1)

	assert.Equal(t, "Secret Key", objects[0].objectType)
	assert.Equal(t, "AES", objects[0].algorithm)
	assert.Equal(t, "my-aes-key", objects[0].label)
	assert.Equal(t, "03", objects[0].id)
}

func TestHSMModule_ParseListObjects_Cert(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	output := `Certificate Object; type = X.509 cert
  label:      my-cert
  subject:    DN: CN=example.com
  ID:         04
`

	objects := m.parseListObjects(output)
	require.Len(t, objects, 1)

	assert.Equal(t, "Certificate", objects[0].objectType)
	assert.Equal(t, "X.509", objects[0].algorithm)
	assert.Equal(t, "my-cert", objects[0].label)
	assert.Equal(t, "04", objects[0].id)
}

func TestHSMModule_ParseListMechanisms(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	output := `Supported mechanisms:
  RSA-PKCS, keySize={1024,4096}, sign, verify, decrypt, encrypt
  RSA-PKCS-OAEP, keySize={1024,4096}, encrypt, decrypt
  SHA256-RSA-PKCS, keySize={1024,4096}, sign, verify
  ECDSA, keySize={256,521}, sign, verify
  AES-CBC, keySize={16,32}, encrypt, decrypt
`

	mechs := m.parseListMechanisms(output)
	require.Len(t, mechs, 5)

	assert.Equal(t, "RSA-PKCS", mechs[0].name)
	assert.Equal(t, 1024, mechs[0].minKeySize)
	assert.Equal(t, 4096, mechs[0].maxKeySize)
	assert.Contains(t, mechs[0].operations, "sign")

	assert.Equal(t, "ECDSA", mechs[3].name)
	assert.Equal(t, 256, mechs[3].minKeySize)
	assert.Equal(t, 521, mechs[3].maxKeySize)

	assert.Equal(t, "AES-CBC", mechs[4].name)
	assert.Equal(t, 16, mechs[4].minKeySize)
	assert.Equal(t, 32, mechs[4].maxKeySize)
}

func TestHSMModule_NoPkcs11Tool(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("exec: pkcs11-tool: not found")
	}

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetHSM, Value: "/some/module.so"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)

	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "no findings when pkcs11-tool is unavailable")
}

func TestHSMModule_NoModulesFound(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetHSM, Value: "auto"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)

	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "no findings when no PKCS#11 modules found")
}

func TestHSMModule_ContextCancellation(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(""), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetHSM, Value: "auto"}
	err := m.Scan(ctx, target, findings)
	close(findings)

	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
}

func TestHSMModule_FindingClassification(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	// Create a mock that returns RSA-2048 key
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		for _, arg := range args {
			if arg == "--list-objects" {
				return []byte(`Public Key Object; RSA 2048 bits
  label:      test-key
  ID:         01
`), nil
			}
		}
		return []byte(""), nil
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetHSM, Value: "/usr/lib/softhsm/libsofthsm2.so"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)
	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Find the object finding (not slot/mechanism)
	var objFinding *model.Finding
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "HSM public key" {
			objFinding = f
			break
		}
	}

	require.NotNil(t, objFinding, "should have HSM public key finding")
	assert.Equal(t, 5, objFinding.Category)
	assert.Equal(t, "hsm", objFinding.Module)
	assert.Equal(t, 0.95, objFinding.Confidence)
	assert.NotEmpty(t, objFinding.CryptoAsset.PQCStatus, "RSA-2048 should have PQC classification")
	assert.Equal(t, 2048, objFinding.CryptoAsset.KeySize)
}

func TestHSMModule_MechanismClassification(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		for _, arg := range args {
			if arg == "--list-mechanisms" {
				return []byte(`Supported mechanisms:
  RSA-PKCS, keySize={1024,4096}, sign, verify
  AES-CBC, keySize={16,32}, encrypt, decrypt
`), nil
			}
		}
		return []byte(""), nil
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetHSM, Value: "/usr/lib/softhsm/libsofthsm2.so"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)
	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Find mechanism findings
	var mechFindings []*model.Finding
	for _, f := range collected {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "HSM supported algorithm" {
			mechFindings = append(mechFindings, f)
		}
	}

	require.Len(t, mechFindings, 2, "should have 2 mechanism findings")
	for _, f := range mechFindings {
		assert.Equal(t, 5, f.Category)
		assert.Equal(t, 0.85, f.Confidence)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
	}
}

func TestHSMModule_ExplicitModule(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})

	var cmdsRun []string
	m.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmdsRun = append(cmdsRun, name)
		return []byte(""), nil
	}

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetHSM, Value: "/custom/path/to/module.so"}
	err := m.Scan(context.Background(), target, findings)
	close(findings)
	require.NoError(t, err)

	// Should have called pkcs11-tool directly (not checked paths)
	assert.Contains(t, cmdsRun, "pkcs11-tool")
}

func TestHSMModule_ParseListSlotsEmpty(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	slots := m.parseListSlots("")
	assert.Empty(t, slots)
}

func TestHSMModule_ParseListObjectsEmpty(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	objects := m.parseListObjects("")
	assert.Empty(t, objects)
}

func TestHSMModule_ParseListMechanismsEmpty(t *testing.T) {
	t.Parallel()
	m := NewHSMModule(&config.Config{})
	mechs := m.parseListMechanisms("")
	assert.Empty(t, mechs)
}

func TestNormalizeHSMAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		expected string
	}{
		{"RSA-PKCS", "RSA"},
		{"RSA-PKCS-OAEP", "RSA"},
		{"ECDSA", "ECDSA"},
		{"AES-CBC", "AES"},
		{"AES-GCM", "AES"},
		{"SHA256-RSA-PKCS", "SHA256withRSA"},
		{"EC", "ECDSA"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeHSMAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
