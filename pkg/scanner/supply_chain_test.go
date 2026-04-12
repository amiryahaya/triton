package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsSupplyChainFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// SLSA provenance
		{"/repo/artifact.slsa.json", true},
		{"/build/output.slsa.jsonl", true},
		{"provenance.slsa.json", true},

		// in-toto
		{"/repo/step1.link", true},
		{"/repo/layout.json", false}, // too generic without in-toto path
		{"/repo/.in-toto/layout.json", true},
		{"/repo/.in-toto/root.layout", true},

		// Fulcio / Sigstore trust roots
		{"/etc/sigstore/root.json", true},
		{"/etc/sigstore/targets/fulcio_v1.crt.pem", true},
		{"/home/user/.sigstore/root.json", true},
		{"trusted_root.json", true},

		// GitHub Actions OIDC
		{".github/workflows/release.yml", true},
		{".github/workflows/ci.yaml", true},

		// Not supply chain
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/data.json", false},
		{"/repo/README.md", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isSupplyChainFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- SLSA provenance parser tests ---

func TestParseSLSA_V1(t *testing.T) {
	prov := `{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://actions.github.io/buildtypes/workflow/v1"
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/actions/runner"
      }
    }
  }
}
`
	m := &SupplyChainModule{}
	findings := m.parseSLSAProvenance("/repo/artifact.slsa.json", []byte(prov))
	require.NotEmpty(t, findings)
	assert.Equal(t, "SLSA provenance attestation", findings[0].CryptoAsset.Function)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "slsa.dev/provenance")
}

func TestParseSLSA_V02(t *testing.T) {
	prov := `{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/slsa-framework/slsa-github-generator"
    },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1"
  }
}
`
	m := &SupplyChainModule{}
	findings := m.parseSLSAProvenance("/repo/artifact.slsa.json", []byte(prov))
	require.NotEmpty(t, findings)
}

func TestParseSLSA_NotSLSA(t *testing.T) {
	prov := `{"key": "value"}`
	m := &SupplyChainModule{}
	findings := m.parseSLSAProvenance("/repo/artifact.slsa.json", []byte(prov))
	assert.Empty(t, findings)
}

// --- in-toto link tests ---

func TestParseInTotoLink(t *testing.T) {
	link := `{
  "_type": "link",
  "name": "build",
  "signatures": [
    {
      "keyid": "abc123",
      "sig": "deadbeef",
      "method": "ed25519"
    }
  ]
}
`
	m := &SupplyChainModule{}
	findings := m.parseInTotoLink("/repo/step1.link", []byte(link))
	require.NotEmpty(t, findings)
	assert.Equal(t, "in-toto link signature", findings[0].CryptoAsset.Function)
	assert.Equal(t, "Ed25519", findings[0].CryptoAsset.Algorithm)
}

func TestParseInTotoLink_RSA(t *testing.T) {
	link := `{
  "_type": "link",
  "signatures": [
    {"keyid": "xyz", "sig": "aabbcc", "method": "rsassa-pss-sha256"}
  ]
}
`
	m := &SupplyChainModule{}
	findings := m.parseInTotoLink("/repo/step.link", []byte(link))
	require.NotEmpty(t, findings)
	assert.Equal(t, "RSA-PSS", findings[0].CryptoAsset.Algorithm)
}

func TestParseInTotoLink_NoSignatures(t *testing.T) {
	link := `{"_type": "link", "name": "test"}`
	m := &SupplyChainModule{}
	findings := m.parseInTotoLink("/repo/step.link", []byte(link))
	assert.Empty(t, findings)
}

// --- Sigstore / Fulcio trust root tests ---

func TestParseSigstoreTrustRoot(t *testing.T) {
	root := `{
  "signed": {
    "_type": "root",
    "spec_version": "1.0.0",
    "keys": {
      "abc123": {
        "keytype": "ecdsa-sha2-nistp256",
        "scheme": "ecdsa-sha2-nistp256",
        "keyval": {"public": "MFkwEwYH..."}
      },
      "def456": {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": "abc..."}
      }
    }
  }
}
`
	m := &SupplyChainModule{}
	findings := m.parseSigstoreTrustRoot("/etc/sigstore/root.json", []byte(root))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["ECDSA-P256"])
	assert.True(t, algoSet["Ed25519"])
}

func TestParseSigstoreTrustRoot_NotTUF(t *testing.T) {
	root := `{"some": "json"}`
	m := &SupplyChainModule{}
	findings := m.parseSigstoreTrustRoot("/etc/sigstore/root.json", []byte(root))
	assert.Empty(t, findings)
}

// --- GitHub Actions OIDC tests ---

func TestParseGHAWorkflow_OIDC(t *testing.T) {
	wf := `name: Release
on:
  push:
    tags: ['v*']

permissions:
  id-token: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1
`
	m := &SupplyChainModule{}
	findings := m.parseGHAWorkflow(".github/workflows/release.yml", []byte(wf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["GitHub Actions OIDC token"])
	assert.True(t, funcSet["Sigstore cosign usage"])
}

func TestParseGHAWorkflow_NoCrypto(t *testing.T) {
	wf := `name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...
`
	m := &SupplyChainModule{}
	findings := m.parseGHAWorkflow(".github/workflows/ci.yml", []byte(wf))
	assert.Empty(t, findings)
}

func TestParseGHAWorkflow_SLSAGenerator(t *testing.T) {
	wf := `name: Build
on: push
jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
`
	m := &SupplyChainModule{}
	findings := m.parseGHAWorkflow(".github/workflows/build.yml", []byte(wf))
	require.NotEmpty(t, findings)

	found := false
	for _, f := range findings {
		if f.CryptoAsset.Function == "SLSA provenance generator" {
			found = true
		}
	}
	assert.True(t, found)
}

// --- module interface ---

func TestSupplyChainModuleInterface(t *testing.T) {
	m := NewSupplyChainModule(nil)
	assert.Equal(t, "supply_chain", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
