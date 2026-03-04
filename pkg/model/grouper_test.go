package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupFindingsIntoSystemsWithAgility(t *testing.T) {
	findings := []Finding{
		{
			ID:     "f1",
			Source: FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "AES-256",
				Function:  "Encryption",
			},
			Module: "libraries",
		},
	}

	called := false
	agilityFn := func(asset *CryptoAsset) string {
		called = true
		return "high-agility"
	}

	systems := GroupFindingsIntoSystemsWithAgility(findings, agilityFn)
	assert.True(t, called, "agilityFn should be called")
	require.NotEmpty(t, systems)

	// Verify agility was set on at least one asset
	found := false
	for _, sys := range systems {
		for _, comp := range sys.CryptoAssets {
			if comp.CryptoAgility == "high-agility" {
				found = true
			}
		}
	}
	assert.True(t, found, "CryptoAgility should be set by agilityFn")
}

func TestGroupFindingsIntoSystems_NilAgility(t *testing.T) {
	findings := []Finding{
		{
			ID:          "f1",
			Source:      FindingSource{Type: "file", Path: "/test/cert.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "RSA-2048"},
			Module:      "certificates",
		},
	}

	// Without agility function, CryptoAgility should remain empty
	systems := GroupFindingsIntoSystems(findings)
	require.NotEmpty(t, systems)
	for _, sys := range systems {
		for _, asset := range sys.CryptoAssets {
			assert.Empty(t, asset.CryptoAgility, "CryptoAgility should be empty without agilityFn")
		}
	}
}

func TestGroupFindingsIntoSystems_Empty(t *testing.T) {
	systems := GroupFindingsIntoSystems([]Finding{})
	assert.Nil(t, systems, "empty findings should return nil")
}

func TestGroupFindingsIntoSystems_NilCryptoAsset(t *testing.T) {
	findings := []Finding{
		{
			ID:          "f1",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: nil, // findings without a crypto asset are skipped
			Module:      "certificates",
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	assert.Empty(t, systems, "findings with nil CryptoAsset should produce no systems")
}

func TestGroupFindingsIntoSystems_NetworkGrouping(t *testing.T) {
	findings := []Finding{
		{
			ID:     "f1",
			Source: FindingSource{Type: "network", Endpoint: "192.168.1.1:443"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "RSA-2048",
				Function:  "TLS handshake",
			},
			Module: "protocol",
		},
		{
			ID:     "f2",
			Source: FindingSource{Type: "network", Endpoint: "192.168.1.1:443"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "AES-256-GCM",
				Function:  "TLS session",
			},
			Module: "protocol",
		},
		{
			ID:     "f3",
			Source: FindingSource{Type: "network", Endpoint: "10.0.0.1:22"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "ECDSA-256",
				Function:  "SSH authentication",
			},
			Module: "protocol",
		},
	}

	systems := GroupFindingsIntoSystems(findings)

	// Two different endpoints → two systems
	require.Len(t, systems, 2)

	// The first system (192.168.1.1:443) should have 2 assets
	assert.Len(t, systems[0].CryptoAssets, 2)
	assert.Equal(t, "192.168.1.1:443", systems[0].URL)

	// The second system (10.0.0.1:22) should have 1 asset
	assert.Len(t, systems[1].CryptoAssets, 1)
	assert.Equal(t, "10.0.0.1:22", systems[1].URL)
}

func TestGroupFindingsIntoSystems_ProcessGrouping(t *testing.T) {
	findings := []Finding{
		{
			ID:     "f1",
			Source: FindingSource{Type: "process", Path: "/usr/sbin/sshd -D"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "ECDSA-256",
			},
			Module: "process",
		},
		{
			ID:     "f2",
			Source: FindingSource{Type: "process", Path: "/usr/sbin/sshd"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "RSA-2048",
			},
			Module: "process",
		},
	}

	systems := GroupFindingsIntoSystems(findings)

	// Both are sshd → one system
	require.Len(t, systems, 1)
	assert.Len(t, systems[0].CryptoAssets, 2)
	assert.Contains(t, systems[0].Name, "sshd")
}

func TestGroupFindingsIntoSystems_FileGrouping(t *testing.T) {
	findings := []Finding{
		{
			ID:          "f1",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "RSA-2048"},
			Module:      "certificates",
		},
		{
			ID:          "f2",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/key.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "RSA-2048"},
			Module:      "keys",
		},
		{
			ID:          "f3",
			Source:      FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
			CryptoAsset: &CryptoAsset{Algorithm: "AES-256"},
			Module:      "libraries",
		},
	}

	systems := GroupFindingsIntoSystems(findings)

	// /etc/ssl and /usr/lib are different dirs → two systems
	require.Len(t, systems, 2)

	// First system: /etc/ssl (2 findings)
	assert.Len(t, systems[0].CryptoAssets, 2)

	// Second system: /usr/lib (1 finding)
	assert.Len(t, systems[1].CryptoAssets, 1)
}

func TestGroupFindingsIntoSystems_SystemName_TLSService(t *testing.T) {
	findings := []Finding{
		{
			ID:     "f1",
			Source: FindingSource{Type: "network", Endpoint: "example.com:443"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "RSA-2048",
				Function:  "TLS handshake",
			},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)
	assert.Contains(t, systems[0].Name, "TLS Service")
}

func TestGroupFindingsIntoSystems_SystemName_SSHService(t *testing.T) {
	findings := []Finding{
		{
			ID:     "f1",
			Source: FindingSource{Type: "network", Endpoint: "host:22"},
			CryptoAsset: &CryptoAsset{
				Algorithm: "ECDSA-256",
				Function:  "SSH host key",
			},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)
	assert.Contains(t, systems[0].Name, "SSH Service")
}

func TestGroupFindingsIntoSystems_CBOMRefs(t *testing.T) {
	findings := []Finding{
		{
			ID:          "f1",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "RSA-2048"},
		},
		{
			ID:          "f2",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/key.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "EC-256"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)

	// Two assets → range ref "CBOM #1 - CBOM #2"
	require.NotEmpty(t, systems[0].CBOMRefs)
	assert.Contains(t, systems[0].CBOMRefs[0], "CBOM #1")
	assert.Contains(t, systems[0].CBOMRefs[0], "CBOM #2")
}

func TestGroupFindingsIntoSystems_SingleAsset_CBOMRef(t *testing.T) {
	findings := []Finding{
		{
			ID:          "f1",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "RSA-2048"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)

	// Single asset → single ref "CBOM #1"
	require.NotEmpty(t, systems[0].CBOMRefs)
	assert.Equal(t, "CBOM #1", systems[0].CBOMRefs[0])
}

func TestGroupFindingsIntoSystems_Criticality(t *testing.T) {
	tests := []struct {
		name              string
		migrationPriority int
		expectedLabel     string
	}{
		{"very high priority", 80, "Sangat Tinggi"},
		{"high priority", 60, "Tinggi"},
		{"medium priority", 30, "Sederhana"},
		{"low priority", 10, "Rendah"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []Finding{
				{
					ID:     "f1",
					Source: FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
					CryptoAsset: &CryptoAsset{
						Algorithm:         "RSA-2048",
						MigrationPriority: tt.migrationPriority,
					},
				},
			}
			systems := GroupFindingsIntoSystems(findings)
			require.Len(t, systems, 1)
			assert.Equal(t, tt.expectedLabel, systems[0].CriticalityLevel)
		})
	}
}

func TestGroupFindingsIntoSystems_AgilityFnCalledPerAsset(t *testing.T) {
	findings := []Finding{
		{
			ID:          "f1",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "RSA-2048"},
		},
		{
			ID:          "f2",
			Source:      FindingSource{Type: "file", Path: "/etc/ssl/key.pem"},
			CryptoAsset: &CryptoAsset{Algorithm: "EC-256"},
		},
	}

	callCount := 0
	agilityFn := func(asset *CryptoAsset) string {
		callCount++
		return "medium-agility"
	}

	systems := GroupFindingsIntoSystemsWithAgility(findings, agilityFn)
	require.NotEmpty(t, systems)

	// agilityFn should be called once per crypto asset
	assert.Equal(t, 2, callCount, "agilityFn should be called once per asset")

	// All assets should have the agility label set
	for _, sys := range systems {
		for _, asset := range sys.CryptoAssets {
			assert.Equal(t, "medium-agility", asset.CryptoAgility)
		}
	}
}

func TestDeriveAppFromPath_MacOSAppBundle(t *testing.T) {
	app := DeriveAppFromPath("/Applications/Rider.app/Contents/lib/libcrypto.dylib")
	assert.Equal(t, "Rider", app)
}

func TestDeriveAppFromPath_MacOSFramework(t *testing.T) {
	app := DeriveAppFromPath("/System/Library/Frameworks/Security.framework/Versions/A/Security")
	assert.Equal(t, "Security", app)
}

func TestDeriveAppFromPath_HomebrewCellar(t *testing.T) {
	app := DeriveAppFromPath("/usr/local/Cellar/openssl@3/3.1.0/lib/libssl.dylib")
	assert.Equal(t, "openssl@3", app)
}

func TestDeriveAppFromPath_SnapPackage(t *testing.T) {
	app := DeriveAppFromPath("/snap/core20/1234/usr/lib/libssl.so")
	assert.Equal(t, "core20", app)
}

func TestDeriveAppFromPath_LinuxUsrLib(t *testing.T) {
	app := DeriveAppFromPath("/usr/lib/openssl/libcrypto.so")
	assert.Equal(t, "openssl", app)
}

func TestDeriveAppFromPath_UnknownPath(t *testing.T) {
	app := DeriveAppFromPath("/some/random/unknown/path.so")
	assert.Empty(t, app, "unknown paths should return empty string")
}
