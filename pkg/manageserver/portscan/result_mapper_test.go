package portscan_test

import (
	"testing"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/portscan"
)

func TestMapToScanResult_TLSCert(t *testing.T) {
	nb := time.Now().Add(-24 * time.Hour)
	na := time.Now().Add(30 * 24 * time.Hour)
	findings := []portscan.Finding{
		{
			IP:   "10.0.0.1",
			Port: 443,
			TLSCert: &portscan.TLSCertInfo{
				Subject:   "CN=example.com",
				Algorithm: "RSA",
				KeyBits:   2048,
				NotBefore: nb,
				NotAfter:  na,
				SANs:      []string{"example.com"},
			},
		},
	}
	result := portscan.MapToScanResult("web-01", "standard", findings)
	require.NotNil(t, result)
	assert.Equal(t, "web-01", result.Metadata.Hostname)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "RSA", result.Findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, 2048, result.Findings[0].CryptoAsset.KeySize)
}

func TestMapToScanResult_SSHService(t *testing.T) {
	findings := []portscan.Finding{
		{
			IP:   "10.0.0.1",
			Port: 22,
			Service: &plugins.Service{
				Protocol: "ssh",
				Version:  "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
			},
		},
	}
	result := portscan.MapToScanResult("db-01", "quick", findings)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "SSH", result.Findings[0].CryptoAsset.Algorithm)
}

func TestMapToScanResult_Empty(t *testing.T) {
	result := portscan.MapToScanResult("host", "quick", nil)
	assert.NotNil(t, result)
	assert.Len(t, result.Findings, 0)
}
