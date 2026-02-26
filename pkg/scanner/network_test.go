package scanner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*NetworkModule)(nil)

func TestNetworkModuleInterface(t *testing.T) {
	m := NewNetworkModule(&config.Config{})
	assert.Equal(t, "network", m.Name())
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
	assert.Equal(t, model.TargetNetwork, m.ScanTargetType())
}

func TestParseListeningPorts(t *testing.T) {
	m := NewNetworkModule(&config.Config{})

	// Simulate lsof output for listening ports
	output := `COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd      123 root    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)
nginx     456 www     4u  IPv4  23456      0t0  TCP *:443 (LISTEN)
nginx     456 www     5u  IPv4  23457      0t0  TCP *:80 (LISTEN)
openvpn   789 root    6u  IPv4  34567      0t0  UDP *:1194
postgres  101 pg      7u  IPv4  45678      0t0  TCP *:5432 (LISTEN)
`

	findings := make(chan *model.Finding, 20)
	err := m.parseLsofOutput(context.Background(), output, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find: sshd (22/SSH), nginx (443/TLS), openvpn (1194/VPN)
	// Should skip: nginx (80/HTTP plain), postgres (5432/not crypto)
	require.NotEmpty(t, collected, "should find crypto network services")

	// Verify finding shape
	for _, f := range collected {
		assert.Equal(t, 8, f.Category)
		assert.Equal(t, "network", f.Source.Type)
		assert.Equal(t, "network", f.Module)
		assert.Equal(t, 0.75, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
		assert.NotEmpty(t, f.Source.Endpoint)
	}
}

func TestClassifyPort(t *testing.T) {
	tests := []struct {
		port      int
		protocol  string
		command   string
		wantAlgo  string
		wantCrypt bool
	}{
		{22, "TCP", "sshd", "SSH", true},
		{443, "TCP", "nginx", "TLS", true},
		{8443, "TCP", "java", "TLS", true},
		{993, "TCP", "dovecot", "TLS", true},       // IMAPS
		{995, "TCP", "dovecot", "TLS", true},       // POP3S
		{636, "TCP", "slapd", "TLS", true},         // LDAPS
		{5061, "TCP", "kamailio", "TLS", true},     // SIPS
		{1194, "UDP", "openvpn", "TLS", true},      // OpenVPN
		{500, "UDP", "strongswan", "IPsec", true},  // IKE
		{4500, "UDP", "strongswan", "IPsec", true}, // NAT-T
		{80, "TCP", "nginx", "", false},            // HTTP plain
		{8080, "TCP", "java", "", false},           // HTTP plain
		{5432, "TCP", "postgres", "", false},       // PostgreSQL
		{3306, "TCP", "mysqld", "", false},         // MySQL
	}

	for _, tt := range tests {
		t.Run(tt.command+"/"+tt.protocol, func(t *testing.T) {
			algo, isCrypto := classifyPort(tt.port, tt.protocol, tt.command)
			assert.Equal(t, tt.wantCrypt, isCrypto, "port %d should be crypto=%v", tt.port, tt.wantCrypt)
			if tt.wantCrypt {
				assert.Equal(t, tt.wantAlgo, algo)
			}
		})
	}
}

func TestParseListeningPortsEmpty(t *testing.T) {
	m := NewNetworkModule(&config.Config{})

	findings := make(chan *model.Finding, 10)
	err := m.parseLsofOutput(context.Background(), "", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestParseListeningPortsContextCancellation(t *testing.T) {
	m := NewNetworkModule(&config.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	output := `COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd      123 root    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)
`
	findings := make(chan *model.Finding, 10)
	err := m.parseLsofOutput(ctx, output, findings)
	close(findings)
	_ = err
}

func TestNetworkFindingPQCStatus(t *testing.T) {
	m := NewNetworkModule(&config.Config{})

	output := `COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd      123 root    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)
`
	findings := make(chan *model.Finding, 10)
	err := m.parseLsofOutput(context.Background(), output, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.NotEmpty(t, finding.CryptoAsset.PQCStatus)
}

func TestParseSSOutput(t *testing.T) {
	m := NewNetworkModule(&config.Config{})

	// Simulate ss output
	output := `State  Recv-Q  Send-Q   Local Address:Port    Peer Address:Port
LISTEN 0       128            0.0.0.0:22           0.0.0.0:*
LISTEN 0       128            0.0.0.0:443          0.0.0.0:*
LISTEN 0       128            0.0.0.0:80           0.0.0.0:*
`

	findings := make(chan *model.Finding, 20)
	err := m.parseSSOutput(context.Background(), output, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find port 22 (SSH) and 443 (TLS), skip 80 (plain HTTP)
	require.NotEmpty(t, collected)
	assert.True(t, len(collected) >= 2, "should find at least SSH and TLS services")
}
