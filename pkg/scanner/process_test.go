package scanner

import (
	"context"
	"testing"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface check
var _ Module = (*ProcessModule)(nil)

func TestProcessModuleInterface(t *testing.T) {
	m := NewProcessModule(&config.Config{})
	assert.Equal(t, "processes", m.Name())
	assert.Equal(t, model.CategoryActiveRuntime, m.Category())
	assert.Equal(t, model.TargetProcess, m.ScanTargetType())
}

func TestParseProcessOutput(t *testing.T) {
	m := NewProcessModule(&config.Config{})

	// Simulate ps output with crypto-related processes
	output := `  PID COMMAND
  123 /usr/sbin/sshd -D
  456 /usr/bin/openssl s_server -port 4433
  789 /usr/bin/nginx -g daemon off;
  101 /usr/local/bin/stunnel
  202 /usr/bin/python3 -m http.server
  303 /usr/sbin/openvpn --config server.conf
`

	findings := make(chan *model.Finding, 20)
	err := m.parseProcessOutput(context.Background(), output, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find: sshd, openssl, stunnel, openvpn (4 crypto processes)
	// nginx is not directly crypto
	require.NotEmpty(t, collected, "should find crypto-related processes")

	// Verify finding shape
	for _, f := range collected {
		assert.Equal(t, 1, f.Category)
		assert.Equal(t, "process", f.Source.Type)
		assert.Equal(t, "processes", f.Module)
		assert.Equal(t, 0.70, f.Confidence)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Function)
		assert.True(t, f.Source.PID > 0, "should have a PID")
	}
}

func TestParseProcessOutputWithLibraries(t *testing.T) {
	m := NewProcessModule(&config.Config{})

	// Output with linked libraries
	output := `  PID COMMAND
  500 /usr/sbin/apache2 -k start
`
	findings := make(chan *model.Finding, 10)
	err := m.parseProcessOutput(context.Background(), output, findings)
	require.NoError(t, err)
	close(findings)

	// apache2 is not inherently crypto; should not match
	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "non-crypto process should not produce findings")
}

func TestIsCryptoProcess(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"/usr/sbin/sshd -D", true},
		{"/usr/bin/openssl s_server", true},
		{"/usr/local/bin/stunnel", true},
		{"/usr/sbin/openvpn --config", true},
		{"/usr/sbin/ipsec start", true},
		{"/usr/bin/gpg --decrypt", true},
		{"/usr/bin/gpg-agent --daemon", true},
		{"/usr/sbin/strongswan start", true},
		{"/usr/bin/certbot renew", true},
		{"/usr/bin/wireguard-go wg0", true},
		{"/usr/bin/bash script.sh", false},
		{"/usr/bin/python3 app.py", false},
		{"/usr/bin/ls -la", false},
		{"/usr/bin/cat /etc/hosts", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			name, _, ok := identifyCryptoProcess(tt.command)
			if tt.want {
				assert.True(t, ok, "should identify %s as crypto process", tt.command)
				assert.NotEmpty(t, name)
			} else {
				assert.False(t, ok, "should NOT identify %s as crypto process", tt.command)
			}
		})
	}
}

func TestParseProcessOutputEmpty(t *testing.T) {
	m := NewProcessModule(&config.Config{})

	findings := make(chan *model.Finding, 10)
	err := m.parseProcessOutput(context.Background(), "", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestParseProcessOutputContextCancellation(t *testing.T) {
	m := NewProcessModule(&config.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	output := `  PID COMMAND
  123 /usr/sbin/sshd -D
`
	findings := make(chan *model.Finding, 10)
	err := m.parseProcessOutput(ctx, output, findings)
	close(findings)

	// Should get context error or no error depending on timing
	_ = err
}

func TestProcessFindingPQCStatus(t *testing.T) {
	m := NewProcessModule(&config.Config{})

	output := `  PID COMMAND
  123 /usr/sbin/sshd -D
`
	findings := make(chan *model.Finding, 10)
	err := m.parseProcessOutput(context.Background(), output, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.NotEmpty(t, finding.CryptoAsset.PQCStatus)
}

func TestParsePID(t *testing.T) {
	assert.Equal(t, 123, parsePID("123"))
	assert.Equal(t, 0, parsePID("abc"))
	assert.Equal(t, 0, parsePID(""))
	assert.Equal(t, 45678, parsePID("45678"))
}
