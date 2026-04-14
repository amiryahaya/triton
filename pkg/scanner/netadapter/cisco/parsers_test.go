package cisco

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseShowIPSSH(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "show_ip_ssh.txt"))
	require.NoError(t, err)

	findings := parseShowIPSSH("edge-rtr-1", string(data))
	require.NotEmpty(t, findings, "expected at least one finding")

	// Count findings per module
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Module]++
	}

	assert.GreaterOrEqual(t, counts["cisco-ssh-cipher"], 1, "expected cipher findings")
	assert.GreaterOrEqual(t, counts["cisco-ssh-mac"], 1, "expected MAC findings")
	assert.GreaterOrEqual(t, counts["cisco-ssh-kex"], 1, "expected KEX findings")
}

func TestParseShowIPSSH_Source(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "show_ip_ssh.txt"))
	require.NoError(t, err)

	findings := parseShowIPSSH("core-sw-2", string(data))
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, "network-device", f.Source.Type)
		assert.Equal(t, "core-sw-2", f.Source.Path)
		assert.Equal(t, 1.0, f.Confidence)
		require.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
		assert.NotEmpty(t, f.CryptoAsset.Purpose)
	}
}

func TestParseShowIPSSH_AllAlgos(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "show_ip_ssh.txt"))
	require.NoError(t, err)

	findings := parseShowIPSSH("rtr-1", string(data))

	algos := map[string]bool{}
	for _, f := range findings {
		if f.CryptoAsset != nil {
			algos[f.CryptoAsset.Algorithm] = true
		}
	}

	// Cipher algorithms from fixture
	assert.True(t, algos["aes128-ctr"], "aes128-ctr should be found")
	assert.True(t, algos["aes256-ctr"], "aes256-ctr should be found")

	// MAC algorithms from fixture
	assert.True(t, algos["hmac-sha2-256"], "hmac-sha2-256 should be found")
	assert.True(t, algos["hmac-sha1"], "hmac-sha1 should be found")

	// KEX algorithms from fixture
	assert.True(t, algos["diffie-hellman-group14-sha1"], "dh-group14-sha1 should be found")
	assert.True(t, algos["ecdh-sha2-nistp256"], "ecdh-sha2-nistp256 should be found")
}

func TestParseShowIPSSH_EmptyOutput(t *testing.T) {
	findings := parseShowIPSSH("rtr-1", "")
	assert.Empty(t, findings, "empty output should yield no findings")
}

func TestStubParsers(t *testing.T) {
	assert.Nil(t, parseShowCryptoPKI("h", "output"))
	assert.Nil(t, parseShowIsakmpPolicy("h", "output"))
	assert.Nil(t, parseShowCryptoIPsec("h", "output"))
	assert.Nil(t, parseShowSNMP("h", "output"))
}
