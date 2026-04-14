package juniper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSSHConfig(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "ssh_config.xml"))
	require.NoError(t, err)

	findings, err := parseSSHConfig("core-srx-1", data)
	require.NoError(t, err)

	// Expect 3 ciphers + 2 MACs + 1 KEX = 6 findings
	assert.Len(t, findings, 6)

	// Verify all have the correct hostname
	for _, f := range findings {
		assert.Equal(t, "core-srx-1", f.Source.Path)
	}

	// Verify module distribution
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Module]++
	}
	assert.Equal(t, 3, counts["juniper-ssh-cipher"])
	assert.Equal(t, 2, counts["juniper-ssh-mac"])
	assert.Equal(t, 1, counts["juniper-ssh-kex"])
}

func TestParseSSHConfig_EmptyXML(t *testing.T) {
	_, err := parseSSHConfig("host", []byte{})
	assert.Error(t, err)
}
