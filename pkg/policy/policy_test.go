package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_Valid(t *testing.T) {
	yaml := `
version: "1"
name: "Test Policy"
rules:
  - id: no-unsafe
    severity: error
    condition:
      pqc_status: UNSAFE
    action: fail
thresholds:
  max_unsafe_count: 0
`
	p, err := Parse([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "1", p.Version)
	assert.Equal(t, "Test Policy", p.Name)
	assert.Len(t, p.Rules, 1)
	assert.Equal(t, "no-unsafe", p.Rules[0].ID)
	assert.Equal(t, "UNSAFE", p.Rules[0].Condition.PQCStatus)
	require.NotNil(t, p.Thresholds.MaxUnsafeCount)
	assert.Equal(t, 0, *p.Thresholds.MaxUnsafeCount)
}

func TestParse_MissingVersion(t *testing.T) {
	yaml := `name: "Test"`
	_, err := Parse([]byte(yaml))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestParse_MissingName(t *testing.T) {
	yaml := `version: "1"`
	_, err := Parse([]byte(yaml))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte("{{invalid"))
	assert.Error(t, err)
}

func TestParse_AllConditionFields(t *testing.T) {
	yaml := `
version: "1"
name: "Full Condition"
rules:
  - id: full
    severity: warning
    condition:
      pqc_status: DEPRECATED
      algorithm_family: RSA
      algorithm: RSA-1024
      key_size_below: 2048
      key_size_above: 4096
      module: certificates
      category: 2
    action: warn
`
	p, err := Parse([]byte(yaml))
	require.NoError(t, err)
	c := p.Rules[0].Condition
	assert.Equal(t, "DEPRECATED", c.PQCStatus)
	assert.Equal(t, "RSA", c.AlgorithmFamily)
	assert.Equal(t, "RSA-1024", c.Algorithm)
	assert.Equal(t, 2048, c.KeySizeBelow)
	assert.Equal(t, 4096, c.KeySizeAbove)
	assert.Equal(t, "certificates", c.Module)
	assert.Equal(t, 2, c.Category)
}

func TestLoadBuiltin_NACSA(t *testing.T) {
	p, err := LoadBuiltin("nacsa-2030")
	require.NoError(t, err)
	assert.Equal(t, "NACSA PQC Compliance 2030", p.Name)
	assert.True(t, len(p.Rules) > 0)
}

func TestLoadBuiltin_CNSA(t *testing.T) {
	p, err := LoadBuiltin("cnsa-2.0")
	require.NoError(t, err)
	assert.Equal(t, "CNSA 2.0 Commercial National Security Algorithm Suite", p.Name)
}

func TestLoadBuiltin_Unknown(t *testing.T) {
	_, err := LoadBuiltin("nonexistent")
	assert.Error(t, err)
	var unk *ErrUnknownPolicy
	assert.ErrorAs(t, err, &unk)
}

func TestListBuiltin(t *testing.T) {
	names := ListBuiltin()
	assert.Contains(t, names, "nacsa-2030")
	assert.Contains(t, names, "cnsa-2.0")
}
