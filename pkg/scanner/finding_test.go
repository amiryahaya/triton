package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestNewFinding(t *testing.T) {
	asset := &model.CryptoAsset{Algorithm: "AES-256"}
	source := model.FindingSource{Type: "file", Path: "/test"}

	f := newFinding("certificates", CategoryCert, source, asset, ConfidenceDefinitive)

	require.NotNil(t, f)
	assert.NotEmpty(t, f.ID, "should generate UUID")
	assert.Equal(t, CategoryCert, f.Category)
	assert.Equal(t, "file", f.Source.Type)
	assert.Equal(t, "/test", f.Source.Path)
	assert.Equal(t, asset, f.CryptoAsset)
	assert.Equal(t, ConfidenceDefinitive, f.Confidence)
	assert.Equal(t, "certificates", f.Module)
	assert.False(t, f.Timestamp.IsZero(), "should set timestamp")
}

func TestNewFinding_UniqueIDs(t *testing.T) {
	source := model.FindingSource{Type: "file"}
	f1 := newFinding("test", 1, source, nil, 0.5)
	f2 := newFinding("test", 1, source, nil, 0.5)
	assert.NotEqual(t, f1.ID, f2.ID, "each finding should have unique ID")
}

func TestCategoryConstants(t *testing.T) {
	assert.Equal(t, 1, CategoryRuntime)
	assert.Equal(t, 2, CategoryBinary)
	assert.Equal(t, 3, CategoryLibrary)
	assert.Equal(t, 4, CategoryKernel)
	assert.Equal(t, 5, CategoryCert)
	assert.Equal(t, 6, CategorySourceCode)
	assert.Equal(t, 7, CategoryWebApp)
	assert.Equal(t, 8, CategoryConfig)
	assert.Equal(t, 9, CategoryNetwork)
}

func TestConfidenceConstants(t *testing.T) {
	assert.Greater(t, ConfidenceDefinitive, ConfidenceHigh)
	assert.Greater(t, ConfidenceHigh, ConfidenceMedium)
	assert.Greater(t, ConfidenceMedium, ConfidenceMediumLow)
	assert.Greater(t, ConfidenceMediumLow, ConfidenceLow)
	assert.Greater(t, ConfidenceLow, ConfidenceSpeculative)
}
