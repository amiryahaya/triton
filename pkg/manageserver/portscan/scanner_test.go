package portscan_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/manageserver/portscan"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

func TestPortListSizes(t *testing.T) {
	quick := portscan.Ports(scanjobs.ProfileQuick)
	standard := portscan.Ports(scanjobs.ProfileStandard)
	comprehensive := portscan.Ports(scanjobs.ProfileComprehensive)

	assert.Greater(t, len(quick), 0)
	assert.Greater(t, len(standard), len(quick))
	assert.Greater(t, len(comprehensive), len(standard))
	assert.LessOrEqual(t, len(quick), 100)
	assert.LessOrEqual(t, len(standard), 1000)
	assert.LessOrEqual(t, len(comprehensive), 10000)
}

func TestNewScannerDefaults(t *testing.T) {
	quick := portscan.NewScanner(scanjobs.ProfileQuick)
	assert.Equal(t, 50, quick.Concurrency)
	assert.Equal(t, 3, quick.TimeoutSeconds)

	std := portscan.NewScanner(scanjobs.ProfileStandard)
	assert.Equal(t, 200, std.Concurrency)
	assert.Equal(t, 3, std.TimeoutSeconds)

	comp := portscan.NewScanner(scanjobs.ProfileComprehensive)
	assert.Equal(t, 500, comp.Concurrency)
	assert.Equal(t, 5, comp.TimeoutSeconds)
}
