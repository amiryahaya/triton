package netscan

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadInventory(t *testing.T) {
	inv, err := LoadInventory(filepath.Join("testdata", "inventory.yaml"))
	require.NoError(t, err)
	assert.Equal(t, 1, inv.Version)
	assert.Len(t, inv.Devices, 3)

	// Port defaults
	var srx Device
	for _, d := range inv.Devices {
		if d.Name == "core-srx-1" {
			srx = d
		}
	}
	assert.Equal(t, 830, srx.Port, "Juniper should default to NETCONF port 830")
}

func TestValidate_DuplicateNames(t *testing.T) {
	inv := &Inventory{
		Version: 1,
		Devices: []Device{
			{Name: "a", Type: "unix", Address: "1.1.1.1", Credential: "k"},
			{Name: "a", Type: "unix", Address: "1.1.1.2", Credential: "k"},
		},
	}
	err := inv.Validate()
	assert.ErrorContains(t, err, "duplicate")
}

func TestValidate_UnknownType(t *testing.T) {
	inv := &Inventory{
		Version: 1,
		Devices: []Device{
			{Name: "a", Type: "windows", Address: "1.1.1.1", Credential: "k"},
		},
	}
	err := inv.Validate()
	assert.ErrorContains(t, err, "unknown type")
}

func TestDevicesByGroup(t *testing.T) {
	inv, err := LoadInventory(filepath.Join("testdata", "inventory.yaml"))
	require.NoError(t, err)

	prod, err := inv.DevicesByGroup("production")
	require.NoError(t, err)
	assert.Len(t, prod, 2)

	all, err := inv.DevicesByGroup("")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	_, err = inv.DevicesByGroup("nonexistent")
	assert.Error(t, err)
}
