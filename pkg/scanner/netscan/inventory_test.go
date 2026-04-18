package netscan

import (
	"os"
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

func TestInventory_DevicesForFleet(t *testing.T) {
	inv := &Inventory{
		Devices: []Device{
			{Name: "web-1", Type: "unix"},
			{Name: "aix-1", Type: "unix", SkipFleet: true},
			{Name: "router", Type: "cisco-iosxe"},
			{Name: "db-1", Type: "unix"},
		},
	}
	got := inv.DevicesForFleet()
	if len(got) != 2 {
		t.Fatalf("DevicesForFleet: got %d, want 2", len(got))
	}
	names := map[string]bool{got[0].Name: true, got[1].Name: true}
	if !names["web-1"] || !names["db-1"] {
		t.Errorf("DevicesForFleet: got %v, want [web-1, db-1]", names)
	}
}

func TestInventory_DevicesForDeviceScan_SkipsDeviceScanOptOuts(t *testing.T) {
	inv := &Inventory{
		Devices: []Device{
			{Name: "router-1", Type: "cisco-iosxe"},
			{Name: "router-2", Type: "cisco-iosxe", SkipDevice: true},
			{Name: "web-1", Type: "unix"},
		},
	}
	got := inv.DevicesForDeviceScan()
	if len(got) != 2 {
		t.Fatalf("DevicesForDeviceScan: got %d, want 2", len(got))
	}
	for _, d := range got {
		if d.Name == "router-2" {
			t.Errorf("router-2 should be excluded (SkipDevice=true)")
		}
	}
}

func TestDevice_NewFields_YAMLRoundTrip(t *testing.T) {
	yaml := []byte(`
version: 1
devices:
  - name: aix-legacy
    type: unix
    address: 10.0.1.20
    credential: legacy-ssh
    binary: /opt/triton-binaries/triton-aix-ppc64
    work_dir: /home/triton-test
    skip_fleet: false
    skip_device: true
`)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "devices.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(inv.Devices) != 1 {
		t.Fatalf("want 1 device, got %d", len(inv.Devices))
	}
	d := inv.Devices[0]
	if d.Binary != "/opt/triton-binaries/triton-aix-ppc64" {
		t.Errorf("Binary: got %q", d.Binary)
	}
	if d.WorkDir != "/home/triton-test" {
		t.Errorf("WorkDir: got %q", d.WorkDir)
	}
	if d.SkipFleet {
		t.Errorf("SkipFleet: got true, want false")
	}
	if !d.SkipDevice {
		t.Errorf("SkipDevice: got false, want true")
	}
}
