// Package netscan wires agentless scanning together: inventory,
// credentials, and the orchestrator.
package netscan

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Inventory is the parsed devices.yaml file.
type Inventory struct {
	Version  int            `yaml:"version"`
	Defaults DeviceDefaults `yaml:"defaults"`
	Devices  []Device       `yaml:"devices"`
	Groups   []Group        `yaml:"groups"`
}

// DeviceDefaults applies to all devices unless overridden.
type DeviceDefaults struct {
	Port        int           `yaml:"port"`
	ScanTimeout time.Duration `yaml:"scan_timeout"`
	Sudo        bool          `yaml:"sudo"`
}

// Device describes one scan target.
type Device struct {
	Name             string   `yaml:"name"`
	Type             string   `yaml:"type"` // unix | cisco-iosxe | juniper-junos
	Address          string   `yaml:"address"`
	Port             int      `yaml:"port"`
	Credential       string   `yaml:"credential"`
	EnableCredential string   `yaml:"enable_credential"` // Cisco enable password
	ScanPaths        []string `yaml:"scan_paths"`        // unix only
	Sudo             bool     `yaml:"sudo"`
	OSHint           string   `yaml:"os_hint"` // linux | macos | aix

	// Fleet-scan extensions:
	Binary     string `yaml:"binary,omitempty"`
	WorkDir    string `yaml:"work_dir,omitempty"`
	SkipFleet  bool   `yaml:"skip_fleet,omitempty"`
	SkipDevice bool   `yaml:"skip_device,omitempty"`
}

// Group bundles devices for selective scans.
type Group struct {
	Name    string   `yaml:"name"`
	Members []string `yaml:"members"`
}

// LoadInventory reads and validates a devices.yaml file.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory %s: %w", path, err)
	}
	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	inv.applyDefaults()
	return &inv, nil
}

// Validate checks for common errors.
func (inv *Inventory) Validate() error {
	if inv.Version != 1 {
		return fmt.Errorf("unsupported inventory version: %d (expected 1)", inv.Version)
	}
	names := make(map[string]bool)
	for i := range inv.Devices {
		d := &inv.Devices[i]
		if d.Name == "" {
			return fmt.Errorf("device %d: name is required", i)
		}
		if names[d.Name] {
			return fmt.Errorf("duplicate device name: %s", d.Name)
		}
		names[d.Name] = true

		switch d.Type {
		case "unix", "cisco-iosxe", "juniper-junos":
			// OK
		default:
			return fmt.Errorf("device %s: unknown type %q", d.Name, d.Type)
		}
		if d.Address == "" {
			return fmt.Errorf("device %s: address is required", d.Name)
		}
		if d.Credential == "" {
			return fmt.Errorf("device %s: credential is required", d.Name)
		}
	}

	for _, g := range inv.Groups {
		for _, m := range g.Members {
			if !names[m] {
				return fmt.Errorf("group %s: member %s is not defined", g.Name, m)
			}
		}
	}
	return nil
}

// applyDefaults fills in missing fields from Defaults.
func (inv *Inventory) applyDefaults() {
	for i := range inv.Devices {
		d := &inv.Devices[i]
		if d.Port != 0 {
			continue
		}
		switch {
		case d.Type == "juniper-junos":
			d.Port = 830 // NETCONF default
		case inv.Defaults.Port != 0:
			d.Port = inv.Defaults.Port
		default:
			d.Port = 22
		}
	}
}

// DevicesByGroup returns devices matching the named group.
// Empty groupName returns all devices.
func (inv *Inventory) DevicesByGroup(groupName string) ([]Device, error) {
	if groupName == "" {
		return inv.Devices, nil
	}
	for _, g := range inv.Groups {
		if g.Name != groupName {
			continue
		}
		members := make(map[string]bool)
		for _, m := range g.Members {
			members[m] = true
		}
		var out []Device
		for i := range inv.Devices {
			if members[inv.Devices[i].Name] {
				out = append(out, inv.Devices[i])
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("group not found: %s", groupName)
}

// DevicesForFleet returns all unix-type devices that opt in to fleet-scan
// (i.e. not SkipFleet). Non-unix devices are excluded because fleet-scan
// pushes a unix binary.
func (i *Inventory) DevicesForFleet() []Device {
	out := make([]Device, 0, len(i.Devices))
	for _, d := range i.Devices {
		if d.Type == "unix" && !d.SkipFleet {
			out = append(out, d)
		}
	}
	return out
}

// DevicesForDeviceScan returns all devices that opt in to device-scan
// (i.e. not SkipDevice). Type filtering is left to the caller.
func (i *Inventory) DevicesForDeviceScan() []Device {
	out := make([]Device, 0, len(i.Devices))
	for _, d := range i.Devices {
		if !d.SkipDevice {
			out = append(out, d)
		}
	}
	return out
}
