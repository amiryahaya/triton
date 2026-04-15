package tpmfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DiscoverDevices walks sysRoot (e.g. "/sys/class/tpm") and returns one
// Device entry per discovered tpm* subdirectory. Returns an empty slice
// (and no error) if sysRoot does not exist — TPM absence is not a failure.
func DiscoverDevices(sysRoot string) ([]Device, error) {
	entries, err := os.ReadDir(sysRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("tpmfs: readdir %s: %w", sysRoot, err)
	}
	out := []Device{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "tpm") {
			continue
		}
		devPath := filepath.Join(sysRoot, name)
		d := Device{Path: devPath, Name: name}
		d.SpecVersion = readTrimmed(filepath.Join(devPath, "tpm_version_major"))
		if d.SpecVersion == "2" {
			d.SpecVersion = "2.0"
		}
		d.Description = readTrimmed(filepath.Join(devPath, "device", "description"))
		parseCaps(filepath.Join(devPath, "device", "caps"), &d)
		ekPath := filepath.Join(devPath, "device", "endorsement_key_cert")
		if _, err := os.Stat(ekPath); err == nil {
			d.EKCertPath = ekPath
		}
		out = append(out, d)
	}
	return out, nil
}

// readTrimmed returns the trimmed contents of a file, or "" if absent.
func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseCaps reads the multi-line caps file and populates Vendor + FirmwareVersion.
func parseCaps(path string, d *Device) {
	content := readTrimmed(path)
	if content == "" {
		return
	}
	for _, line := range strings.Split(content, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "Manufacturer":
			d.VendorRawID = val
			d.Vendor = decodeVendorID(val)
		case "Firmware version":
			d.FirmwareVersion = val
		case "TCG version":
			if d.SpecVersion == "" {
				d.SpecVersion = val
			}
		}
	}
}

// vendorIDTable maps 4-char ASCII manufacturer codes to human names.
// Codes may be space-padded to 4 chars.
var vendorIDTable = map[string]string{
	"IFX ": "Infineon",
	"INTC": "Intel",
	"NTC ": "Nuvoton",
	"STM ": "STMicroelectronics",
	"ATML": "Microchip",
	"MSFT": "Microsoft",
	"GOOG": "Google",
	"AMD ": "AMD",
}

// decodeVendorID converts a hex manufacturer code (e.g. "0x49465800")
// to a human-readable vendor name via vendorIDTable. Unknown vendors
// pass through the input as-is.
func decodeVendorID(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return s
	}
	n, err := strconv.ParseUint(s[2:], 16, 32)
	if err != nil {
		return raw
	}
	bs := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	// Replace NUL bytes with spaces so lookups match the space-padded keys.
	for i, b := range bs {
		if b == 0 {
			bs[i] = ' '
		}
	}
	if name, ok := vendorIDTable[string(bs)]; ok {
		return name
	}
	// Fallback: return raw hex without the "0x" prefix for consistency.
	return s[2:]
}
