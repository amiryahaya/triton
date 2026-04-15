package tpmfs

import (
	"testing"
)

func TestDiscoverDevices_ParsesInfineonFixture(t *testing.T) {
	devs, err := DiscoverDevices("testdata/sysfs-infineon")
	if err != nil {
		t.Fatalf("DiscoverDevices: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("len(devs) = %d, want 1", len(devs))
		return
	}
	d := devs[0]
	if d.Name != "tpm0" {
		t.Errorf("Name = %q, want tpm0", d.Name)
	}
	if d.SpecVersion != "2.0" {
		t.Errorf("SpecVersion = %q, want 2.0", d.SpecVersion)
	}
	if d.Vendor != "Infineon" {
		t.Errorf("Vendor = %q, want Infineon", d.Vendor)
	}
	if d.FirmwareVersion != "4.32.1.2" {
		t.Errorf("FirmwareVersion = %q, want 4.32.1.2", d.FirmwareVersion)
	}
	if d.Description != "TPM 2.0 Device" {
		t.Errorf("Description = %q, want 'TPM 2.0 Device'", d.Description)
	}
}

func TestDiscoverDevices_MissingRoot(t *testing.T) {
	// Non-existent root → no error, empty slice.
	devs, err := DiscoverDevices("testdata/does-not-exist")
	if err != nil {
		t.Errorf("missing root should not error, got %v", err)
	}
	if len(devs) != 0 {
		t.Errorf("len(devs) = %d, want 0", len(devs))
	}
}

func TestDecodeVendorID(t *testing.T) {
	cases := map[string]string{
		"0x49465800": "Infineon",           // "IFX\x00" → "IFX "
		"0x494E5443": "Intel",              // "INTC"
		"0x4E544300": "Nuvoton",            // "NTC\x00" → "NTC "
		"0x53544D20": "STMicroelectronics", // "STM "
		"0x41544D4C": "Microchip",          // "ATML"
		"0x4D534654": "Microsoft",          // "MSFT"
		"0x474F4F47": "Google",             // "GOOG"
		"0x414D4400": "AMD",                // "AMD\x00" → "AMD "
		"0x01020304": "01020304",           // unknown → raw hex
		"INVALID":    "INVALID",            // non-hex → passes through
	}
	for input, want := range cases {
		got := decodeVendorID(input)
		if got != want {
			t.Errorf("decodeVendorID(%q) = %q, want %q", input, got, want)
		}
	}
}
