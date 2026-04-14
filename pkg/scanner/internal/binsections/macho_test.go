package binsections

import (
	"os"
	"runtime"
	"testing"
)

func TestExtractMachOSections_Self(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Mach-O test requires darwin host")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	sections, err := ExtractMachOSections(exe)
	if err != nil {
		t.Fatalf("ExtractMachOSections(%s): %v", exe, err)
	}

	// Mach-O Go binaries have __rodata in __DATA_CONST or __DATA segments.
	foundConst := false
	for _, s := range sections {
		if s.Name == "__rodata" || s.Name == "__const" {
			foundConst = true
			break
		}
	}
	if !foundConst {
		t.Errorf("expected __rodata or __const section, got %d sections", len(sections))
		for _, s := range sections {
			t.Logf("  section: %s (%d bytes)", s.Name, len(s.Data))
		}
	}
}
