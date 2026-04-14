package binsections

import (
	"os"
	"testing"
)

func TestExtractSections_AutoDetect(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sections, err := ExtractSections(exe)
	if err != nil {
		t.Fatalf("ExtractSections(%s): %v", exe, err)
	}
	if len(sections) == 0 {
		t.Error("expected at least one section from self-executable")
	}
}

func TestExtractSections_NonBinary(t *testing.T) {
	// Plain text file — should fail cleanly, not panic.
	path := "testdata/README.md"
	_, err := ExtractSections(path)
	if err == nil {
		t.Error("expected error from non-binary file")
	}
}
