package binsections

import (
	"os"
	"runtime"
	"testing"
)

func TestExtractELFSections_Self(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF test requires a Linux host with the test binary as ELF")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	sections, err := ExtractELFSections(exe)
	if err != nil {
		t.Fatalf("ExtractELFSections(%s) failed: %v", exe, err)
	}

	// Go binaries always have .rodata and .go.buildinfo.
	names := map[string]bool{}
	for _, s := range sections {
		names[s.Name] = true
	}
	if !names[".rodata"] {
		t.Errorf("expected .rodata section, got section names: %v", keys(names))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
