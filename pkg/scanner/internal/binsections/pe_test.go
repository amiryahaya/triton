package binsections

import "testing"

func TestExtractPESections_Fixture(t *testing.T) {
	sections, err := ExtractPESections("testdata/hello.exe")
	if err != nil {
		t.Fatalf("ExtractPESections: %v", err)
	}
	// PE binaries split read-only data into .rdata typically.
	names := map[string]bool{}
	for _, s := range sections {
		names[s.Name] = true
	}
	if !names[".rdata"] {
		t.Errorf("expected .rdata, got sections: %+v", names)
	}
}
