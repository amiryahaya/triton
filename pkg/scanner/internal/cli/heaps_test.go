package cli

import "testing"

func TestParseStringsHeap_NullTerminated(t *testing.T) {
	// "Hello\0World\0System\0" -> indices 0->"" (reserved), 1->"ello", 6->"World", 12->"System"
	heap := []byte("Hello\x00World\x00System\x00")
	cases := map[uint32]string{
		0:  "",
		1:  "ello",
		6:  "World",
		12: "System",
	}
	for idx, want := range cases {
		got, err := readStringAt(heap, idx)
		if err != nil {
			t.Errorf("readStringAt(%d): %v", idx, err)
			continue
		}
		if got != want {
			t.Errorf("readStringAt(%d) = %q, want %q", idx, got, want)
		}
	}
}

func TestParseStringsHeap_OutOfBounds(t *testing.T) {
	heap := []byte("Hello\x00")
	if _, err := readStringAt(heap, 100); err == nil {
		t.Error("expected error on out-of-bounds index")
	}
}

func TestParseUSHeap_AllStrings(t *testing.T) {
	heap := []byte{
		0x00,       // index 0: empty entry (compressed length 0)
		0x05,       // index 1: compressed length = 5 (4 UTF-16 bytes + 1 terminal)
		0x48, 0x00, // 'H'
		0x69, 0x00, // 'i'
		0x00, // terminal byte
	}
	got, err := parseUSHeap(heap)
	if err != nil {
		t.Fatalf("parseUSHeap: %v", err)
	}
	want := []string{"Hi"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("parseUSHeap = %v, want %v", got, want)
	}
}

func TestParseUSHeap_RejectsTruncated(t *testing.T) {
	heap := []byte{0x00, 0x64, 0x48}
	if _, err := parseUSHeap(heap); err == nil {
		t.Error("expected error on truncated US entry")
	}
}
