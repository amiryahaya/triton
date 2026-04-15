package tpmfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildEventLog synthesises a minimal TCG PFP TPM 2.0 binary event log with
// the given events. Each event is a TCG_PCR_EVENT2 record.
//
// algos describes the digest algorithms present in EVERY event (simplified
// for tests — real logs vary event-by-event). Returns the full log including
// the spec-ID pseudo-header.
func buildEventLog(algos []HashAlgo, eventCount int) []byte {
	var buf bytes.Buffer

	// Spec ID pseudo-event (TCG_PCR_EVENT, old format, 32 bytes + SpecID blob).
	// For testing purposes this is minimal; real parsers accept it as a no-op marker.
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // PCRIndex = 0
	binary.Write(&buf, binary.LittleEndian, uint32(3)) // EventType = EV_NO_ACTION
	buf.Write(make([]byte, 20))                        // SHA1 digest (zero)
	specIDBlob := []byte("Spec ID Event03\x00")        // placeholder blob
	binary.Write(&buf, binary.LittleEndian, uint32(len(specIDBlob)))
	buf.Write(specIDBlob)

	// N TCG_PCR_EVENT2 records.
	for i := 0; i < eventCount; i++ {
		binary.Write(&buf, binary.LittleEndian, uint32(4))          // PCRIndex = 4
		binary.Write(&buf, binary.LittleEndian, uint32(0x0D))       // EventType = EV_EFI_BOOT_SERVICES_APPLICATION
		binary.Write(&buf, binary.LittleEndian, uint32(len(algos))) // DigestCount
		for _, a := range algos {
			binary.Write(&buf, binary.LittleEndian, uint16(a))
			buf.Write(make([]byte, a.Size()))
		}
		binary.Write(&buf, binary.LittleEndian, uint32(0)) // EventSize = 0
	}
	return buf.Bytes()
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseEventLog_SHA256Only(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA256}, 5)
	p := writeFixture(t, "event-log-sha256-only.bin", data)
	defer os.Remove(p)

	log, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if len(log.Entries) != 5 {
		t.Errorf("len(Entries) = %d, want 5", len(log.Entries))
	}
	if log.AlgoCounts[AlgSHA256] != 5 {
		t.Errorf("SHA-256 count = %d, want 5", log.AlgoCounts[AlgSHA256])
	}
	if log.AlgoCounts[AlgSHA1] != 0 {
		t.Errorf("SHA-1 count = %d, want 0", log.AlgoCounts[AlgSHA1])
	}
}

func TestParseEventLog_SHA1Only(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA1}, 3)
	log, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if log.AlgoCounts[AlgSHA1] != 3 {
		t.Errorf("SHA-1 count = %d, want 3", log.AlgoCounts[AlgSHA1])
	}
	if log.AlgoCounts[AlgSHA256] != 0 {
		t.Errorf("SHA-256 count = %d, want 0", log.AlgoCounts[AlgSHA256])
	}
}

func TestParseEventLog_Mixed(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA1, AlgSHA256}, 4)
	log, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	if log.AlgoCounts[AlgSHA1] != 4 {
		t.Errorf("SHA-1 count = %d, want 4", log.AlgoCounts[AlgSHA1])
	}
	if log.AlgoCounts[AlgSHA256] != 4 {
		t.Errorf("SHA-256 count = %d, want 4", log.AlgoCounts[AlgSHA256])
	}
}

func TestParseEventLog_TruncatedReturnsError(t *testing.T) {
	data := buildEventLog([]HashAlgo{AlgSHA256}, 2)
	// Truncate mid-record.
	truncated := data[:len(data)-10]
	_, err := ParseEventLog(truncated)
	if err == nil {
		t.Error("expected error on truncated log")
	}
}
