package crypto

import (
	"bytes"
	"testing"
)

func TestFindOIDsInBuffer_Basic(t *testing.T) {
	// DER-encoded OID for sha256WithRSAEncryption (1.2.840.113549.1.1.11)
	// Tag=0x06, Len=9, Content=2A 86 48 86 F7 0D 01 01 0B
	sha256RSA := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}

	// ML-KEM-512 OID (2.16.840.1.101.3.4.4.1)
	// Tag=0x06, Len=9, Content=60 86 48 01 65 03 04 04 01
	mlkem := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01}

	// Embed them with junk in between (simulates binary .rodata layout)
	buf := bytes.Buffer{}
	buf.Write([]byte("random string data here xxxxx"))
	buf.Write(sha256RSA)
	buf.Write([]byte{0x00, 0xFF, 0x42, 0x17, 0xAB})
	buf.Write(mlkem)
	buf.Write([]byte("more junk"))

	found := FindOIDsInBuffer(buf.Bytes())

	wantOIDs := map[string]bool{
		"1.2.840.113549.1.1.11":  false,
		"2.16.840.1.101.3.4.4.1": false,
	}
	for _, f := range found {
		if _, ok := wantOIDs[f.OID]; ok {
			wantOIDs[f.OID] = true
		}
	}
	for oid, seen := range wantOIDs {
		if !seen {
			t.Errorf("missing expected OID: %s", oid)
		}
	}
}

func TestFindOIDsInBuffer_RejectsGarbage(t *testing.T) {
	// Random bytes with scattered 0x06 bytes but no valid OID structure
	garbage := []byte{
		0x06, 0x03, 0xFF, 0xFF, 0xFF, // first arc would be invalid
		0x06, 0x02, 0x2A, 0x86, // truncated - last byte has continuation bit set
		0x06, 0x00, // zero length
		0x06, 0x50, 0x2A, // length claims 80 bytes but only 1 follows
	}
	found := FindOIDsInBuffer(garbage)
	if len(found) != 0 {
		t.Errorf("expected no OIDs from garbage, got %d: %+v", len(found), found)
	}
}

func TestFindOIDsInBuffer_DedupesByOffset(t *testing.T) {
	// Same OID byte pattern repeated
	sha256RSA := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
	buf := append(append([]byte{}, sha256RSA...), sha256RSA...)

	found := FindOIDsInBuffer(buf)
	// Two distinct hits at different offsets
	if len(found) != 2 {
		t.Errorf("expected 2 hits, got %d", len(found))
	}
	if found[0].Offset == found[1].Offset {
		t.Errorf("expected distinct offsets, got %d and %d", found[0].Offset, found[1].Offset)
	}
}

func TestFindOIDsInBuffer_DecodesLargeSecondArc(t *testing.T) {
	// First content byte = 0x78 (120): combined=120, firstArc=2, secondArc=40.
	// X.690 §8.19.4 allows any secondArc when firstArc==2, so this is a valid OID 2.40.1.2.
	buf := []byte{0x06, 0x03, 0x78, 0x01, 0x02}
	found := FindOIDsInBuffer(buf)
	if len(found) != 1 {
		t.Fatalf("expected 1 hit for valid OID with firstArc=2, got %d", len(found))
	}
	if found[0].OID != "2.40.1.2" {
		t.Errorf("got %q, want 2.40.1.2", found[0].OID)
	}
}

func TestFindOIDsInBuffer_SupportsLargeFirstArc(t *testing.T) {
	// OID 2.100.3 (first component value 180 = 0x81 0x34 in base-128 multi-byte).
	// Tag=0x06, Len=3, Content = 0x81 0x34 0x03
	der := []byte{0x06, 0x03, 0x81, 0x34, 0x03}
	found := FindOIDsInBuffer(der)
	if len(found) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(found))
	}
	if found[0].OID != "2.100.3" {
		t.Errorf("got %q, want 2.100.3", found[0].OID)
	}
}

func TestClassifyFoundOIDs(t *testing.T) {
	found := []FoundOID{
		{OID: "1.2.840.113549.1.1.11", Offset: 100},  // SHA256-RSA (registered)
		{OID: "2.16.840.1.101.3.4.4.1", Offset: 200}, // ML-KEM-512 (registered)
		{OID: "9.9.9.9.9.9", Offset: 300},            // unknown (valid-looking but not in registry)
	}

	classified := ClassifyFoundOIDs(found)

	if len(classified) != 2 {
		t.Fatalf("expected 2 classified results (unknown filtered out), got %d", len(classified))
	}
	if classified[0].Entry.Algorithm != "SHA256-RSA" {
		t.Errorf("first entry: got %q, want SHA256-RSA", classified[0].Entry.Algorithm)
	}
	if classified[1].Entry.Algorithm != "ML-KEM-512" {
		t.Errorf("second entry: got %q, want ML-KEM-512", classified[1].Entry.Algorithm)
	}
}
