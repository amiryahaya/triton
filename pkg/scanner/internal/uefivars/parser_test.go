package uefivars

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildSignatureList constructs a minimal EFI_SIGNATURE_LIST containing a single
// entry of the given type. Used by tests to exercise the parser without needing
// real UEFI firmware.
func buildSignatureList(sigTypeGUID string, sigData []byte) []byte {
	guidBytes := guidFromString(sigTypeGUID)
	sigSize := uint32(16 + len(sigData)) // 16 = owner GUID
	listSize := 28 + sigSize             // 28 = EFI_SIGNATURE_LIST header
	var buf bytes.Buffer
	buf.Write(guidBytes)                               // SignatureType
	binary.Write(&buf, binary.LittleEndian, listSize)  // SignatureListSize
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // SignatureHeaderSize
	binary.Write(&buf, binary.LittleEndian, sigSize)   // SignatureSize
	// SignatureData: owner (16 zero bytes) + data
	buf.Write(make([]byte, 16))
	buf.Write(sigData)
	return buf.Bytes()
}

// guidFromString converts a GUID like "a5c059a1-..." to 16 mixed-endian bytes.
// EFI GUIDs use little-endian for the first 3 fields, big-endian for the last 2.
func guidFromString(s string) []byte {
	// Remove dashes.
	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}
	raw, _ := hex.DecodeString(clean)
	if len(raw) != 16 {
		panic("guidFromString: bad GUID " + s)
	}
	// Mixed endian: swap first 4, next 2, next 2 bytes.
	raw[0], raw[3] = raw[3], raw[0]
	raw[1], raw[2] = raw[2], raw[1]
	raw[4], raw[5] = raw[5], raw[4]
	raw[6], raw[7] = raw[7], raw[6]
	return raw
}

func TestParseSignatureList_X509Entry(t *testing.T) {
	// Embed a tiny fake "DER cert" (just bytes — parser doesn't validate cert structure).
	cert := bytes.Repeat([]byte{0xAB}, 100)
	data := buildSignatureList(CertX509GUID, cert)
	entries, err := ParseSignatureList(data)
	if err != nil {
		t.Fatalf("ParseSignatureList: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
		return
	}
	if entries[0].Type != SigTypeX509 {
		t.Errorf("Type = %v, want SigTypeX509", entries[0].Type)
	}
	if len(entries[0].Data) != 100 {
		t.Errorf("Data len = %d, want 100", len(entries[0].Data))
	}
	if entries[0].ListIndex != 0 || entries[0].EntryIndex != 0 {
		t.Errorf("ListIndex=%d EntryIndex=%d, want 0/0", entries[0].ListIndex, entries[0].EntryIndex)
	}
}

func TestParseSignatureList_SHA256Entry(t *testing.T) {
	hash := make([]byte, 32)
	hash[0] = 0xFF
	data := buildSignatureList(CertSHA256GUID, hash)
	entries, err := ParseSignatureList(data)
	if err != nil {
		t.Fatalf("ParseSignatureList: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
		return
	}
	if entries[0].Type != SigTypeSHA256 {
		t.Errorf("Type = %v, want SigTypeSHA256", entries[0].Type)
	}
	if len(entries[0].Data) != 32 {
		t.Errorf("Data len = %d, want 32", len(entries[0].Data))
	}
}

func TestParseSignatureList_ChainedLists(t *testing.T) {
	// Two signature lists concatenated.
	cert := bytes.Repeat([]byte{0xCD}, 50)
	hash := make([]byte, 32)
	data := append(buildSignatureList(CertX509GUID, cert), buildSignatureList(CertSHA256GUID, hash)...)
	entries, err := ParseSignatureList(data)
	if err != nil {
		t.Fatalf("ParseSignatureList: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
		return
	}
	if entries[0].ListIndex != 0 || entries[1].ListIndex != 1 {
		t.Errorf("ListIndex: got %d/%d, want 0/1", entries[0].ListIndex, entries[1].ListIndex)
	}
}

func TestParseSignatureList_EmptyReturnsEmpty(t *testing.T) {
	entries, err := ParseSignatureList(nil)
	if err != nil {
		t.Errorf("nil input should not error, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("len(entries) = %d, want 0", len(entries))
	}
}

func TestParseSignatureList_TruncatedReturnsError(t *testing.T) {
	data := buildSignatureList(CertX509GUID, bytes.Repeat([]byte{0xAB}, 50))
	if _, err := ParseSignatureList(data[:20]); err == nil {
		t.Error("expected error on truncated input")
	}
}

func TestParseSignatureList_MultipleEntriesInOneList(t *testing.T) {
	// Build a list with SignatureSize = 16+32 = 48 and TWO entries (total body = 96).
	hash1 := make([]byte, 32)
	hash1[0] = 0xAA
	hash2 := make([]byte, 32)
	hash2[0] = 0xBB
	guidBytes := guidFromString(CertSHA256GUID)
	sigSize := uint32(16 + 32) // owner + hash
	listSize := 28 + 2*sigSize // header + 2 entries
	var buf bytes.Buffer
	buf.Write(guidBytes)
	binary.Write(&buf, binary.LittleEndian, listSize)
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, sigSize)
	// Entry 1
	buf.Write(make([]byte, 16)) // owner
	buf.Write(hash1)
	// Entry 2
	buf.Write(make([]byte, 16))
	buf.Write(hash2)

	entries, err := ParseSignatureList(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseSignatureList: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
		return
	}
	if entries[0].Data[0] != 0xAA || entries[1].Data[0] != 0xBB {
		t.Errorf("entry data wrong: [0x%02x, 0x%02x]", entries[0].Data[0], entries[1].Data[0])
	}
	if entries[0].EntryIndex != 0 || entries[1].EntryIndex != 1 {
		t.Errorf("EntryIndex: %d/%d, want 0/1", entries[0].EntryIndex, entries[1].EntryIndex)
	}
}

func TestParseSignatureList_FixturePK(t *testing.T) {
	data, err := ReadVariable("testdata/efivars", "PK-"+EFIGlobalGUID)
	if err != nil {
		t.Fatalf("ReadVariable: %v", err)
	}
	if data == nil {
		t.Fatal("PK fixture missing")
		return
	}
	entries, err := ParseSignatureList(data)
	if err != nil {
		t.Fatalf("ParseSignatureList: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
		return
	}
	if entries[0].Type != SigTypeX509 {
		t.Errorf("Type = %v, want SigTypeX509", entries[0].Type)
	}
	if len(entries[0].Data) < 100 {
		t.Errorf("cert data suspiciously short: %d bytes", len(entries[0].Data))
	}
}

func TestParseSignatureList_FixtureDbx(t *testing.T) {
	data, err := ReadVariable("testdata/efivars", "dbx-"+EFIGlobalGUID)
	if err != nil {
		t.Fatalf("ReadVariable: %v", err)
	}
	entries, err := ParseSignatureList(data)
	if err != nil {
		t.Fatalf("ParseSignatureList: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
		return
	}
	if entries[0].Type != SigTypeSHA256 {
		t.Errorf("Type = %v, want SigTypeSHA256", entries[0].Type)
	}
	if len(entries[0].Data) != 32 {
		t.Errorf("hash len = %d, want 32", len(entries[0].Data))
	}
}
