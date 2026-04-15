package cli

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildMinimalTablesStream(t *testing.T, typeRefs []struct{ NS, Name uint16 }) []byte {
	t.Helper()
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // reserved
	buf.WriteByte(2)                                    // major
	buf.WriteByte(0)                                    // minor
	buf.WriteByte(0)                                    // heap sizes (all 2-byte)
	buf.WriteByte(1)                                    // reserved
	binary.Write(&buf, binary.LittleEndian, uint64(1<<0x01)) // valid: TypeRef only
	binary.Write(&buf, binary.LittleEndian, uint64(0))       // sorted: none
	binary.Write(&buf, binary.LittleEndian, uint32(len(typeRefs)))
	for _, r := range typeRefs {
		binary.Write(&buf, binary.LittleEndian, uint16(0)) // ResolutionScope
		binary.Write(&buf, binary.LittleEndian, r.Name)
		binary.Write(&buf, binary.LittleEndian, r.NS)
	}
	return buf.Bytes()
}

func TestParseTablesStream_ExtractsTypeRefs(t *testing.T) {
	stringsHeap := []byte("\x00System.Security.Cryptography\x00RSACryptoServiceProvider\x00AesManaged\x00")
	idxNS1 := uint16(1)
	idxName1 := uint16(1 + len("System.Security.Cryptography") + 1)
	idxName2 := idxName1 + uint16(len("RSACryptoServiceProvider")+1)

	tablesBytes := buildMinimalTablesStream(t, []struct{ NS, Name uint16 }{
		{NS: idxNS1, Name: idxName1},
		{NS: idxNS1, Name: idxName2},
	})

	refs, err := parseTablesStream(tablesBytes, stringsHeap)
	if err != nil {
		t.Fatalf("parseTablesStream: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("len(refs) = %d, want 2", len(refs))
	}
	want := []string{
		"System.Security.Cryptography.RSACryptoServiceProvider",
		"System.Security.Cryptography.AesManaged",
	}
	for i, r := range refs {
		if r.FullName() != want[i] {
			t.Errorf("refs[%d] = %q, want %q", i, r.FullName(), want[i])
		}
	}
}

func TestParseTablesStream_RejectsBadReserved(t *testing.T) {
	bad := []byte{0xFF, 0xFF, 0xFF, 0xFF, 2, 0, 0, 1}
	if _, err := parseTablesStream(bad, nil); err == nil {
		t.Error("expected error on non-zero reserved field")
	}
}
