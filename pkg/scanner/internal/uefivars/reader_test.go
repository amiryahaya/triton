package uefivars

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadVariable_StripsAttributePrefix(t *testing.T) {
	root := "testdata/efivars"
	data, err := ReadVariable(root, "SecureBoot-"+EFIGlobalGUID)
	if err != nil {
		t.Fatalf("ReadVariable: %v", err)
	}
	if len(data) != 1 {
		t.Fatalf("body len = %d, want 1 (single byte after 4-byte prefix)", len(data))
		return
	}
	if data[0] != 0x01 {
		t.Errorf("body[0] = 0x%02x, want 0x01", data[0])
	}
}

func TestReadVariable_MissingFileReturnsNilNoError(t *testing.T) {
	data, err := ReadVariable("testdata/efivars", "DoesNotExist-abcdef12")
	if err != nil {
		t.Errorf("missing file should return nil error, got %v", err)
	}
	if data != nil {
		t.Errorf("data = %v, want nil", data)
	}
}

func TestReadVariable_TooShortReturnsError(t *testing.T) {
	dir := t.TempDir()
	// Write a 3-byte file — not enough for the 4-byte prefix.
	if err := os.WriteFile(filepath.Join(dir, "bad-var"), []byte{0x07, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadVariable(dir, "bad-var")
	if err == nil {
		t.Error("expected error on file shorter than attribute prefix")
	}
}

func TestReadBoolVariable_SecureBootEnabled(t *testing.T) {
	val, err := ReadBoolVariable("testdata/efivars", "SecureBoot-"+EFIGlobalGUID)
	if err != nil {
		t.Fatalf("ReadBoolVariable: %v", err)
	}
	if !val {
		t.Error("SecureBoot should be true (0x01)")
	}
}

func TestReadBoolVariable_SetupModeDisabled(t *testing.T) {
	val, err := ReadBoolVariable("testdata/efivars", "SetupMode-"+EFIGlobalGUID)
	if err != nil {
		t.Fatalf("ReadBoolVariable: %v", err)
	}
	if val {
		t.Error("SetupMode should be false (0x00)")
	}
}

func TestReadBoolVariable_MissingReturnsFalseNoError(t *testing.T) {
	val, err := ReadBoolVariable("testdata/efivars", "Missing-abcdef")
	if err != nil {
		t.Errorf("missing should not error, got %v", err)
	}
	if val {
		t.Error("missing should return false")
	}
}
