package uefivars

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReadVariable reads an EFI variable file, strips the 4-byte attribute prefix,
// and returns the raw value body. Missing files return (nil, nil) — absence is
// not a failure (the variable may not exist on this platform).
func ReadVariable(root, name string) ([]byte, error) {
	path := filepath.Join(root, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("uefivars: read %s: %w", path, err)
	}
	if len(data) < efiAttrPrefixLen {
		return nil, fmt.Errorf("uefivars: %s too short (%d bytes, need ≥ %d)", name, len(data), efiAttrPrefixLen)
	}
	return data[efiAttrPrefixLen:], nil
}

// ReadBoolVariable reads a 1-byte boolean EFI variable (SecureBoot, SetupMode).
// Returns false with no error when the variable is absent.
func ReadBoolVariable(root, name string) (bool, error) {
	body, err := ReadVariable(root, name)
	if err != nil {
		return false, err
	}
	if body == nil {
		return false, nil
	}
	if len(body) != 1 {
		return false, fmt.Errorf("uefivars: bool variable %s has %d bytes, want 1", name, len(body))
	}
	return body[0] != 0, nil
}
