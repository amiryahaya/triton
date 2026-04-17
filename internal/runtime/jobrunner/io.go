package jobrunner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// statusFileName is the canonical file for job status on disk.
const statusFileName = "status.json"

// WriteStatusAtomic writes the status to <jobDir>/status.json atomically via
// write-tmp-rename. Callers: status-writer goroutine, terminal-state writer.
func WriteStatusAtomic(jobDir string, s *Status) error {
	s.Touch()
	return WriteJSON(filepath.Join(jobDir, statusFileName), s)
}

// ReadStatus reads <jobDir>/status.json and returns the parsed Status.
// Returns os.IsNotExist-wrapped error if the file is missing.
func ReadStatus(jobDir string) (*Status, error) {
	data, err := os.ReadFile(filepath.Join(jobDir, statusFileName))
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse status.json: %w", err)
	}
	return &s, nil
}

// WriteJSON marshals v as indented JSON and writes it atomically (write-tmp-
// rename). The temp file lives in the same directory so rename is same-FS.
// Mode 0600 — status files can contain host/process metadata.
func WriteJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
