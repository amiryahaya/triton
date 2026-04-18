package jobrunner

import (
	"os"
	"path/filepath"
)

// cancelFlagName is the sentinel file inside a job-dir that signals
// "please cancel" to the daemon.
const cancelFlagName = "cancel.flag"

// TouchCancelFlag creates <jobDir>/cancel.flag if it does not exist.
// Idempotent — touching an already-touched flag is a no-op.
func TouchCancelFlag(jobDir string) error {
	path := filepath.Join(jobDir, cancelFlagName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// IsCancelled reports whether <jobDir>/cancel.flag exists.
func IsCancelled(jobDir string) bool {
	_, err := os.Stat(filepath.Join(jobDir, cancelFlagName))
	return err == nil
}
