package jobrunner

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultWorkDirName is the subdirectory under $HOME where work-dirs live.
const DefaultWorkDirName = ".triton/jobs"

// ResolveWorkDir returns the absolute path to use as the jobs root. If
// override is empty, returns $HOME/.triton/jobs. A leading ~/ is expanded.
func ResolveWorkDir(override string) string {
	if override != "" {
		return expandHome(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "triton-jobs")
	}
	return filepath.Join(home, DefaultWorkDirName)
}

// JobDir returns workDir/jobID — the filesystem path for a specific job.
// Does not create the directory.
func JobDir(workDir, jobID string) string {
	return filepath.Join(workDir, jobID)
}

// EnsureJobDir creates workDir/jobID and workDir/jobID/reports if they do
// not exist. Idempotent. Returns the job directory path.
func EnsureJobDir(workDir, jobID string) (string, error) {
	jobDir := JobDir(workDir, jobID)
	if err := os.MkdirAll(filepath.Join(jobDir, "reports"), 0o700); err != nil {
		return "", err
	}
	return jobDir, nil
}

// expandHome expands a leading ~/ to the user's home directory. If home
// lookup fails, returns the path unchanged.
func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
