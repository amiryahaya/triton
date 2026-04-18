package jobrunner

import (
	"fmt"
	"os"
	"path/filepath"
)

// JobSummary is the compact per-job view returned by List.
type JobSummary struct {
	JobID  string
	Status *Status
}

// List enumerates all job directories under workDir that contain a
// status.json file. Unrecognised entries (stray files, empty dirs) are
// skipped. Results are in filesystem order (not sorted).
func List(workDir string) ([]JobSummary, error) {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read workdir: %w", err)
	}
	var out []JobSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		jobDir := filepath.Join(workDir, e.Name())
		s, err := ReadStatus(jobDir)
		if err != nil {
			continue
		}
		out = append(out, JobSummary{JobID: e.Name(), Status: s})
	}
	return out, nil
}

// Remove deletes a single job directory. Refuses if the status is
// non-terminal AND the daemon PID is alive — in that case the caller
// should --cancel first.
func Remove(workDir, jobID string) error {
	return removeWithLiveness(workDir, jobID, realPIDAlive)
}

// removeWithLiveness is the testable form, parameterised on a pidAlive
// predicate so unit tests can inject deterministic behaviour without
// depending on the process table.
func removeWithLiveness(workDir, jobID string, pidAlive func(int) bool) error {
	jobDir := filepath.Join(workDir, jobID)
	s, err := ReadStatus(jobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.RemoveAll(jobDir)
		}
		return err
	}
	if !s.State.IsTerminal() && s.PID > 0 && pidAlive(s.PID) {
		return fmt.Errorf("job %s is running (pid %d); cancel it first", jobID, s.PID)
	}
	return os.RemoveAll(jobDir)
}

// RemoveAll removes all finished (terminal-state) jobs under workDir.
// Running jobs are skipped silently. Returns the count removed.
func RemoveAll(workDir string) (int, error) {
	return removeAllWithLiveness(workDir, realPIDAlive)
}

// removeAllWithLiveness is the testable form.
func removeAllWithLiveness(workDir string, pidAlive func(int) bool) (int, error) {
	jobs, err := List(workDir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, j := range jobs {
		if !j.Status.State.IsTerminal() && j.Status.PID > 0 && pidAlive(j.Status.PID) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(workDir, j.JobID)); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
