package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

// PollStatus runs statusCmd on the remote every pollInterval and returns
// the parsed Status once it reaches a terminal state (done / failed /
// cancelled). Returns an error if the context is cancelled, a Run fails,
// or the status JSON is malformed.
func PollStatus(ctx context.Context, r SSHRunner, jobID, statusCmd string, pollInterval time.Duration) (*jobrunner.Status, error) {
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		out, err := r.Run(ctx, statusCmd)
		if err != nil {
			return nil, fmt.Errorf("run status cmd for job %s: %w", jobID, err)
		}
		var s jobrunner.Status
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			return nil, fmt.Errorf("parse status json for job %s: %w", jobID, err)
		}
		if s.State.IsTerminal() {
			return &s, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("poll status: %w", ctx.Err())
		case <-ticker.C:
			// next iteration
		}
	}
}

// CollectTar streams the output of `triton scan --collect --job-id <id>
// -o -` (which is a gzip'd tar of the reports/ dir) into
// outputDir/<deviceName>.tar.gz. Returns the local file path.
func CollectTar(ctx context.Context, r SSHRunner, remoteBinary, jobID, outputDir, deviceName string) (string, error) {
	cmd := fmt.Sprintf("%s scan --collect --job-id %s -o -", remoteBinary, jobID)
	stdout, err := r.Run(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("run collect cmd: %w", err)
	}
	if stdout == "" {
		return "", fmt.Errorf("collect returned empty stream for job %s", jobID)
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir output dir: %w", err)
	}
	path := filepath.Join(outputDir, deviceName+".tar.gz")
	if err := os.WriteFile(path, []byte(stdout), 0o600); err != nil {
		return "", fmt.Errorf("write tar: %w", err)
	}
	return path, nil
}
