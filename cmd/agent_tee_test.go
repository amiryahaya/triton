package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
)

// --- resolveAgentConfig: alsoLocal field ---

func TestResolveAgentConfig_AlsoLocal_FromYAML(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "agent.yaml"),
		[]byte("report_server: http://example/\nalso_local: true\n"),
		0o600,
	))
	t.Setenv("HOME", t.TempDir())
	agentConfigDir = dir
	t.Cleanup(func() { agentConfigDir = "" })

	// Make sure the package-global CLI flag is false so the
	// yaml value is the only source.
	agentAlsoLocal = false
	t.Cleanup(func() { agentAlsoLocal = false })

	r, err := resolveAgentConfig(nil)
	require.NoError(t, err)
	assert.True(t, r.alsoLocal, "agent.yaml also_local:true should propagate to resolvedAgentConfig")
}

func TestResolveAgentConfig_AlsoLocal_FlagOverridesYAMLFalse(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "agent.yaml"),
		[]byte("report_server: http://example/\n"),
		0o600,
	))
	t.Setenv("HOME", t.TempDir())
	agentConfigDir = dir
	t.Cleanup(func() { agentConfigDir = "" })

	// Simulate --also-local (flag-only path, no yaml value).
	agentAlsoLocal = true
	t.Cleanup(func() { agentAlsoLocal = false })

	r, err := resolveAgentConfig(nil)
	require.NoError(t, err)
	assert.True(t, r.alsoLocal, "CLI --also-local must enable tee mode even when yaml omits it")
}

func TestResolveAgentConfig_AlsoLocal_DefaultFalse(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	agentConfigDir = emptyDir
	t.Cleanup(func() { agentConfigDir = "" })
	agentAlsoLocal = false

	r, err := resolveAgentConfig(nil)
	require.NoError(t, err)
	assert.False(t, r.alsoLocal, "no flag, no yaml → tee mode off")
}

// --- dispatchScanResult: the 4-way matrix ---

// dispatchTestScan is a minimal valid ScanResult that every dispatch
// test reuses. The only field writeLocalReports actually touches is
// Metadata.Hostname (for the timestamp directory naming via
// cmd/report).
func dispatchTestScan() *model.ScanResult {
	return &model.ScanResult{
		ID: "scan-dispatch-test",
		Metadata: model.ScanMetadata{
			Hostname:    "tee-host",
			ScanProfile: "quick",
		},
		Findings: nil,
		Summary:  model.Summary{},
	}
}

// TestDispatchScanResult_LocalOnly confirms that with no server
// configured, dispatchScanResult writes exactly one local report
// tree and does not attempt any network submission.
func TestDispatchScanResult_LocalOnly(t *testing.T) {
	tmp := t.TempDir()
	r := &resolvedAgentConfig{
		outputDir:        tmp,
		effectiveFormats: []string{"json"},
	}

	err := dispatchScanResult(context.Background(), r, nil, dispatchTestScan())
	require.NoError(t, err)

	// One timestamped subdir should exist under tmp.
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	require.Len(t, entries, 1, "local-only mode should produce exactly one report directory")
	assert.True(t, entries[0].IsDir())
}

// TestDispatchScanResult_ServerOnly confirms that with a client
// configured and alsoLocal=false, submission runs and no local
// directory is touched.
func TestDispatchScanResult_ServerOnly(t *testing.T) {
	var submitCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/scans" && req.Method == http.MethodPost {
			atomic.AddInt32(&submitCalls, 1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan-dispatch-test","status":"saved"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tmp := t.TempDir()
	r := &resolvedAgentConfig{
		reportServer:     srv.URL,
		outputDir:        tmp,
		effectiveFormats: []string{"json"},
		alsoLocal:        false,
	}
	client := agent.New(srv.URL)
	client.RetryMaxAttempts = 1 // keep tests fast

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan())
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&submitCalls), "server should receive exactly one submission")

	// tmp directory must be empty — server-only mode must not
	// write local files.
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, entries, "server-only mode should not create local report directory")
}

// TestDispatchScanResult_TeeBothSucceed is the headline A8 test:
// when client is configured AND alsoLocal is true, BOTH the local
// write AND the server submit happen, and the caller receives no
// error.
func TestDispatchScanResult_TeeBothSucceed(t *testing.T) {
	var submitCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/scans" && req.Method == http.MethodPost {
			atomic.AddInt32(&submitCalls, 1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan-dispatch-test","status":"saved"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	tmp := t.TempDir()
	r := &resolvedAgentConfig{
		reportServer:     srv.URL,
		outputDir:        tmp,
		effectiveFormats: []string{"json"},
		alsoLocal:        true,
	}
	client := agent.New(srv.URL)
	client.RetryMaxAttempts = 1

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan())
	require.NoError(t, err, "tee mode with both paths succeeding should return nil")

	// Server must have received the submission.
	assert.Equal(t, int32(1), atomic.LoadInt32(&submitCalls), "server should still receive the submission in tee mode")

	// Local directory must have exactly one timestamped subdirectory
	// containing at least the JSON report.
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	require.Len(t, entries, 1, "tee mode should produce exactly one local report directory")
	assert.True(t, entries[0].IsDir())

	// Verify the JSON report file exists inside the timestamped dir.
	runDir := filepath.Join(tmp, entries[0].Name())
	runEntries, err := os.ReadDir(runDir)
	require.NoError(t, err)
	assert.NotEmpty(t, runEntries, "report dir should contain the generated report file(s)")
}

// TestDispatchScanResult_TeeLocalFailsServerSucceeds verifies the
// "server is authoritative" contract: a local write failure must
// degrade to a warning, NOT abort the server submission. The caller
// sees the submission's result (success here).
func TestDispatchScanResult_TeeLocalFailsServerSucceeds(t *testing.T) {
	var submitCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/scans" && req.Method == http.MethodPost {
			atomic.AddInt32(&submitCalls, 1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan-dispatch-test","status":"saved"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Point outputDir at a path under a read-only parent directory
	// so MkdirAll fails. Cleanest reliable way: point at a path
	// inside an existing regular FILE (can't mkdir inside a file).
	notADir := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(notADir, []byte("regular file"), 0o600))

	r := &resolvedAgentConfig{
		reportServer:     srv.URL,
		outputDir:        notADir, // writeLocalReports will fail here
		effectiveFormats: []string{"json"},
		alsoLocal:        true,
	}
	client := agent.New(srv.URL)
	client.RetryMaxAttempts = 1

	// Capture stderr so we can confirm the warning was logged
	// without requiring operator eyes on the test output.
	oldStderr := os.Stderr
	rPipe, wPipe, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = wPipe
	defer func() { os.Stderr = oldStderr }()

	err = dispatchScanResult(context.Background(), r, client, dispatchTestScan())
	require.NoError(t, err, "tee mode with local failure + server success must NOT return an error")

	// Close writer and read the captured stderr.
	_ = wPipe.Close()
	captured := make([]byte, 4096)
	n, _ := rPipe.Read(captured)
	stderrOut := string(captured[:n])

	assert.Contains(t, stderrOut, "Warning: local report write failed",
		"local-failure warning must reach stderr so operators can diagnose")
	assert.Equal(t, int32(1), atomic.LoadInt32(&submitCalls),
		"server submission must proceed even when local write failed")
}

// TestDispatchScanResult_TeeServerFails confirms that when the
// server submit fails in tee mode, the caller sees the server error
// (the local write's success is irrelevant to the exit status).
func TestDispatchScanResult_TeeServerFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	tmp := t.TempDir()
	r := &resolvedAgentConfig{
		reportServer:     srv.URL,
		outputDir:        tmp,
		effectiveFormats: []string{"json"},
		alsoLocal:        true,
	}
	client := agent.New(srv.URL)
	client.RetryMaxAttempts = 1 // don't wait for backoff

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan())
	require.Error(t, err, "server-submit failure must propagate even if local write succeeded")
	assert.Contains(t, err.Error(), "submit failed")

	// Local directory should still have the report from the
	// successful local write — that's the forensic backup.
	entries, _ := os.ReadDir(tmp)
	assert.Len(t, entries, 1, "local write should have completed even though submit failed")
}
