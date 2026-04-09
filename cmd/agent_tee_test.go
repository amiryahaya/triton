package cmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
)

// newAgentTestCmd builds a throwaway cobra command carrying only the
// flags resolveAgentConfig inspects. Tests use it to exercise the
// prod code path (cmd.Flags().Changed) without standing up the real
// root command — which would drag in the scanner engine and every
// other subcommand.
//
// If flagSet is true, the helper marks --also-local as explicitly set
// on the command line so cobra reports Changed("also-local") == true.
func newAgentTestCmd(t *testing.T, flagSet bool) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "agent"}
	c.Flags().BoolVar(&agentAlsoLocal, "also-local", false, "")
	if flagSet {
		require.NoError(t, c.Flags().Set("also-local", "true"))
	}
	return c
}

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

	// Flag NOT set on the command line — yaml is the only source.
	agentAlsoLocal = false
	t.Cleanup(func() { agentAlsoLocal = false })
	cmd := newAgentTestCmd(t, false)

	r, err := resolveAgentConfig(cmd)
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

	// Simulate --also-local on the command line (flag-only path,
	// yaml does not set also_local).
	t.Cleanup(func() { agentAlsoLocal = false })
	cmd := newAgentTestCmd(t, true)

	r, err := resolveAgentConfig(cmd)
	require.NoError(t, err)
	assert.True(t, r.alsoLocal, "CLI --also-local must enable tee mode even when yaml omits it")
}

// TestResolveAgentConfig_AlsoLocal_FlagFalseOverridesYAMLTrue
// pins the SF1 fix: --also-local=false on the command line must
// override also_local:true in agent.yaml. Prior to the fix the
// cmd==nil branch used OR-logic and this override was impossible
// from tests. Now resolution runs the same cobra.Changed() path
// in both tests and production.
func TestResolveAgentConfig_AlsoLocal_FlagFalseOverridesYAMLTrue(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "agent.yaml"),
		[]byte("report_server: http://example/\nalso_local: true\n"),
		0o600,
	))
	t.Setenv("HOME", t.TempDir())
	agentConfigDir = dir
	t.Cleanup(func() { agentConfigDir = "" })

	// Build a command that explicitly sets --also-local=false.
	c := &cobra.Command{Use: "agent"}
	c.Flags().BoolVar(&agentAlsoLocal, "also-local", false, "")
	require.NoError(t, c.Flags().Set("also-local", "false"))
	t.Cleanup(func() { agentAlsoLocal = false })

	r, err := resolveAgentConfig(c)
	require.NoError(t, err)
	assert.False(t, r.alsoLocal, "CLI --also-local=false must override yaml also_local:true")
}

func TestResolveAgentConfig_AlsoLocal_DefaultFalse(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	agentConfigDir = emptyDir
	t.Cleanup(func() { agentConfigDir = "" })
	agentAlsoLocal = false
	cmd := newAgentTestCmd(t, false)

	r, err := resolveAgentConfig(cmd)
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

	err := dispatchScanResult(context.Background(), r, nil, dispatchTestScan(), io.Discard)
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

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan(), io.Discard)
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

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan(), io.Discard)
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

	// Capture the warning via an injected writer rather than
	// swapping os.Stderr — the global swap is racy under -race
	// because any other goroutine writing to os.Stderr concurrently
	// (e.g. the go test runner's internal logging) touches the same
	// global.
	var warnBuf bytes.Buffer

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan(), &warnBuf)
	require.NoError(t, err, "tee mode with local failure + server success must NOT return an error")

	assert.Contains(t, warnBuf.String(), "Warning: local report write failed",
		"local-failure warning must be emitted so operators can diagnose")
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

	err := dispatchScanResult(context.Background(), r, client, dispatchTestScan(), io.Discard)
	require.Error(t, err, "server-submit failure must propagate even if local write succeeded")
	assert.Contains(t, err.Error(), "submit failed")

	// Local directory should still have the report from the
	// successful local write — that's the forensic backup.
	entries, _ := os.ReadDir(tmp)
	assert.Len(t, entries, 1, "local write should have completed even though submit failed")
}
