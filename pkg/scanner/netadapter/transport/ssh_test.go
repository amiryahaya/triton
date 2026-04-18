package transport

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSHClient_LocalLoopback tests against a local SSH server if
// TRITON_SSH_TEST_HOST is set. Skipped by default (CI safe).
func TestSSHClient_LocalLoopback(t *testing.T) {
	addr := os.Getenv("TRITON_SSH_TEST_HOST")
	user := os.Getenv("TRITON_SSH_TEST_USER")
	key := os.Getenv("TRITON_SSH_TEST_KEY")
	if addr == "" || user == "" || key == "" {
		t.Skip("SSH test requires TRITON_SSH_TEST_{HOST,USER,KEY} env vars")
	}

	keyBytes, err := os.ReadFile(key)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := NewSSHClient(ctx, SSHConfig{
		Address:    addr,
		Username:   user,
		PrivateKey: keyBytes,
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	out, err := client.Run(ctx, "echo hello")
	require.NoError(t, err)
	assert.Contains(t, out, "hello")
}

func TestBuildAuth_NoMethods(t *testing.T) {
	_, err := buildAuth(SSHConfig{Username: "u"})
	assert.Error(t, err)
}

func TestBuildAuth_PasswordOnly(t *testing.T) {
	methods, err := buildAuth(SSHConfig{Username: "u", Password: "p"})
	require.NoError(t, err)
	assert.Len(t, methods, 1)
}

func TestSSHClient_Upload_LocalFileValidation(t *testing.T) {
	// Upload must reject nonexistent local file with a clear error,
	// without requiring a real SSH connection (short-circuits on stat).
	c := &SSHClient{cmdTimeout: 5 * time.Second}
	err := c.Upload(context.Background(), "/nonexistent/file/triton", "/tmp/out", 0o755)
	if err == nil {
		t.Fatal("Upload should fail on nonexistent local file")
	}
	if !strings.Contains(err.Error(), "open local file") {
		t.Errorf("error should mention 'open local file', got %v", err)
	}
}
