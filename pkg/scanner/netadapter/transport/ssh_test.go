package transport

import (
	"context"
	"os"
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
