package fsadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockExec records commands and returns canned responses matched by substring.
type mockExec struct {
	responses map[string]string // substring → response
	lastCmd   string
}

func (m *mockExec) Run(_ context.Context, cmd string) (string, error) {
	m.lastCmd = cmd
	for pattern, resp := range m.responses {
		if strings.Contains(cmd, pattern) {
			return resp, nil
		}
	}
	return "", fmt.Errorf("no mock response for: %s", cmd)
}

func TestSshReader_ReadFile(t *testing.T) {
	payload := []byte("hello, world\n")
	encoded := base64.StdEncoding.EncodeToString(payload)

	m := &mockExec{responses: map[string]string{
		"base64": encoded,
	}}
	r := NewSshReader(m)

	data, err := r.ReadFile(context.Background(), "/etc/test")
	require.NoError(t, err)
	assert.Equal(t, payload, data)
	assert.Contains(t, m.lastCmd, "/etc/test")
}

func TestSshReader_Walk(t *testing.T) {
	// Simulate `find /etc -printf '%p\t%y\t%s\n'`
	output := "/etc\td\t4096\n/etc/foo.conf\tf\t123\n/etc/subdir\td\t4096\n/etc/subdir/bar\tf\t7\n"
	m := &mockExec{responses: map[string]string{
		"find": output,
	}}
	r := NewSshReader(m)

	var visited []string
	err := r.Walk(context.Background(), "/etc", func(path string, _ fs.DirEntry, _ error) error {
		visited = append(visited, path)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, visited, 4)
	assert.Contains(t, visited, "/etc/foo.conf")
	assert.Contains(t, visited, "/etc/subdir/bar")
}

func TestSshReader_Walk_BinarySafePath(t *testing.T) {
	// Filenames with spaces
	output := "/etc\td\t4096\n/etc/has space.conf\tf\t42\n"
	m := &mockExec{responses: map[string]string{
		"find": output,
	}}
	r := NewSshReader(m)

	var visited []string
	err := r.Walk(context.Background(), "/etc", func(path string, _ fs.DirEntry, _ error) error {
		visited = append(visited, path)
		return nil
	})
	require.NoError(t, err)
	assert.Contains(t, visited, "/etc/has space.conf")
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/etc/ssh/sshd_config": "'/etc/ssh/sshd_config'",
		"/tmp/with space":      "'/tmp/with space'",
		"/tmp/it's":            `'/tmp/it'\''s'`,
	}
	for in, want := range cases {
		assert.Equal(t, want, shellQuote(in))
	}
}

func TestTypeFromFindCode(t *testing.T) {
	assert.True(t, typeFromFindCode("d").IsDir())
	assert.True(t, typeFromFindCode("l")&fs.ModeSymlink != 0)
	assert.Equal(t, fs.FileMode(0), typeFromFindCode("f")) // regular file
}
