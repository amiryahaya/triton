package sshagent_test

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/sshagent"
)

func TestScanner_Interface(t *testing.T) {
	// Compile-time: *SSHScanner must implement Scanner
	var _ sshagent.Scanner = (*sshagent.SSHScanner)(nil)
}
