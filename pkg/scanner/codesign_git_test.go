package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// `git log --format=%G?%n%GK%n%GF -n 5` emits, per commit:
//
//	G? = signature status (G = good, B = bad, U = unknown, N = none, X = expired, Y = expired key, R = revoked key, E = cannot be checked)
//	GK = signing key ID (e.g., an SSH fingerprint or a GPG key ID)
//	GF = signing key fingerprint
//
// We use the simpler `git tag -v <tag>` / `git verify-commit`
// output for classification since those are the documented
// release-signing tools.
const gitVerifyOutputGood = `object 1234567890abcdef
type commit
tag v1.2.3
tagger Alice <alice@example.com> 1700000000 +0000

Release v1.2.3

gpg: Signature made Mon 01 Jan 2024 00:00:00 UTC
gpg:                using RSA key ABCDEF1234567890
gpg: Good signature from "Alice <alice@example.com>" [ultimate]
`

const gitVerifyOutputSSH = `object 1234567890abcdef
type commit
tag v1.2.4

Release v1.2.4

Good "git" signature for alice@example.com with ED25519 key SHA256:abcdef1234567890
`

const gitVerifyOutputUnsigned = `object 1234567890abcdef
type commit
tag v1.2.5

Release v1.2.5 (unsigned release)
`

func TestCheckGitSignature_GPG_Good(t *testing.T) {
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(gitVerifyOutputGood), nil
	})
	findings := m.checkGitSignature(context.Background(), "/tmp/repo/v1.2.3")
	require.NotEmpty(t, findings)

	var signed *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(strings.ToUpper(f.CryptoAsset.Algorithm), "RSA") {
			signed = f
		}
	}
	require.NotNil(t, signed, "RSA-signed git tag should produce a finding")
	assert.Contains(t, signed.CryptoAsset.Subject, "alice@example.com")
}

func TestCheckGitSignature_SSH_Good(t *testing.T) {
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(gitVerifyOutputSSH), nil
	})
	findings := m.checkGitSignature(context.Background(), "/tmp/repo/v1.2.4")
	require.NotEmpty(t, findings)

	var ed *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(strings.ToUpper(f.CryptoAsset.Algorithm), "ED25519") {
			ed = f
		}
	}
	require.NotNil(t, ed, "SSH Ed25519 signed tag should produce a finding")
}

func TestCheckGitSignature_Unsigned(t *testing.T) {
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		// git exits with status 1 for unsigned tags, writing the
		// tag body to stdout with no signature block.
		return []byte(gitVerifyOutputUnsigned), errors.New("exit status 1")
	})
	findings := m.checkGitSignature(context.Background(), "/tmp/repo/v1.2.5")
	require.NotEmpty(t, findings)

	var unsigned *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "none" {
			unsigned = f
		}
	}
	require.NotNil(t, unsigned, "unsigned tag should produce an 'algorithm=none' finding")
}

func TestCheckGitSignature_ToolMissing(t *testing.T) {
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, errors.New(`exec: "git": executable file not found in $PATH`)
	})
	findings := m.checkGitSignature(context.Background(), "/tmp/repo/v1.2.6")
	require.NotEmpty(t, findings)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "git not on PATH")
}
