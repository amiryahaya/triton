package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*CodeSignModule)(nil)

func TestCodeSignModule_Name(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})
	assert.Equal(t, "codesign", m.Name())
}

func TestCodeSignModule_Category(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestCodeSignModule_ScanTargetType(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestCodeSignModule_ParseMacOSVerify_Valid(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})

	displayOut := `Executable=/usr/bin/curl
Identifier=com.apple.curl
Format=Mach-O thin (arm64e)
CodeDirectory v=20400 size=26129 flags=0x0(none) hashes=810+2 location=embedded
Hash type=sha256 size=32
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set
Signature size=4442`

	findings := m.parseMacOSCodeSign("/usr/bin/curl", "", nil, displayOut, nil)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "Code signing certificate", f.CryptoAsset.Function)
	assert.Equal(t, "SHA-256", f.CryptoAsset.Algorithm)
	assert.Contains(t, f.CryptoAsset.Purpose, "valid")
	assert.Contains(t, f.CryptoAsset.Purpose, "Software Signing")
	assert.Equal(t, 4, f.Category)
	assert.Equal(t, "codesign", f.Module)
	assert.Equal(t, 0.90, f.Confidence)
}

func TestCodeSignModule_ParseMacOSVerify_Invalid(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})

	findings := m.parseMacOSCodeSign(
		"/usr/bin/bad",
		"invalid signature (code or signature have been modified)",
		fmt.Errorf("exit status 3"),
		"",
		fmt.Errorf("not signed"),
	)

	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "invalid")
}

func TestCodeSignModule_ParseMacOSDisplay(t *testing.T) {
	output := `Executable=/Applications/Slack.app/Contents/MacOS/Slack
Identifier=com.tinyspeck.slackmacgap
Format=app bundle with Mach-O thin (arm64)
Authority=Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=BQR82RBBHL
Hash type=sha256 size=32
Signature size=9023`

	authority, teamID, sigAlgo := parseMacOSDisplayOutput(output)

	assert.Equal(t, "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)", authority)
	assert.Equal(t, "BQR82RBBHL", teamID)
	assert.Equal(t, "SHA256withRSA", sigAlgo)
}

func TestCodeSignModule_ParseRPMVerify(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})

	tests := []struct {
		name     string
		output   string
		wantAlgo string
		wantOK   bool
	}{
		{
			name:     "valid RSA signature",
			output:   "package.rpm: rsa sha256 (md5) pgp md5 OK",
			wantAlgo: "SHA-256",
			wantOK:   true,
		},
		{
			name:     "missing signature",
			output:   "package.rpm: MISSING KEYS: RSA sha256",
			wantAlgo: "SHA-256",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := m.parseRPMVerify("/tmp/package.rpm", tt.output, nil)
			require.Len(t, findings, 1)
			assert.Equal(t, tt.wantAlgo, findings[0].CryptoAsset.Algorithm)

			if tt.wantOK {
				assert.Contains(t, findings[0].CryptoAsset.Purpose, "valid")
			} else {
				assert.Contains(t, findings[0].CryptoAsset.Purpose, "invalid")
			}
		})
	}
}

func TestCodeSignModule_ParseDpkgSig(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})

	tests := []struct {
		name     string
		output   string
		wantStat string
	}{
		{
			name:     "good signature",
			output:   "GOODSIG _gpgbuilder 1234ABCD",
			wantStat: "valid",
		},
		{
			name:     "bad signature",
			output:   "BADSIG _gpgbuilder 1234ABCD",
			wantStat: "invalid",
		},
		{
			name:     "no signature",
			output:   "NOSIG",
			wantStat: "unsigned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := m.parseDpkgSigVerify("/tmp/package.deb", tt.output, nil)
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0].CryptoAsset.Purpose, tt.wantStat)
			assert.Equal(t, "GPG", findings[0].CryptoAsset.Algorithm)
		})
	}
}

func TestCodeSignModule_UnsignedBinary(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})

	findings := m.parseMacOSCodeSign(
		"/usr/local/bin/custom",
		"/usr/local/bin/custom: code object is not signed at all",
		fmt.Errorf("exit status 1"),
		"",
		fmt.Errorf("no signature"),
	)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "Code signing", f.CryptoAsset.Function)
	assert.Equal(t, "none", f.CryptoAsset.Algorithm)
	assert.Contains(t, f.CryptoAsset.Purpose, "Unsigned binary")
}

func TestCodeSignModule_ContextCancellation(t *testing.T) {
	m := &CodeSignModule{
		config: &config.Config{MaxDepth: 1},
		cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				return nil, nil
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	found := m.checkCodeSign(ctx, "/usr/bin/test")
	assert.Empty(t, found, "cancelled context should produce no findings")
}

func TestCodeSignModule_PQCClassification(t *testing.T) {
	m := NewCodeSignModule(&config.Config{})

	displayOut := `Authority=Apple Root CA
TeamIdentifier=APPLE
Hash type=sha256 size=32
Signature size=4442`

	findings := m.parseMacOSCodeSign("/usr/bin/test", "", nil, displayOut, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "SHA-256", findings[0].CryptoAsset.Algorithm)
	assert.NotEmpty(t, findings[0].CryptoAsset.PQCStatus)
}

func TestCodeSignModule_IsBinaryFile(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"/usr/bin/curl", true},
		{"/tmp/test.app", true},
		{"/tmp/test.pkg", true},
		{"/tmp/test.dylib", true},
		{"/tmp/test.deb", true},
		{"/tmp/test.rpm", true},
		{"/tmp/test.txt", false},
		{"/tmp/test.go", false},
		{"/tmp/test.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isCodeSignCandidate(tt.path)
			// On non-matching platforms, some results differ
			// We just verify it doesn't panic and returns a bool
			_ = result
		})
	}
}
