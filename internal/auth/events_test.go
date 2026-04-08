package auth

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// captureLog swaps log output to a buffer for the duration of fn,
// then returns whatever fn's log calls produced.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	fn()
	return buf.String()
}

func TestLogFailedLogin_EmitsStructuredKeyValue(t *testing.T) {
	out := captureLog(t, func() {
		LogFailedLogin("report", "bad_password", "alice@example.com", "10.0.0.1", "bcrypt mismatch")
	})
	assert.Contains(t, out, "event=login_failure")
	assert.Contains(t, out, "server=report")
	assert.Contains(t, out, "stage=bad_password")
	assert.Contains(t, out, "email=alice@example.com")
	assert.Contains(t, out, "ip=10.0.0.1")
	// reason contains whitespace, so must be quoted
	assert.Contains(t, out, `reason="bcrypt mismatch"`)
}

func TestLogFailedLogin_EmptyFieldsBecomeDash(t *testing.T) {
	out := captureLog(t, func() {
		LogFailedLogin("report", "unknown_email", "", "", "")
	})
	// An empty field becomes "-" (not "" which would collide with
	// a legitimately empty quoted value). IP missing in tests is
	// the common case.
	assert.Contains(t, out, "email=-")
	assert.Contains(t, out, "ip=-")
	assert.Contains(t, out, "reason=-")
}

func TestLogFailedLogin_QuotesContainingCharsEscaped(t *testing.T) {
	out := captureLog(t, func() {
		LogFailedLogin("report", "bad_password", `eve@"example".com`, "1.2.3.4", "nah")
	})
	// The embedded double-quote must be backslash-escaped so parsers
	// relying on the outer quoting contract aren't fooled.
	assert.Contains(t, out, `email="eve@\"example\".com"`)
}

func TestLogSuccessfulLogin_EmitsStructuredKeyValue(t *testing.T) {
	out := captureLog(t, func() {
		LogSuccessfulLogin("license", "bob@example.com", "10.0.0.2")
	})
	assert.Contains(t, out, "event=login_success")
	assert.Contains(t, out, "server=license")
	assert.Contains(t, out, "email=bob@example.com")
	assert.Contains(t, out, "ip=10.0.0.2")
}

// TestKvValue_EqualsInValueGetsQuoted ensures a value containing `=`
// (e.g., an email with an embedded equals — rare but legal) is
// quoted so the parser isn't confused about key boundaries.
func TestKvValue_EqualsInValueGetsQuoted(t *testing.T) {
	out := kvValue("a=b")
	assert.True(t, strings.HasPrefix(out, `"`), "equals must force quoting")
	assert.True(t, strings.HasSuffix(out, `"`))
}
