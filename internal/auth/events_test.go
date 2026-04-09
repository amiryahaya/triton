package auth

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestLogFailedLogin_NewlineInEmailIsNeutralized is the D1 regression
// from the Sprint 2 review: an attacker supplying a login request
// with a literal newline inside the email value MUST NOT be able to
// inject a fake log line. The newline must be escaped (`\n`) inside
// a quoted value, so the downstream log aggregator sees one
// structured event, not two.
func TestLogFailedLogin_NewlineInEmailIsNeutralized(t *testing.T) {
	out := captureLog(t, func() {
		LogFailedLogin("report", "bad_password",
			"alice@example.com\nevent=login_success server=attacker",
			"10.0.0.1", "bcrypt mismatch")
	})
	// Count how many "event=login_failure" and "event=login_success"
	// substrings appear. Only ONE failure event should be present,
	// and NO success event — the success text must be inside the
	// quoted email value, not a standalone line.
	assert.Equal(t, 1, strings.Count(out, "event=login_failure"),
		"exactly one failure event must be emitted")
	// The injected "event=login_success" substring will literally
	// appear inside the quoted email value, but the `\n` between
	// it and the rest of the line must have been escaped to the
	// two-character sequence backslash-n.
	assert.Contains(t, out, `\nevent=login_success`,
		"injected newline must be escaped as \\n inside the quoted email")
	// Confirm the only occurrence of "event=login_success" is
	// preceded by the escape marker, proving the attacker did NOT
	// succeed in creating a standalone second log line.
	idx := strings.Index(out, "event=login_success")
	require.GreaterOrEqual(t, idx, 2)
	assert.Equal(t, `\n`, out[idx-2:idx],
		"login_success substring must be immediately preceded by escaped \\n, not a real newline")
}

// TestLogFailedLogin_CarriageReturnAndTabAlsoEscaped covers other
// common injection attempts against line-based parsers.
func TestLogFailedLogin_CarriageReturnAndTabAlsoEscaped(t *testing.T) {
	out := captureLog(t, func() {
		LogFailedLogin("report", "bad_password",
			"eve\r\tfoo@example.com", "1.2.3.4", "oops")
	})
	assert.Contains(t, out, `\r`)
	assert.Contains(t, out, `\t`)
	// Raw control bytes must not appear anywhere in the output.
	assert.NotContains(t, out, "\r\tfoo")
}

// TestKvValue_BackslashEscapedFirstThenQuote covers D2: a value
// containing a literal `\"` sequence must produce an unambiguous
// quoted form where the parser can correctly identify the closing
// quote. The contract is: escape backslashes first, then quotes.
func TestKvValue_BackslashEscapedFirstThenQuote(t *testing.T) {
	out := kvValue(`a\"b`)
	// Input bytes: a, \, ", b
	// Expected output: "a\\\"b"  (quoted, with \\ and \" inside)
	expected := `"a\\\"b"`
	assert.Equal(t, expected, out,
		"backslash must be escaped before quote so parsers can unambiguously detect the closing quote")
}

// TestKvValue_DelEscaped covers the 0x7f DEL character which is
// often overlooked by "control character" checks.
func TestKvValue_DelEscaped(t *testing.T) {
	out := kvValue("a\x7fb")
	assert.Equal(t, `"a\x7fb"`, out, "DEL (0x7f) must be hex-escaped")
}
