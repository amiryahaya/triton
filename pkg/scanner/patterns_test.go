package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLiteralPatternMatch(t *testing.T) {
	p := lit("hashlib.sha256", "SHA-256", "Hash function", "api-call")

	assert.True(t, p.Match("import hashlib; h = hashlib.sha256(data)"))
	assert.False(t, p.Match("import hashlib; h = hashlib.sha512(data)"))
	assert.Equal(t, PatternLiteral, p.Kind)
	assert.Equal(t, "SHA-256", p.Algorithm)
	assert.Equal(t, "api-call", p.DetectionMethod)
}

func TestRegexPatternMatch(t *testing.T) {
	p := rx(`(?i)AES[-_]?256[-_]?GCM`, "AES-256-GCM", "Symmetric encryption", "string")

	assert.True(t, p.Match("using AES-256-GCM cipher"))
	assert.True(t, p.Match("aes_256_gcm mode"))
	assert.True(t, p.Match("AES256GCM"))
	assert.False(t, p.Match("AES-128-GCM"))
	assert.Equal(t, PatternRegex, p.Kind)
}

func TestPatternHelperFields(t *testing.T) {
	l := lit("test", "ALGO", "Function", "import")
	assert.Equal(t, "test", l.Literal)
	assert.Equal(t, "ALGO", l.Algorithm)
	assert.Equal(t, "Function", l.Function)
	assert.Equal(t, "import", l.DetectionMethod)
	assert.Nil(t, l.Regex)

	r := rx(`test`, "ALGO2", "Function2", "symbol")
	assert.Equal(t, "", r.Literal)
	assert.Equal(t, "ALGO2", r.Algorithm)
	assert.NotNil(t, r.Regex)
}
