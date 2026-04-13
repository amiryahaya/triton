package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeFindingKey_Deterministic(t *testing.T) {
	key1 := ComputeFindingKey("org-1", "web-srv1", "RSA", 2048, "certificate")
	key2 := ComputeFindingKey("org-1", "web-srv1", "RSA", 2048, "certificate")
	assert.Equal(t, key1, key2, "same inputs must produce same key")
	assert.Len(t, key1, 64, "SHA-256 hex = 64 chars")
}

func TestComputeFindingKey_DifferentInputs(t *testing.T) {
	key1 := ComputeFindingKey("org-1", "web-srv1", "RSA", 2048, "certificate")
	key2 := ComputeFindingKey("org-1", "web-srv1", "RSA", 4096, "certificate")
	key3 := ComputeFindingKey("org-1", "db-main", "RSA", 2048, "certificate")
	assert.NotEqual(t, key1, key2, "different key_size must produce different key")
	assert.NotEqual(t, key1, key3, "different hostname must produce different key")
}
