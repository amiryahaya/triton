package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineIDMiddleware_Valid(t *testing.T) {
	var captured string
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = MachineIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	valid := strings.Repeat("a", 64)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Triton-Machine-ID", valid)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, valid, captured)
}

func TestMachineIDMiddleware_Missing(t *testing.T) {
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMachineIDMiddleware_InvalidLength(t *testing.T) {
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Triton-Machine-ID", "too-short")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMachineIDMiddleware_NonHex(t *testing.T) {
	h := RequireMachineID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Triton-Machine-ID", strings.Repeat("z", 64))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "hex")
}
