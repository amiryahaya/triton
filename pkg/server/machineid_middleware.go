package server

import (
	"context"
	"encoding/hex"
	"net/http"
)

const machineIDHeader = "X-Triton-Machine-ID"

type machineIDCtxKey struct{}

// MachineIDFromContext returns the SHA3-256-hex machine fingerprint
// that RequireMachineID stashed in context, or empty string if the
// middleware hasn't run.
func MachineIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(machineIDCtxKey{}).(string)
	return v
}

// RequireMachineID validates the X-Triton-Machine-ID header as a
// 64-character lowercase-hex string (SHA3-256 digest from
// license.MachineFingerprint()) and stashes it in the request context.
// Missing header → 401. Malformed value → 400.
func RequireMachineID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(machineIDHeader)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "missing "+machineIDHeader+" header")
			return
		}
		if len(raw) != 64 {
			writeError(w, http.StatusBadRequest, machineIDHeader+" must be 64 hex characters")
			return
		}
		if _, err := hex.DecodeString(raw); err != nil {
			writeError(w, http.StatusBadRequest, machineIDHeader+" must be hex: "+err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), machineIDCtxKey{}, raw)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
