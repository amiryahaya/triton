package engine

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// GatewayHandlers serves the /api/v1/engine/* mTLS-authenticated API
// (enroll + heartbeat). The engine identity is supplied by
// MTLSMiddleware via EngineFromContext; no JWT claims are involved.
type GatewayHandlers struct {
	Store Store
}

// NewGatewayHandlers wires a GatewayHandlers.
func NewGatewayHandlers(s Store) *GatewayHandlers {
	return &GatewayHandlers{Store: s}
}

// Enroll is the first-contact handshake. It is idempotent: on the
// initial call it claims first_seen_at and flips the engine to
// online; on any subsequent call it is a no-op that still returns
// 200 with the engine's current id + online status. Because the
// engine identity is already authenticated by mTLS, there is no
// secret to verify here.
func (h *GatewayHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
	eng := EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "engine not in context")
		return
	}

	alreadyEnrolled := eng.FirstSeenAt != nil
	ip := ipFromRemote(r.RemoteAddr)
	firstClaim, err := h.Store.RecordFirstSeen(r.Context(), eng.ID, ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "record first seen: "+err.Error())
		return
	}

	// If the engine was already enrolled when the mTLS middleware
	// resolved it, this is a legitimate idempotent re-enroll (restart,
	// network hiccup). If the middleware saw an un-enrolled engine but
	// RecordFirstSeen reports "not first", someone else just claimed
	// the bundle — reject the replay.
	if !alreadyEnrolled && !firstClaim {
		log.Printf("engine enroll replay rejected: engine_id=%s remote=%s",
			eng.ID, r.RemoteAddr)
		writeErr(w, http.StatusConflict, "bundle already claimed from a different source")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"engine_id": eng.ID.String(),
		"status":    "online",
	})
}

// Heartbeat bumps last_poll_at. Body is ignored (may be empty).
func (h *GatewayHandlers) Heartbeat(w http.ResponseWriter, r *http.Request) {
	eng := EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "engine not in context")
		return
	}
	if err := h.Store.RecordPoll(r.Context(), eng.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "record poll: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SubmitEncryptionPubkey is the mTLS-authenticated endpoint where an
// engine uploads its static X25519 public key. The portal echoes this
// pubkey back to operator browsers so the browser can seal secrets to
// it before POSTing a profile. Called once per engine lifetime (after
// first-contact keypair generation).
func (h *GatewayHandlers) SubmitEncryptionPubkey(w http.ResponseWriter, r *http.Request) {
	eng := EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "engine not in context")
		return
	}
	var body struct {
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.Pubkey)
	if err != nil || len(raw) != 32 {
		writeErr(w, http.StatusBadRequest, "invalid pubkey: expect 32-byte X25519 base64")
		return
	}
	if err := h.Store.SetEncryptionPubkey(r.Context(), eng.ID, raw); err != nil {
		writeErr(w, http.StatusInternalServerError, "set encryption pubkey: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ipFromRemote strips the :port suffix from a net/http RemoteAddr.
// IPv6 bracketed forms ("[::1]:1234") and plain IPv4 ("1.2.3.4:5678")
// both collapse cleanly. Returns the input unchanged if no port is
// found (which shouldn't happen for real http.Requests, but keeps the
// helper total).
func ipFromRemote(remote string) string {
	if remote == "" {
		return ""
	}
	// Strip bracketed IPv6.
	if strings.HasPrefix(remote, "[") {
		if end := strings.IndexByte(remote, ']'); end > 0 {
			return remote[1:end]
		}
	}
	if idx := strings.LastIndexByte(remote, ':'); idx >= 0 {
		// Only strip if the part before has no colons (IPv4) or was a
		// bracketed form (already handled above).
		if !strings.ContainsRune(remote[:idx], ':') {
			return remote[:idx]
		}
	}
	return remote
}
