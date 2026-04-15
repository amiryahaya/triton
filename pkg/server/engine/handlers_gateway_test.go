package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// gwRequest builds a POST request with an engine already stashed in
// context (simulating MTLSMiddleware having run upstream).
func gwRequest(method, url string, eng *Engine) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.RemoteAddr = "10.0.0.5:54321"
	if eng != nil {
		ctx := context.WithValue(req.Context(), mtlsCtxKey{}, eng)
		req = req.WithContext(ctx)
	}
	return req
}

func TestEnroll_FirstCall_SetsFirstSeenAndReturnsOnline(t *testing.T) {
	store := newFakeStore()
	engID := uuid.New()
	store.engines[engID] = Engine{ID: engID, OrgID: uuid.New(), Label: "e1", Status: StatusEnrolled}

	h := NewGatewayHandlers(store)
	req := gwRequest(http.MethodPost, "/enroll", &Engine{ID: engID, Status: StatusEnrolled})
	rec := httptest.NewRecorder()
	h.Enroll(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "online" {
		t.Errorf("status = %q, want online", body["status"])
	}
	if body["engine_id"] != engID.String() {
		t.Errorf("engine_id = %q, want %s", body["engine_id"], engID)
	}
	if len(store.firstSeenCalls) != 1 || store.firstSeenCalls[0] != engID {
		t.Errorf("RecordFirstSeen calls = %v, want [%s]", store.firstSeenCalls, engID)
	}
	if store.engines[engID].FirstSeenAt == nil {
		t.Error("FirstSeenAt was not set on engine row")
	}
}

func TestEnroll_Idempotent_SecondCall_NoExtraFirstSeenWrite(t *testing.T) {
	store := newFakeStore()
	engID := uuid.New()
	store.engines[engID] = Engine{ID: engID, OrgID: uuid.New(), Label: "e1", Status: StatusEnrolled}

	h := NewGatewayHandlers(store)

	// First call — uses the "no FirstSeen yet" copy so the handler
	// goes through RecordFirstSeen.
	req1 := gwRequest(http.MethodPost, "/enroll", &Engine{ID: engID, Status: StatusEnrolled})
	rec1 := httptest.NewRecorder()
	h.Enroll(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status = %d", rec1.Code)
	}

	// Second call — supplies an engine context that already has
	// FirstSeenAt populated (as the mTLS middleware would resolve
	// from the row), so the handler must skip the write.
	seen := store.engines[engID].FirstSeenAt
	if seen == nil {
		t.Fatalf("precondition: first call should have set FirstSeenAt")
	}
	req2 := gwRequest(http.MethodPost, "/enroll", &Engine{
		ID: engID, Status: StatusOnline, FirstSeenAt: seen,
	})
	rec2 := httptest.NewRecorder()
	h.Enroll(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second status = %d", rec2.Code)
	}
	if len(store.firstSeenCalls) != 1 {
		t.Errorf("RecordFirstSeen call count = %d, want 1 (idempotent)", len(store.firstSeenCalls))
	}
}

func TestEnroll_NoEngineInContext_500(t *testing.T) {
	h := NewGatewayHandlers(newFakeStore())
	req := gwRequest(http.MethodPost, "/enroll", nil)
	rec := httptest.NewRecorder()
	h.Enroll(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestHeartbeat_UpdatesLastPoll_204(t *testing.T) {
	store := newFakeStore()
	engID := uuid.New()
	store.engines[engID] = Engine{ID: engID, OrgID: uuid.New(), Label: "e1", Status: StatusOnline}

	h := NewGatewayHandlers(store)
	req := gwRequest(http.MethodPost, "/heartbeat", &Engine{ID: engID, Status: StatusOnline})
	rec := httptest.NewRecorder()
	h.Heartbeat(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if len(store.pollCalls) != 1 || store.pollCalls[0] != engID {
		t.Errorf("RecordPoll calls = %v, want [%s]", store.pollCalls, engID)
	}
	if store.engines[engID].LastPollAt == nil {
		t.Error("LastPollAt was not set")
	}
}

func TestIPFromRemote(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678":       "1.2.3.4",
		"[::1]:443":          "::1",
		"[2001:db8::1]:9999": "2001:db8::1",
		"":                   "",
	}
	for in, want := range cases {
		if got := ipFromRemote(in); got != want {
			t.Errorf("ipFromRemote(%q) = %q, want %q", in, got, want)
		}
	}
}
