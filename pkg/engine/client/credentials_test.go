package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitEncryptionPubkey_Posts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newDirectClient(ts)
	pub := []byte{1, 2, 3, 4, 5}
	if err := c.SubmitEncryptionPubkey(context.Background(), pub); err != nil {
		t.Fatalf("SubmitEncryptionPubkey: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q", gotMethod)
	}
	if gotPath != "/api/v1/engine/encryption-pubkey" {
		t.Errorf("path = %q", gotPath)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotBody["pubkey"])
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	if string(decoded) != string(pub) {
		t.Errorf("pubkey round-trip failed: %v", decoded)
	}
}

func TestSubmitEncryptionPubkey_BadStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if err := c.SubmitEncryptionPubkey(context.Background(), []byte{1}); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestPollCredentialDelivery_204(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	got, err := c.PollCredentialDelivery(context.Background())
	if err != nil {
		t.Fatalf("PollCredentialDelivery: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestPollCredentialDelivery_200(t *testing.T) {
	payload := DeliveryPayload{
		ID: "d1", ProfileID: "p1", SecretRef: "r1", AuthType: "ssh-password",
		Kind: "push", Ciphertext: "YmFzZTY0",
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/engine/credentials/deliveries/poll" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	got, err := c.PollCredentialDelivery(context.Background())
	if err != nil {
		t.Fatalf("PollCredentialDelivery: %v", err)
	}
	if got == nil || got.ID != "d1" || got.Kind != "push" || got.Ciphertext != "YmFzZTY0" {
		t.Errorf("payload = %+v", got)
	}
}

func TestAckCredentialDelivery_NoError(t *testing.T) {
	var gotPath string
	var gotBody ackDeliveryBody
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if err := c.AckCredentialDelivery(context.Background(), "abc", ""); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if gotPath != "/api/v1/engine/credentials/deliveries/abc/ack" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody.Error != "" {
		t.Errorf("error body = %q, want empty", gotBody.Error)
	}
}

func TestAckCredentialDelivery_WithError(t *testing.T) {
	var gotBody ackDeliveryBody
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if err := c.AckCredentialDelivery(context.Background(), "abc", "boom"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if gotBody.Error != "boom" {
		t.Errorf("error = %q", gotBody.Error)
	}
}

func TestPollCredentialTest_204(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	got, err := c.PollCredentialTest(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil")
	}
}

func TestPollCredentialTest_200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/engine/credentials/tests/poll" {
			t.Errorf("path = %q", r.URL.Path)
		}
		job := TestJobPayload{
			ID: "t1", ProfileID: "p1", SecretRef: "r1", AuthType: "ssh-password",
			Hosts: []HostTarget{{ID: "h1", Address: "10.0.0.1", Port: 22}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	got, err := c.PollCredentialTest(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got == nil || got.ID != "t1" || len(got.Hosts) != 1 || got.Hosts[0].Address != "10.0.0.1" {
		t.Errorf("payload = %+v", got)
	}
}

func TestSubmitCredentialTest_Success(t *testing.T) {
	var gotPath string
	var gotBody submitTestBody
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	results := []SubmittedTestResult{
		{HostID: "h1", Success: true, LatencyMs: 42},
		{HostID: "h2", Success: false, Error: "nope"},
	}
	if err := c.SubmitCredentialTest(context.Background(), "t1", results, ""); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotPath != "/api/v1/engine/credentials/tests/t1/submit" {
		t.Errorf("path = %q", gotPath)
	}
	if len(gotBody.Results) != 2 || gotBody.Results[0].LatencyMs != 42 {
		t.Errorf("results = %+v", gotBody.Results)
	}
}

func TestSubmitCredentialTest_BadStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if err := c.SubmitCredentialTest(context.Background(), "t1", nil, "boom"); err == nil {
		t.Fatal("expected error")
	}
}
