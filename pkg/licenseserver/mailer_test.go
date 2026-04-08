package licenseserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResendServer returns an httptest server that records the last
// email payload received and emits the given response status/body.
func fakeResendServer(t *testing.T, status int, wantAPIKey string) (*httptest.Server, *resendSendRequest) {
	t.Helper()
	var received resendSendRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		auth := r.Header.Get("Authorization")
		if wantAPIKey != "" && auth != "Bearer "+wantAPIKey {
			http.Error(w, "wrong api key", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "email-123"})
	}))
	t.Cleanup(func() { ts.Close() })
	return ts, &received
}

// --- Construction ---

func TestNewResendMailer_EmptyFieldsReturnsNil(t *testing.T) {
	assert.Nil(t, NewResendMailer("", "from@test.com", "Triton"))
	assert.Nil(t, NewResendMailer("api-key", "", "Triton"))
	// Empty fromName is allowed (rare but not disallowed).
	assert.NotNil(t, NewResendMailer("api-key", "from@test.com", ""))
	assert.NotNil(t, NewResendMailer("api-key", "from@test.com", "Triton"))
}

// --- SendInviteEmail ---

func TestResendMailer_SendInviteEmail_Success(t *testing.T) {
	ts, received := fakeResendServer(t, http.StatusOK, "test-api-key")
	mailer := NewResendMailer("test-api-key", "noreply@example.com", "Triton Reports").WithEndpoint(ts.URL)

	err := mailer.SendInviteEmail(context.Background(), InviteEmailData{
		ToEmail:      "alice@acme.com",
		ToName:       "Alice Admin",
		OrgName:      "Acme Corp",
		TempPassword: "s3cr3t-p@ssw0rd",
		LoginURL:     "https://reports.example.com/login",
	})
	require.NoError(t, err)

	// Verify the Resend API received the right payload.
	assert.Equal(t, "Triton Reports <noreply@example.com>", received.From)
	require.Len(t, received.To, 1)
	assert.Equal(t, "alice@acme.com", received.To[0])
	assert.Contains(t, received.Subject, "Acme Corp")
	assert.Contains(t, received.Text, "Alice Admin")
	assert.Contains(t, received.Text, "s3cr3t-p@ssw0rd")
	assert.Contains(t, received.Text, "https://reports.example.com/login")
}

func TestResendMailer_SendInviteEmail_WrongAPIKey(t *testing.T) {
	ts, _ := fakeResendServer(t, http.StatusOK, "expected-key")
	mailer := NewResendMailer("wrong-key", "noreply@example.com", "Triton").WithEndpoint(ts.URL)

	err := mailer.SendInviteEmail(context.Background(), InviteEmailData{
		ToEmail: "a@b.c", ToName: "A", OrgName: "O", TempPassword: "p", LoginURL: "u",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestResendMailer_SendInviteEmail_ServerUnreachable(t *testing.T) {
	// Point at a closed port — connection refused.
	mailer := NewResendMailer("any-key", "noreply@example.com", "Triton").WithEndpoint("http://127.0.0.1:1")

	err := mailer.SendInviteEmail(context.Background(), InviteEmailData{
		ToEmail: "a@b.c", ToName: "A", OrgName: "O", TempPassword: "p", LoginURL: "u",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sending invite")
}

func TestResendMailer_SendInviteEmail_ResendErrorResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"invalid from address"}`))
	}))
	defer ts.Close()
	mailer := NewResendMailer("key", "bogus-address", "Triton").WithEndpoint(ts.URL)

	err := mailer.SendInviteEmail(context.Background(), InviteEmailData{
		ToEmail: "a@b.c", ToName: "A", OrgName: "O", TempPassword: "p", LoginURL: "u",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "422")
}

func TestResendMailer_SendInviteEmail_SubjectIncludesOrgName(t *testing.T) {
	ts, received := fakeResendServer(t, http.StatusOK, "key")
	mailer := NewResendMailer("key", "from@test.com", "Triton").WithEndpoint(ts.URL)
	_ = mailer.SendInviteEmail(context.Background(), InviteEmailData{
		ToEmail: "a@b.c", ToName: "A", OrgName: "MegaCorp", TempPassword: "p", LoginURL: "u",
	})
	assert.True(t, strings.Contains(received.Subject, "MegaCorp"))
}
