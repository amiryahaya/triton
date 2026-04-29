package mailer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendExpiryWarningEmail_30d(t *testing.T) {
	var captured resendSendRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"test-id"}`))
	}))
	defer srv.Close()

	m := NewResendMailer("test-key", "no-reply@triton.io", "Triton").WithEndpoint(srv.URL)
	data := ExpiryWarningEmailData{
		RecipientName: "Ahmad bin Ali",
		OrgName:       "NACSA",
		LicenseID:     "lic-001",
		ExpiresAt:     time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		DaysRemaining: 30,
	}
	err := m.SendExpiryWarningEmail(context.Background(), "ahmad@nacsa.gov.my", data)
	require.NoError(t, err)

	assert.Equal(t, []string{"ahmad@nacsa.gov.my"}, captured.To)
	assert.Contains(t, captured.Subject, "30 days")
	assert.Contains(t, captured.Text, "NACSA")
	assert.Contains(t, captured.Text, "Ahmad bin Ali")
	assert.Contains(t, captured.Text, "1 Jun 2026")
}

func TestSendExpiryWarningEmail_SubjectVariants(t *testing.T) {
	tests := []struct {
		days            int
		subjectContains string
	}{
		{30, "30 days"},
		{7, "7 days"},
		{1, "tomorrow"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%dd", tc.days), func(t *testing.T) {
			var captured resendSendRequest
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &captured)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":"x"}`))
			}))
			defer srv.Close()

			m := NewResendMailer("key", "from@example.com", "T").WithEndpoint(srv.URL)
			data := ExpiryWarningEmailData{
				RecipientName: "Admin",
				OrgName:       "Org",
				LicenseID:     "lic-x",
				ExpiresAt:     time.Now().Add(time.Duration(tc.days) * 24 * time.Hour),
				DaysRemaining: tc.days,
			}
			err := m.SendExpiryWarningEmail(context.Background(), "admin@example.com", data)
			require.NoError(t, err)

			assert.Contains(t, captured.Subject, tc.subjectContains)
		})
	}
}
