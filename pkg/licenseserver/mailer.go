package licenseserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Mailer sends transactional emails from the license server. Currently
// used for admin invite delivery after org provisioning (Phase 1.8); may
// grow to cover password reset and other flows later.
//
// Implementations must be safe for concurrent use. A nil Mailer is
// valid and means "don't send emails" — handlers check for nil before
// calling and fall back to returning credentials in the API response
// for out-of-band delivery.
type Mailer interface {
	SendInviteEmail(ctx context.Context, data InviteEmailData) error
}

// InviteEmailData is the content of an admin-invite email. The license
// server constructs this after successful report server provisioning
// and passes it to the Mailer.
type InviteEmailData struct {
	ToEmail      string // recipient address
	ToName       string // recipient name (used in greeting and From-header)
	OrgName      string // the org they've been invited to admin
	TempPassword string // one-time temporary password
	LoginURL     string // where to log in (report server URL)
}

// ResendMailer sends email via the Resend API (https://resend.com).
// Uses a plain-text body by default; HTML templating can be added later.
type ResendMailer struct {
	apiKey           string
	fromEmail        string
	fromName         string
	httpClient       *http.Client
	endpointOverride string // test-only — overrides the Resend API URL
}

// NewResendMailer constructs a ResendMailer. Returns nil if any of the
// required fields are empty — callers should check and fall back to
// out-of-band credential delivery.
func NewResendMailer(apiKey, fromEmail, fromName string) *ResendMailer {
	if apiKey == "" || fromEmail == "" {
		return nil
	}
	return &ResendMailer{
		apiKey:     apiKey,
		fromEmail:  fromEmail,
		fromName:   fromName,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// resendEndpoint is the Resend API URL for sending emails. Overridable
// via the internal field for testing; production always uses the real
// api.resend.com endpoint.
const resendEndpoint = "https://api.resend.com/emails"

// apiEndpoint is used for testing — defaults to the public Resend API
// but can be overridden via WithEndpoint.
func (m *ResendMailer) apiEndpoint() string {
	if m.endpointOverride != "" {
		return m.endpointOverride
	}
	return resendEndpoint
}

// WithEndpoint returns a copy of the mailer with a different endpoint
// URL. Used by tests to point the mailer at httptest.NewServer.
func (m *ResendMailer) WithEndpoint(url string) *ResendMailer {
	copied := *m
	copied.endpointOverride = url
	return &copied
}

// SendInviteEmail constructs and sends the admin-invite message.
// Returns a non-nil error if the Resend API rejects the request or
// is unreachable. The license server's handleCreateOrg treats email
// failure as non-fatal — the temp password is already in the API
// response for manual delivery.
func (m *ResendMailer) SendInviteEmail(ctx context.Context, data InviteEmailData) error {
	subject := fmt.Sprintf("You've been invited to Triton Reports — %s", data.OrgName)

	textBody := fmt.Sprintf(`Hi %s,

You've been added as an administrator for %s on Triton Reports.

Sign in at: %s
Email: %s
Temporary password: %s

You'll be prompted to change your password on first sign-in.

— Triton Reports
`, data.ToName, data.OrgName, data.LoginURL, data.ToEmail, data.TempPassword)

	req := resendSendRequest{
		From:    fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail),
		To:      []string{data.ToEmail},
		Subject: subject,
		Text:    textBody,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling invite email: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.apiEndpoint(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building invite request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+m.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending invite: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a capped portion of the body for the error message.
		limited := io.LimitReader(resp.Body, 4<<10)
		respBody, _ := io.ReadAll(limited)
		return fmt.Errorf("resend returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// resendSendRequest mirrors the subset of the Resend API request body
// that the license server sends. See https://resend.com/docs/api-reference/emails/send-email
type resendSendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text,omitempty"`
	HTML    string   `json:"html,omitempty"`
}
