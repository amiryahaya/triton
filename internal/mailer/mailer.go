// Package mailer provides a shared transactional-email primitive used
// by both the license server (for org provisioning invites) and the
// report server (for resend-invite on stuck users). The interface is
// deliberately small — SendInviteEmail is the only method today — so
// a non-Resend backend (SMTP, SES, Postmark) can be dropped in without
// touching any handler.
//
// Extracted from pkg/licenseserver in Phase 5 Sprint 2 so the report
// server can push invite emails directly via the same backend instead
// of leaking temp-password material into JSON response bodies. See the
// Sprint 1 S3 review finding for rationale.
package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// Mailer sends transactional emails. Implementations MUST be safe for
// concurrent use. A nil Mailer is valid and means "don't send emails" —
// callers check for nil before calling and fall back to out-of-band
// credential delivery (API response body, admin UI modal, etc.).
type Mailer interface {
	SendInviteEmail(ctx context.Context, data InviteEmailData) error
	SendExpiryWarningEmail(ctx context.Context, to string, data ExpiryWarningEmailData) error
}

// InviteEmailData is the content of an admin/user-invite email.
type InviteEmailData struct {
	ToEmail      string // recipient address
	ToName       string // recipient name (used in greeting and From-header)
	OrgName      string // the org the recipient has been invited to
	TempPassword string // one-time temporary password
	LoginURL     string // where to log in (report server URL)
}

// ExpiryWarningEmailData is the content of a license expiry warning email.
type ExpiryWarningEmailData struct {
	RecipientName string // e.g. "Ahmad bin Ali" or "Platform Admin"
	OrgName       string // e.g. "NACSA"
	LicenseID     string
	ExpiresAt     time.Time
	DaysRemaining int // 30, 7, or 1
}

// ResendMailer sends email via the Resend API (https://resend.com).
// Plain-text body; HTML templating can be added later.
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

// SendInviteEmail constructs and sends the invite message. Returns a
// non-nil error if the Resend API rejects the request or is
// unreachable. Callers treat email failure as non-fatal in most flows
// and fall back to out-of-band delivery.
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
	// Forward the request ID so Resend dashboard correlations (and our
	// own logs) can trace the email back to the originating HTTP request.
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		httpReq.Header.Set("X-Request-ID", reqID)
	}

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

// SendExpiryWarningEmail constructs and sends a license expiry warning to
// the given recipient address. The subject line varies based on
// data.DaysRemaining (1, 7, or any other value). Returns a non-nil error
// if the Resend API rejects the request or is unreachable.
func (m *ResendMailer) SendExpiryWarningEmail(ctx context.Context, to string, data ExpiryWarningEmailData) error {
	var subject string
	switch data.DaysRemaining {
	case 1:
		subject = fmt.Sprintf("License expiring tomorrow — immediate action required (%s)", data.OrgName)
	case 7:
		subject = fmt.Sprintf("License expiring in 7 days — urgent (%s)", data.OrgName)
	default:
		subject = fmt.Sprintf("License expiring in %d days — action required (%s)", data.DaysRemaining, data.OrgName)
	}

	textBody := fmt.Sprintf(`Hi %s,

This is a reminder that the Triton license for %s is expiring soon.

License ID: %s
Expiry date: %s
Days remaining: %d

Please contact your Triton administrator to arrange a renewal before the expiry date to avoid service disruption.

— Triton License Server
`, data.RecipientName, data.OrgName, data.LicenseID,
		data.ExpiresAt.Format("2 Jan 2006"), data.DaysRemaining)

	req := resendSendRequest{
		From:    fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail),
		To:      []string{to},
		Subject: subject,
		Text:    textBody,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling expiry warning email: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.apiEndpoint(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building expiry warning request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+m.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		httpReq.Header.Set("X-Request-ID", reqID)
	}

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending expiry warning: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited := io.LimitReader(resp.Body, 4<<10)
		respBody, _ := io.ReadAll(limited)
		return fmt.Errorf("resend returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// resendSendRequest mirrors the subset of the Resend API request body
// that we send. See https://resend.com/docs/api-reference/emails/send-email
type resendSendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text,omitempty"`
	HTML    string   `json:"html,omitempty"`
}
