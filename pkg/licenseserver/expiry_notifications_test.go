package licenseserver_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// stubStoreExpiry implements licensestore.Store for expiry notification tests.
// Embeds the interface so unimplemented methods panic — tests only call the
// three methods needed by sendExpiryNotifications.
type stubStoreExpiry struct {
	licensestore.Store
	licenses []licensestore.LicenseWithOrg
	marked   []string // "<id>/<interval>" pairs recorded by MarkLicenseNotified
	users    []licensestore.User
}

func (s *stubStoreExpiry) ListExpiringLicenses(_ context.Context, _ time.Duration) ([]licensestore.LicenseWithOrg, error) {
	return s.licenses, nil
}

func (s *stubStoreExpiry) MarkLicenseNotified(_ context.Context, id, interval string) error {
	s.marked = append(s.marked, id+"/"+interval)
	return nil
}

func (s *stubStoreExpiry) ListUsers(_ context.Context, _ licensestore.UserFilter) ([]licensestore.User, error) {
	return s.users, nil
}

// stubMailerExpiry records SendExpiryWarningEmail calls.
type stubMailerExpiry struct {
	calls  atomic.Int32
	lastTo atomic.Value // string
}

func (m *stubMailerExpiry) SendInviteEmail(_ context.Context, _ mailer.InviteEmailData) error {
	panic("SendInviteEmail called unexpectedly in expiry test")
}

func (m *stubMailerExpiry) SendExpiryWarningEmail(_ context.Context, to string, _ mailer.ExpiryWarningEmailData) error {
	m.calls.Add(1)
	m.lastTo.Store(to)
	return nil
}

func TestSendExpiryNotifications_SendsToAdminsAndContact(t *testing.T) {
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{
				LicenseID:    "lic-001",
				OrgID:        "org-001",
				OrgName:      "NACSA",
				ContactName:  "Ahmad",
				ContactEmail: "ahmad@nacsa.gov.my",
				ExpiresAt:    time.Now().Add(20 * 24 * time.Hour),
			},
		},
		users: []licensestore.User{
			{ID: "u1", Email: "admin@triton.io", Name: "Triton Admin", Role: "platform_admin"},
		},
	}
	m := &stubMailerExpiry{}

	srv := licenseserver.NewForTest(stub, m)
	srv.TriggerExpiryCheck(context.Background())

	// License is 20 days out → matches 30d window; 7d and 1d windows return same licenses
	// but needs 7d and 1d Notified fields nil too. For each window that needs notification:
	// 1 admin + 1 contact = 2 sends per window. All 3 windows match → 6 sends total.
	// BUT: after 30d is "marked" (in stub, mark is a no-op that doesn't set NotifiedAt),
	// 7d and 1d also see the same license with nil notified fields → 6 sends.
	assert.Equal(t, int32(6), m.calls.Load())
	assert.Len(t, stub.marked, 3) // marked once per interval
}

func TestSendExpiryNotifications_SkipsAlreadyNotified30d(t *testing.T) {
	now := time.Now()
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{
				LicenseID:     "lic-001",
				ExpiresAt:     now.Add(20 * 24 * time.Hour),
				Notified30dAt: &now, // already notified for 30d
				// 7d and 1d are nil but 20-day-out license won't be in 7d/1d windows
				// (the stub returns the same licenses for all windows)
			},
		},
		users: []licensestore.User{
			{ID: "u1", Email: "admin@triton.io", Name: "Admin", Role: "platform_admin"},
		},
	}
	m := &stubMailerExpiry{}

	srv := licenseserver.NewForTest(stub, m)
	srv.TriggerExpiryCheck(context.Background())

	// 30d: already notified (skip). 7d: Notified7dAt is nil → send 1 admin (no contact).
	// 1d: Notified1dAt is nil → send 1 admin. Total: 2 sends, 2 marks.
	assert.Equal(t, int32(2), m.calls.Load())
	assert.Len(t, stub.marked, 2)
}

func TestSendExpiryNotifications_SkipsEmptyContactEmail(t *testing.T) {
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{
				LicenseID:    "lic-001",
				ExpiresAt:    time.Now().Add(20 * 24 * time.Hour),
				ContactEmail: "", // no contact email
			},
		},
		users: []licensestore.User{
			{ID: "u1", Email: "admin@triton.io", Name: "Admin", Role: "platform_admin"},
		},
	}
	m := &stubMailerExpiry{}

	srv := licenseserver.NewForTest(stub, m)
	srv.TriggerExpiryCheck(context.Background())

	// Only admin emails sent (no contact). 3 windows × 1 admin = 3 sends, 3 marks.
	assert.Equal(t, int32(3), m.calls.Load())
	assert.Len(t, stub.marked, 3)
}

func TestSendExpiryNotifications_NilMailer(t *testing.T) {
	stub := &stubStoreExpiry{
		licenses: []licensestore.LicenseWithOrg{
			{LicenseID: "lic-001", ExpiresAt: time.Now().Add(5 * 24 * time.Hour)},
		},
	}
	srv := licenseserver.NewForTest(stub, nil)
	// Must not panic and must return immediately
	srv.TriggerExpiryCheck(context.Background())
	// no assertions needed — just verify no panic
}
