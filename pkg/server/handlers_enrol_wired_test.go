//go:build integration

package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/manage_enrol"
	"github.com/amiryahaya/triton/pkg/server/manage_enrol/engineadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// stubLicenseValidator always returns the configured features + tenant.
type stubLicenseValidator struct {
	features manage_enrol.EnrolFeatures
	tenant   string
	err      error
}

func (s *stubLicenseValidator) Validate(_ context.Context, _ string) (manage_enrol.EnrolFeatures, string, error) {
	return s.features, s.tenant, s.err
}

// buildWiredServer stands up a real *server.Server with a fully-wired
// manage_enrol.EnrolHandlers, an in-DB engine CA, and ServiceKeyAuth.
// The test is an integration test (hits the shared test DB) because
// manage_enrol.PostgresStore.Create requires a real pool, and the engine
// CA store likewise.
func buildWiredServer(t *testing.T, validator *stubLicenseValidator) (*server.Server, *store.PostgresStore, string, uuid.UUID) {
	t.Helper()

	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	db, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, db.TruncateAll(ctx))
	_, _ = db.Pool().Exec(ctx, `TRUNCATE manage_instances`)
	_, _ = db.Pool().Exec(ctx, `TRUNCATE engines, engine_cas CASCADE`)
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(), `TRUNCATE manage_instances`)
		_, _ = db.Pool().Exec(context.Background(), `TRUNCATE engines, engine_cas CASCADE`)
		_ = db.TruncateAll(context.Background())
		db.Close()
	})

	// Bootstrap an engine CA under a fresh org.
	master := make([]byte, 32)
	_, err = rand.Read(master)
	require.NoError(t, err)

	engineStore := engine.NewPostgresStore(db.Pool())
	ca, err := engine.GenerateCA(master)
	require.NoError(t, err)

	orgID := uuid.Must(uuid.NewV7())
	_, err = db.Pool().Exec(ctx,
		`INSERT INTO organizations (id, name, created_at, updated_at)
		 VALUES ($1, $2, NOW(), NOW())`,
		orgID, "manage-enrol-wired-test",
	)
	require.NoError(t, err)
	require.NoError(t, engineStore.UpsertCA(ctx, orgID, ca))

	mstore := manage_enrol.NewPostgresStore(db.Pool())
	caProvider := engineadapter.New(engineStore, master, orgID)
	handlers := &manage_enrol.EnrolHandlers{
		CA:              caProvider,
		ManageStore:     mstore,
		ReportPublicURL: "https://reports.example.test",
		LicenseClient:   validator,
	}

	const serviceKey = "test-service-key-wired"
	cfg := &server.Config{
		ListenAddr:          ":0",
		ServiceKey:          serviceKey,
		ManageEnrolHandlers: handlers,
		DisableSetupGuard:   true,
	}
	srv, err := server.New(cfg, db)
	require.NoError(t, err)
	return srv, db, serviceKey, orgID
}

func postEnrolWired(t *testing.T, srv *server.Server, serviceKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/manage", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-Service-Key", serviceKey)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

// TestEnrolManage_ReturnsBundle — with EnrolHandlers wired, a valid POST
// returns a gzipped tar bundle and persists a manage_instances row.
func TestEnrolManage_ReturnsBundle(t *testing.T) {
	srv, db, key, _ := buildWiredServer(t, &stubLicenseValidator{
		features: manage_enrol.EnrolFeatures{Manage: true},
		tenant:   "tenant-abc",
	})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	instanceID := uuid.Must(uuid.NewV7())
	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "lic-test",
	    "public_key_pem": %q
	}`, instanceID.String(), string(pubPEM))

	w := postEnrolWired(t, srv, key, body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "application/x-gzip", w.Header().Get("Content-Type"))
	assert.NotEmpty(t, w.Body.Bytes(), "bundle body must be present")

	var count int
	err = db.Pool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM manage_instances WHERE id = $1`, instanceID,
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "manage_instances row must be persisted")
}

// TestEnrolManage_RejectsWhenFeatureManageFalse — licence validator returns
// features.manage=false → 403.
func TestEnrolManage_RejectsWhenFeatureManageFalse(t *testing.T) {
	srv, _, key, _ := buildWiredServer(t, &stubLicenseValidator{
		features: manage_enrol.EnrolFeatures{Manage: false},
	})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	body := fmt.Sprintf(`{
	    "manage_instance_id": %q,
	    "license_key": "lic-no-manage",
	    "public_key_pem": %q
	}`, uuid.Must(uuid.NewV7()).String(), string(pubPEM))

	w := postEnrolWired(t, srv, key, body)
	assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, strings.ToLower(w.Body.String()), "manage")
}
