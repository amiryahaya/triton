//go:build integration

package scanjobs_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/managestore"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TRITON_TEST_DB_URL")
	if dsn == "" {
		dsn = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	ms, err := managestore.NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("managestore: %v", err)
	}
	if err := ms.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := pool.Exec(context.Background(), "TRUNCATE manage_scan_jobs CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func TestListQueued_FiltersJobType(t *testing.T) {
	pool := testPool(t)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.New()
	hostID := uuid.New()

	insertJob := func(jobType string) {
		_, err := pool.Exec(context.Background(),
			`INSERT INTO manage_scan_jobs (id, tenant_id, host_id, profile, status, job_type)
			 VALUES ($1, $2, $3, 'standard', 'queued', $4)`,
			uuid.New(), tenantID, hostID, jobType)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insertJob("filesystem")
	insertJob("port_survey")

	jobs, err := store.ListQueued(context.Background(), []string{"port_survey"}, 10)
	if err != nil {
		t.Fatalf("ListQueued: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected 1 port_survey job, got %d", len(jobs))
	}
	if jobs[0].JobType != scanjobs.JobTypePortSurvey {
		t.Errorf("job type: got %q", jobs[0].JobType)
	}
}

func TestClaimByID_Transitions(t *testing.T) {
	pool := testPool(t)
	store := scanjobs.NewPostgresStore(pool)
	tenantID, hostID := uuid.New(), uuid.New()
	jobID := uuid.New()

	_, err := pool.Exec(context.Background(),
		`INSERT INTO manage_scan_jobs (id, tenant_id, host_id, profile, status, job_type)
		 VALUES ($1, $2, $3, 'standard', 'queued', 'port_survey')`,
		jobID, tenantID, hostID)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	job, err := store.ClaimByID(context.Background(), jobID, "worker-1")
	if err != nil {
		t.Fatalf("ClaimByID first: %v", err)
	}
	if job.Status != scanjobs.StatusRunning {
		t.Errorf("status: got %q, want running", job.Status)
	}

	_, err = store.ClaimByID(context.Background(), jobID, "worker-2")
	if !errors.Is(err, scanjobs.ErrAlreadyClaimed) {
		t.Errorf("second claim: expected ErrAlreadyClaimed, got %v", err)
	}

	_, err = store.ClaimByID(context.Background(), uuid.New(), "worker-3")
	if !errors.Is(err, scanjobs.ErrNotFound) {
		t.Errorf("missing job: expected ErrNotFound, got %v", err)
	}
}

func TestClaimNext_FilesystemOnly(t *testing.T) {
	pool := testPool(t)
	store := scanjobs.NewPostgresStore(pool)
	tenantID, hostID := uuid.New(), uuid.New()

	_, err := pool.Exec(context.Background(),
		`INSERT INTO manage_scan_jobs (id, tenant_id, host_id, profile, status, job_type)
		 VALUES ($1, $2, $3, 'quick', 'queued', 'port_survey')`,
		uuid.New(), tenantID, hostID)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	_, ok, err := store.ClaimNext(context.Background(), "orchestrator-0")
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if ok {
		t.Error("ClaimNext should not claim a port_survey job")
	}
}
