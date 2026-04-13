package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// Ensure pgx and errors are referenced to satisfy the compiler until
// Task 4 implements the real queries.
var _ = pgx.ErrNoRows
var _ = errors.New

// ComputeFindingKey produces a stable identifier for a crypto finding
// across scans. The key is a hex-encoded SHA-256 hash of the
// concatenation of org_id, hostname, algorithm, key_size, and module.
func ComputeFindingKey(orgID, hostname, algorithm string, keySize int, module string) string {
	data := orgID + hostname + algorithm + strconv.Itoa(keySize) + module
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func (s *PostgresStore) SetFindingStatus(ctx context.Context, entry *FindingStatusEntry) error {
	return fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetFindingHistory(ctx context.Context, findingKey string) ([]FindingStatusEntry, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetRemediationSummary(ctx context.Context, orgID string) (*RemediationSummary, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) ListRemediationFindings(ctx context.Context, orgID string, statusFilter, hostnameFilter, pqcFilter string) ([]RemediationRow, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetFindingByID(ctx context.Context, findingID, orgID string) (*Finding, error) {
	return nil, fmt.Errorf("not implemented")
}
