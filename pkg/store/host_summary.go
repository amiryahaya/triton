package store

import (
	"context"
	"fmt"
)

func (s *PostgresStore) RefreshHostSummary(ctx context.Context, orgID, hostname string) error {
	return fmt.Errorf("not implemented")
}

func (s *PostgresStore) ListHostSummaries(ctx context.Context, orgID string, pqcStatusFilter string) ([]HostSummary, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) ListStaleHosts(ctx context.Context) ([]PipelineJob, error) {
	return nil, fmt.Errorf("not implemented")
}
