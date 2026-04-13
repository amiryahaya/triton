package store

import (
	"context"
	"fmt"
)

func (s *PostgresStore) RefreshOrgSnapshot(ctx context.Context, orgID string) error {
	return fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetOrgSnapshot(ctx context.Context, orgID string) (*OrgSnapshot, error) {
	return nil, fmt.Errorf("not implemented")
}
