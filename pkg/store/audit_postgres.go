package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// WriteAudit inserts a single audit event. Called fire-and-forget
// from handlers — callers typically ignore the error and let a
// background monitor flag repeated write failures.
//
// Details is serialized to JSONB. Nil or empty map becomes `{}`.
func (s *PostgresStore) WriteAudit(ctx context.Context, entry *AuditEvent) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	detailsJSON := []byte("{}")
	if len(entry.Details) > 0 {
		enc, err := json.Marshal(entry.Details)
		if err != nil {
			return fmt.Errorf("marshalling audit details: %w", err)
		}
		detailsJSON = enc
	}

	// OrgID is UUID in the schema. Empty string → NULL so the column
	// check doesn't reject service-key / cross-tenant events.
	var orgIDArg any
	if entry.OrgID != "" {
		orgIDArg = entry.OrgID
	}

	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_events (timestamp, event_type, org_id, actor_id, target_id, details, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.Timestamp, entry.EventType, orgIDArg,
		entry.ActorID, entry.TargetID, detailsJSON, entry.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	return nil
}

// ListAudit returns audit events matching the filter, newest first.
// Limit defaults to 100 and is clamped to 10_000. An empty filter
// returns the 100 most recent events across all orgs (use with
// care — callers that need tenant isolation MUST set OrgID).
func (s *PostgresStore) ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 10_000 {
		limit = 10_000
	}

	query := `SELECT id, timestamp, event_type, COALESCE(org_id::text, ''),
	                 actor_id, target_id, details, ip_address
	          FROM audit_events WHERE 1=1`
	args := []any{}
	idx := 0
	if filter.OrgID != "" {
		idx++
		query += fmt.Sprintf(" AND org_id = $%d", idx)
		args = append(args, filter.OrgID)
	}
	if filter.EventType != "" {
		idx++
		query += fmt.Sprintf(" AND event_type = $%d", idx)
		args = append(args, filter.EventType)
	}
	if filter.ActorID != "" {
		idx++
		query += fmt.Sprintf(" AND actor_id = $%d", idx)
		args = append(args, filter.ActorID)
	}
	if filter.Since != nil {
		idx++
		query += fmt.Sprintf(" AND timestamp >= $%d", idx)
		args = append(args, *filter.Since)
	}
	if filter.Until != nil {
		idx++
		query += fmt.Sprintf(" AND timestamp < $%d", idx)
		args = append(args, *filter.Until)
	}
	idx++
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", idx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	defer rows.Close()

	events := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var detailsJSON []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.OrgID,
			&e.ActorID, &e.TargetID, &detailsJSON, &e.IPAddress); err != nil {
			return nil, fmt.Errorf("scanning audit event: %w", err)
		}
		if len(detailsJSON) > 0 && string(detailsJSON) != "{}" {
			if err := json.Unmarshal(detailsJSON, &e.Details); err != nil {
				// Corrupt details — surface the event without the
				// details map rather than failing the whole list.
				e.Details = map[string]any{"_parse_error": err.Error()}
			}
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
