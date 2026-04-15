package inventory

// Audit event names emitted by this package. Persisted verbatim into
// audit_events.event_type (free-form TEXT — no CHECK constraint).
// Keep these stable; dashboards and log-based alerts grep on the
// literal strings. Onboarding Phase 1 Task 10.
const (
	EventGroupCreate = "inventory.group.create"
	EventGroupUpdate = "inventory.group.update"
	EventGroupDelete = "inventory.group.delete"
	EventHostCreate  = "inventory.host.create"
	EventHostUpdate  = "inventory.host.update"
	EventHostDelete  = "inventory.host.delete"
)
