package agentconfig

import "time"

// ScheduleKind discriminates ScheduleSpec variants without a sum type.
// A plain string keeps the struct yaml/json-safe if we ever serialize it.
type ScheduleKind string

const (
	// ScheduleKindCron means CronExpr is set and Interval is ignored.
	ScheduleKindCron ScheduleKind = "cron"
	// ScheduleKindInterval means Interval is set and CronExpr is ignored.
	ScheduleKindInterval ScheduleKind = "interval"
	// ScheduleKindOneShot means neither is set — the agent runs once
	// and exits. Jitter is ignored.
	ScheduleKindOneShot ScheduleKind = "oneshot"
)

// ScheduleSpec is the plain-data result of resolving schedule/interval
// from agent.yaml + CLI flags. It does NOT import the cron library —
// cmd/agent_scheduler.go is responsible for parsing CronExpr and
// building the runtime scheduler.
//
// One-shot mode is represented by Kind=ScheduleKindOneShot and both
// CronExpr and Interval at their zero values.
type ScheduleSpec struct {
	Kind     ScheduleKind
	CronExpr string        // populated when Kind == ScheduleKindCron
	Interval time.Duration // populated when Kind == ScheduleKindInterval
	Jitter   time.Duration // optional; only populated in cron mode, 0 disables
}
