package scanjobs

import (
	"context"
	"log"
	"time"
)

// ScheduleRunnerConfig holds the dependencies for the schedule runner goroutine.
type ScheduleRunnerConfig struct {
	ScheduleStore ScheduleStore
	BatchStore    BatchStore
	// HostsStore is optional. When set the runner resolves host metadata
	// (connection_type, credentials_ref, ssh_port) so that ResolveJobs can
	// make accurate per-host decisions. When nil, host IDs from the schedule
	// are forwarded to ResolveJobs with only an ID — port_survey jobs are
	// always created regardless, so omitting HostsStore is acceptable for
	// deployments that only schedule port surveys.
	HostsStore hostsGetter
	// TickInterval is the polling period. Defaults to 60 s when <= 0.
	TickInterval time.Duration
}

// ScheduleRunner fires due recurring schedules as batches.
// Start it via go runner.Run(ctx); it exits when ctx is cancelled.
type ScheduleRunner struct {
	cfg ScheduleRunnerConfig
}

// NewScheduleRunner constructs a ScheduleRunner from cfg.
// A zero or negative TickInterval is replaced with the default of 60 s.
func NewScheduleRunner(cfg ScheduleRunnerConfig) *ScheduleRunner {
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 60 * time.Second
	}
	return &ScheduleRunner{cfg: cfg}
}

// Run is the main tick loop. It exits when ctx is done.
func (r *ScheduleRunner) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *ScheduleRunner) tick(ctx context.Context) {
	due, err := r.cfg.ScheduleStore.ClaimDueSchedules(ctx)
	if err != nil {
		log.Printf("schedule runner: claim due schedules: %v", err)
		return
	}
	for _, sched := range due {
		if err := r.spawnBatch(ctx, sched); err != nil {
			// Log the failure but continue so one broken schedule does not
			// prevent other schedules in the same tick from being dispatched.
			log.Printf("schedule runner: spawn batch for schedule %s: %v", sched.ID, err)
		}
	}
}

func (r *ScheduleRunner) spawnBatch(ctx context.Context, sched Schedule) error {
	var infos []ResolveHostInfo
	if r.cfg.HostsStore != nil {
		rawHosts, err := r.cfg.HostsStore.GetByIDs(ctx, sched.HostIDs)
		if err != nil {
			return err
		}
		infos = make([]ResolveHostInfo, len(rawHosts))
		for i, h := range rawHosts {
			infos[i] = ResolveHostInfo{
				ID:             h.ID,
				ConnectionType: h.ConnectionType,
				CredentialsRef: h.CredentialsRef,
				SSHPort:        h.SSHPort,
			}
		}
	} else {
		// Without a HostsStore we have no connection metadata. Forward the IDs
		// with empty ConnectionType so that port_survey jobs are created (they
		// are unconditional) and filesystem jobs are skipped with "no_credential".
		infos = make([]ResolveHostInfo, len(sched.HostIDs))
		for i, id := range sched.HostIDs {
			infos[i] = ResolveHostInfo{ID: id}
		}
	}

	specs, skipped := ResolveJobs(infos, sched.JobTypes)

	schedID := sched.ID
	req := BatchEnqueueReq{
		TenantID:     sched.TenantID,
		ScheduleID:   &schedID,
		JobTypes:     sched.JobTypes,
		HostIDs:      sched.HostIDs,
		Profile:      sched.Profile,
		MaxCPUPct:    sched.MaxCPUPct,
		MaxMemoryMB:  sched.MaxMemoryMB,
		MaxDurationS: sched.MaxDurationS,
	}
	_, err := r.cfg.BatchStore.EnqueueBatch(ctx, req, specs, skipped)
	return err
}
