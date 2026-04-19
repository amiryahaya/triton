package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// UsageMetric is one reported value from a consumer (Report / Manage) to
// the licence server.
type UsageMetric struct {
	Metric string `json:"metric"`
	Window string `json:"window"`
	Value  int64  `json:"value"`
}

// UsageSource collects the current usage values a consumer wants to report.
// Each call returns a fresh snapshot. Runs on the pusher's goroutine — should
// be fast and non-blocking.
type UsageSource func() []UsageMetric

// UsagePusherConfig wires the pusher to a consumer's context.
type UsagePusherConfig struct {
	LicenseServer string        // e.g. "https://license.triton.example"
	LicenseID     string        // the licence whose caps we're reporting against
	InstanceID    string        // unique-per-consumer-instance UUID
	Source        UsageSource   // called on every tick; returns current counts
	Interval      time.Duration // tick interval; 0 → 60s default
	HTTPClient    *http.Client  // nil → new Client{Timeout:15s}

	// OnPushSuccess, if non-nil, is called with the marshalled metrics
	// body after each successful push (HTTP 2xx). Runs synchronously
	// on the pusher's goroutine, so the callback must be fast. Used by
	// Manage Server to stamp manage_license_state.last_pushed_at.
	OnPushSuccess func(ctx context.Context, metricsJSON []byte)

	// OnPushFailure, if non-nil, is called with a reason string after
	// each unsuccessful push (non-2xx, transport error, or marshal
	// failure). Runs synchronously on the pusher's goroutine. Used by
	// Manage Server to increment consecutive_failures in
	// manage_license_state.
	OnPushFailure func(ctx context.Context, reason string)
}

// UsagePusher pushes usage to the license server every Interval, plus on
// demand via PushNow(). Non-blocking — designed to run as a goroutine.
type UsagePusher struct {
	cfg     UsagePusherConfig
	trigger chan struct{}
}

// NewUsagePusher constructs a pusher. Call Run(ctx) in a goroutine to start it.
func NewUsagePusher(cfg UsagePusherConfig) *UsagePusher {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &UsagePusher{
		cfg:     cfg,
		trigger: make(chan struct{}, 1),
	}
}

// Run blocks until ctx is cancelled, pushing usage periodically plus any
// PushNow triggers coalesced in-between. Does an initial push immediately
// on start so limit deltas surface without waiting for the first tick.
func (p *UsagePusher) Run(ctx context.Context) {
	tick := time.NewTicker(p.cfg.Interval)
	defer tick.Stop()

	p.push(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.push(ctx)
		case <-p.trigger:
			p.push(ctx)
		}
	}
}

// PushNow schedules an immediate push (non-blocking; multiple calls coalesce).
// Intended for use on limit-sensitive events (tenant created, scan completed)
// so caps update on the licence server without waiting for the next tick.
func (p *UsagePusher) PushNow() {
	select {
	case p.trigger <- struct{}{}:
	default:
		// already scheduled; no-op
	}
}

func (p *UsagePusher) push(ctx context.Context) {
	metrics := p.cfg.Source()
	body, err := json.Marshal(map[string]any{
		"licenseID":  p.cfg.LicenseID,
		"instanceID": p.cfg.InstanceID,
		"metrics":    metrics,
	})
	if err != nil {
		log.Printf("license usage push: marshal: %v", err)
		p.notifyFailure(ctx, fmt.Sprintf("marshal metrics: %v", err))
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/license/usage", p.cfg.LicenseServer),
		bytes.NewReader(body))
	if err != nil {
		p.notifyFailure(ctx, fmt.Sprintf("build request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		log.Printf("license usage push: %v", err)
		p.notifyFailure(ctx, err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("license usage push: status %d", resp.StatusCode)
		p.notifyFailure(ctx, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return
	}
	p.notifySuccess(ctx, body)
}

// notifySuccess fires the success callback if one is registered.
// Swallow-style: nil callback is a no-op so consumers that only care
// about failures (or only care about successes) can wire just one.
func (p *UsagePusher) notifySuccess(ctx context.Context, metricsJSON []byte) {
	if p.cfg.OnPushSuccess == nil {
		return
	}
	p.cfg.OnPushSuccess(ctx, metricsJSON)
}

// notifyFailure fires the failure callback if one is registered.
func (p *UsagePusher) notifyFailure(ctx context.Context, reason string) {
	if p.cfg.OnPushFailure == nil {
		return
	}
	p.cfg.OnPushFailure(ctx, reason)
}
