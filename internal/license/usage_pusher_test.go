package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestUsagePusher_PushesOnTick(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["licenseID"] != "L1" {
			t.Errorf("licenseID not forwarded: %v", req["licenseID"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"remaining":{},"over_cap":[],"in_buffer":[]}`))
	}))
	defer srv.Close()

	source := func() []UsageMetric {
		return []UsageMetric{{Metric: "seats", Window: "total", Value: 7}}
	}
	p := NewUsagePusher(UsagePusherConfig{
		LicenseServer: srv.URL,
		LicenseID:     "L1",
		InstanceID:    "i1",
		Source:        source,
		Interval:      50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	time.Sleep(180 * time.Millisecond)
	cancel()

	got := atomic.LoadInt64(&hits)
	if got < 2 {
		t.Errorf("expected ≥2 pushes (1 initial + ≥1 tick), got %d", got)
	}
}

func TestUsagePusher_PushNowTriggers(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte(`{"ok":true,"remaining":{},"over_cap":[],"in_buffer":[]}`))
	}))
	defer srv.Close()

	p := NewUsagePusher(UsagePusherConfig{
		LicenseServer: srv.URL,
		LicenseID:     "L1",
		InstanceID:    "i1",
		Source:        func() []UsageMetric { return nil },
		Interval:      time.Hour, // no tick pushes during this test
	})

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	time.Sleep(30 * time.Millisecond) // let Run fire its initial push
	p.PushNow()
	time.Sleep(30 * time.Millisecond)
	cancel()

	got := atomic.LoadInt64(&hits)
	if got != 2 {
		t.Errorf("expected exactly 2 pushes (initial + PushNow), got %d", got)
	}
}

func TestUsagePusher_PushNowCoalesces(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		// Slow response so concurrent PushNow calls coalesce rather than queue.
		time.Sleep(40 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	p := NewUsagePusher(UsagePusherConfig{
		LicenseServer: srv.URL,
		LicenseID:     "L1",
		InstanceID:    "i1",
		Source:        func() []UsageMetric { return nil },
		Interval:      time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	time.Sleep(10 * time.Millisecond)

	// Fire 10 PushNow rapidly — should coalesce into at most 1 additional push
	// because trigger is a buffered channel of size 1.
	for i := 0; i < 10; i++ {
		p.PushNow()
	}
	time.Sleep(100 * time.Millisecond)
	cancel()

	got := atomic.LoadInt64(&hits)
	// 1 initial + at most 1 coalesced = 2.
	if got > 3 {
		t.Errorf("PushNow should coalesce, got %d hits", got)
	}
}

func TestUsagePusher_SurvivesServerError(t *testing.T) {
	// Server returns 500; pusher should log and continue, not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewUsagePusher(UsagePusherConfig{
		LicenseServer: srv.URL,
		LicenseID:     "L1",
		InstanceID:    "i1",
		Source:        func() []UsageMetric { return nil },
		Interval:      30 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	p.Run(ctx) // no panic
}
