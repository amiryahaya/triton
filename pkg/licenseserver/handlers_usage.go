package licenseserver

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// UsageRequest is the wire format for POST /api/v1/license/usage.
type UsageRequest struct {
	LicenseID  string                     `json:"licenseID"`
	InstanceID string                     `json:"instanceID"`
	Metrics    []licensestore.UsageReport `json:"metrics"`
}

// OverCapRef identifies a metric/window pair that is over its cap or buffer.
type OverCapRef struct {
	Metric string `json:"metric"`
	Window string `json:"window"`
}

// UsageResponse is the wire format returned by the usage endpoint.
type UsageResponse struct {
	OK        bool                        `json:"ok"`
	Remaining map[string]map[string]int64 `json:"remaining"`
	OverCap   []OverCapRef                `json:"over_cap"`
	InBuffer  []OverCapRef                `json:"in_buffer"`
}

// POST /api/v1/license/usage — upserts a batch of usage reports from a
// consumer instance and returns the current remaining-per-cap view.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req UsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LicenseID == "" || req.InstanceID == "" {
		writeError(w, http.StatusBadRequest, "licenseID and instanceID are required")
		return
	}
	if len(req.Metrics) == 0 {
		writeError(w, http.StatusBadRequest, "metrics array required")
		return
	}

	lic, err := s.store.GetLicense(r.Context(), req.LicenseID)
	if err != nil {
		var nf *licensestore.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "license not found")
			return
		}
		log.Printf("usage: get license: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Stamp each report with licence + instance IDs server-side —
	// these are not trusted from the body.
	reports := make([]licensestore.UsageReport, len(req.Metrics))
	for i, m := range req.Metrics {
		reports[i] = m
		reports[i].LicenseID = lic.ID
		reports[i].InstanceID = req.InstanceID
	}
	if err := s.store.UpsertUsage(r.Context(), reports); err != nil {
		log.Printf("usage: upsert: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Compute remaining + flags from the aggregated summary.
	summary, err := s.store.UsageSummary(r.Context(), lic.ID)
	if err != nil {
		log.Printf("usage: summary: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	limits := licensestore.ResolveLimits(lic)
	softBufferPct := lic.SoftBufferPct
	if softBufferPct == 0 {
		softBufferPct = 10 // default 10% buffer when not set
	}

	remaining := make(map[string]map[string]int64)
	var overCap, inBuffer []OverCapRef
	for _, e := range limits {
		current := summary[e.Metric][e.Window]
		if remaining[e.Metric] == nil {
			remaining[e.Metric] = make(map[string]int64)
		}
		rem := e.Cap - current
		if rem < 0 {
			rem = 0
		}
		remaining[e.Metric][e.Window] = rem

		if current > e.Cap {
			ref := OverCapRef{Metric: e.Metric, Window: e.Window}
			if current > e.BufferCeiling(softBufferPct) {
				overCap = append(overCap, ref)
			} else {
				inBuffer = append(inBuffer, ref)
			}
		}
	}

	// Ensure slices never serialise as null.
	if overCap == nil {
		overCap = []OverCapRef{}
	}
	if inBuffer == nil {
		inBuffer = []OverCapRef{}
	}

	writeJSON(w, http.StatusOK, UsageResponse{
		OK:        true,
		Remaining: remaining,
		OverCap:   overCap,
		InBuffer:  inBuffer,
	})
}
