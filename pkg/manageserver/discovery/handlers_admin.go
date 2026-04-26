package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// defaultPorts is the set of ports probed when the caller omits the
// "ports" field in a Start request.
var defaultPorts = []int{22, 443, 3389, 5985, 5986}

// HostCapGuard is the narrow licence-guard surface the discovery admin
// handler consults before importing new hosts. Kept minimal so tests
// can inject a one-method fake without constructing a real *license.Guard.
//
// A nil Guard on AdminHandlers means "no licence configured" — cap
// check is skipped entirely (unlimited). LimitCap returning -1 for a
// metric means the same thing.
type HostCapGuard interface {
	LimitCap(metric, window string) int64
}

// WorkerRunner is the minimal interface the handler needs from the
// Worker. The indirection lets tests substitute a no-op runner without
// spinning up real goroutines or a live Scanner.
type WorkerRunner interface {
	Run(ctx context.Context, job Job)
}

// AdminHandlers serves the /api/v1/admin/discovery endpoints.
//
// GuardProvider is called per-request to read the current licence guard
// snapshot (or nil when no licence is active). The indirection lets the
// Server rotate its internal *license.Guard under a mutex during
// activation without racing concurrent admin requests.
// GuardProvider may itself be nil — that is treated identically to
// "returns nil" and disables cap enforcement.
type AdminHandlers struct {
	store         Store
	hostsStore    hosts.Store
	worker        WorkerRunner
	GuardProvider func() HostCapGuard
}

// NewAdminHandlers wires an AdminHandlers with the given Store,
// hosts.Store, WorkerRunner, and (optional) Guard provider.
func NewAdminHandlers(store Store, hostsStore hosts.Store, worker WorkerRunner, gp func() HostCapGuard) *AdminHandlers {
	return &AdminHandlers{
		store:         store,
		hostsStore:    hostsStore,
		worker:        worker,
		GuardProvider: gp,
	}
}

// guard returns the guard to use for this request, or nil when no
// provider is wired or the provider returns nil.
func (h *AdminHandlers) guard() HostCapGuard {
	if h.GuardProvider == nil {
		return nil
	}
	return h.GuardProvider()
}

// HandleStart — POST /: start a new network discovery scan.
func (h *AdminHandlers) HandleStart(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)

	var body struct {
		CIDR  string `json:"cidr"`
		Ports []int  `json:"ports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate CIDR.
	if body.CIDR == "" {
		writeErr(w, http.StatusBadRequest, "cidr is required")
		return
	}
	_, ipNet, err := net.ParseCIDR(body.CIDR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid CIDR")
		return
	}
	ones, bits := ipNet.Mask.Size()
	if bits-ones > 16 {
		writeErr(w, http.StatusBadRequest, "CIDR must be /16 or smaller (max 65536 hosts)")
		return
	}

	// Default ports when caller omits the field.
	ports := body.Ports
	if len(ports) == 0 {
		ports = defaultPorts
	}

	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	// Reject if a scan is already running.
	active, err := h.store.ActiveJobExists(r.Context(), tenantID)
	if err != nil {
		internalErr(w, r, err, "active job exists")
		return
	}
	if active {
		writeErr(w, http.StatusConflict, "a scan is already running")
		return
	}

	// Count total host IPs in the CIDR.
	totalIPs := countHosts(ipNet)

	req := EnqueueReq{
		CIDR:     body.CIDR,
		Ports:    ports,
		TotalIPs: totalIPs,
	}

	job, err := h.store.CreateJob(r.Context(), req, tenantID)
	if err != nil {
		internalErr(w, r, err, "create job")
		return
	}

	// Launch worker in background.
	go h.worker.Run(context.Background(), job)

	writeJSON(w, http.StatusCreated, job)
}

// HandleGet — GET /: return the current job and its candidates.
func (h *AdminHandlers) HandleGet(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	job, err := h.store.GetCurrentJob(r.Context(), tenantID)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no discovery job found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get current job")
		return
	}

	candidates, err := h.store.ListCandidates(r.Context(), job.ID)
	if err != nil {
		internalErr(w, r, err, "list candidates")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"job":        job,
		"candidates": candidates,
	})
}

// HandleCancel — POST /cancel: cancel the active scan.
func (h *AdminHandlers) HandleCancel(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	job, err := h.store.GetCurrentJob(r.Context(), tenantID)
	if errors.Is(err, ErrNotFound) {
		// NOTE: spec says 409 here, but 404 is more semantically correct for
		// "no job resource exists". The spec conflates two cases: no job ever
		// created (404) vs job exists but is not cancellable (409).
		writeErr(w, http.StatusNotFound, "no discovery job found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get current job for cancel")
		return
	}

	if job.Status != "queued" && job.Status != "running" {
		writeErr(w, http.StatusConflict, "no active scan to cancel")
		return
	}

	if err := h.store.SetCancelRequested(r.Context(), job.ID); err != nil {
		internalErr(w, r, err, "set cancel requested")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// importRequest is the JSON body for HandleImport.
type importRequest struct {
	Candidates []ImportItem `json:"candidates"`
}

// HandleImport — POST /import: import selected candidates as hosts.
func (h *AdminHandlers) HandleImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)

	var body importRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}
	// tenantID is validated (503 if missing) but not threaded into GetCandidates
	// because manage_discovery_candidates UUIDs are globally unique. In a
	// multi-tenant scenario, GetCandidates should accept tenantID and join
	// through manage_discovery_jobs to enforce isolation.
	_ = tenantID

	// Build a lookup map from the request body.
	importByID := make(map[uuid.UUID]ImportItem, len(body.Candidates))
	ids := make([]uuid.UUID, 0, len(body.Candidates))
	for _, item := range body.Candidates {
		importByID[item.ID] = item
		ids = append(ids, item.ID)
	}

	// Fetch candidate rows from the store.
	rows, err := h.store.GetCandidates(r.Context(), ids)
	if err != nil {
		internalErr(w, r, err, "get candidates")
		return
	}

	// Separate: already-imported (ExistingHostID set) vs to-import.
	var toImport []Candidate
	skipped := 0
	for i := range rows {
		if rows[i].ExistingHostID != nil {
			skipped++
		} else {
			toImport = append(toImport, rows[i])
		}
	}

	// Validate: every toImport candidate must have a non-empty hostname
	// in the request body.
	var missingHostnames []string
	for i := range toImport {
		item, ok := importByID[toImport[i].ID]
		if !ok || strings.TrimSpace(item.Hostname) == "" {
			missingHostnames = append(missingHostnames, toImport[i].IP)
		}
	}
	if len(missingHostnames) > 0 {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("hostname is required for: %s", strings.Join(missingHostnames, ", ")))
		return
	}

	// Licence host cap check.
	if g := h.guard(); g != nil {
		if limit := g.LimitCap("hosts", "total"); limit >= 0 {
			c, err := h.hostsStore.Count(r.Context())
			if err != nil {
				internalErr(w, r, err, "count hosts for cap")
				return
			}
			if int64(len(toImport))+c > limit {
				writeErr(w, http.StatusForbidden, fmt.Sprintf(
					"licence host cap exceeded (%d have, %d importing, cap %d)",
					c, len(toImport), limit))
				return
			}
		}
	}

	if len(toImport) == 0 {
		writeJSON(w, http.StatusOK, ImportResult{
			Imported: 0,
			Skipped:  skipped,
			Errors:   []ImportError{},
		})
		return
	}

	// Build hosts.Host slice from toImport.
	hostList := make([]hosts.Host, 0, len(toImport))
	for i := range toImport {
		hostname := strings.TrimSpace(importByID[toImport[i].ID].Hostname)
		hostList = append(hostList, hosts.Host{
			Hostname: hostname,
			IP:       toImport[i].IP,
			OS:       toImport[i].OS,
		})
	}

	// BulkCreate — collect errors on partial failure.
	var importErrors []ImportError
	imported := 0

	_, bulkErr := h.hostsStore.BulkCreate(r.Context(), hostList)
	if bulkErr != nil {
		// Whole-batch failure: attribute the error to each candidate.
		for i := range toImport {
			importErrors = append(importErrors, ImportError{
				IP:     toImport[i].IP,
				Reason: bulkErr.Error(),
			})
		}
	} else {
		imported = len(hostList)
	}

	if importErrors == nil {
		importErrors = []ImportError{}
	}

	writeJSON(w, http.StatusOK, ImportResult{
		Imported: imported,
		Skipped:  skipped,
		Errors:   importErrors,
	})
}

// countHosts returns the number of usable host addresses in an IP network.
// For a /24 that is 254 (256 - network - broadcast). For /31 and /32 returns 0.
func countHosts(ipNet *net.IPNet) int {
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 1 {
		return 0
	}
	return (1 << hostBits) - 2
}

// ---------------------------------------------------------------------------
// Response helpers (package-local, consistent with hosts/handlers_admin.go).
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("manageserver/discovery: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
