package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/store"
)

// maxRequestBody is the maximum allowed request body size (10 MB).
const maxRequestBody = 10 << 20

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// POST /api/v1/scans
func (s *Server) handleSubmitScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var result model.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if result.ID == "" {
		writeError(w, http.StatusBadRequest, "scan result must have an ID")
		return
	}

	if err := s.store.SaveScan(r.Context(), &result); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save scan: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": result.ID, "status": "saved"})
}

// GET /api/v1/scans
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	filter := store.ScanFilter{
		Hostname: r.URL.Query().Get("hostname"),
		Profile:  r.URL.Query().Get("profile"),
	}

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}
	if v := r.URL.Query().Get("after"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.After = &t
		}
	}
	if v := r.URL.Query().Get("before"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Before = &t
		}
	}

	summaries, err := s.store.ListScans(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if summaries == nil {
		summaries = []store.ScanSummary{}
	}
	writeJSON(w, http.StatusOK, summaries)
}

// GET /api/v1/scans/{id}
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DELETE /api/v1/scans/{id}
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteScan(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// GET /api/v1/scans/{id}/findings
func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	findings := result.Findings

	// Optional filters.
	if pqc := r.URL.Query().Get("pqc_status"); pqc != "" {
		findings = filterByPQCStatus(findings, pqc)
	}
	if mod := r.URL.Query().Get("module"); mod != "" {
		findings = filterByModule(findings, mod)
	}

	writeJSON(w, http.StatusOK, findings)
}

// GET /api/v1/diff?base=ID&compare=ID
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	baseID := r.URL.Query().Get("base")
	compareID := r.URL.Query().Get("compare")
	if baseID == "" || compareID == "" {
		writeError(w, http.StatusBadRequest, "both 'base' and 'compare' query params required")
		return
	}

	base, err := s.store.GetScan(r.Context(), baseID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "base scan not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	compare, err := s.store.GetScan(r.Context(), compareID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "compare scan not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	d := diff.ComputeDiff(base, compare)
	writeJSON(w, http.StatusOK, d)
}

// GET /api/v1/trend?hostname=X&last=N
func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	last := 10
	if v := r.URL.Query().Get("last"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			last = n
		}
	}

	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{
		Hostname: hostname,
		Limit:    last,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Load full results in chronological order.
	scans := make([]*model.ScanResult, 0, len(summaries))
	for i := len(summaries) - 1; i >= 0; i-- {
		scan, err := s.store.GetScan(r.Context(), summaries[i].ID)
		if err == nil {
			scans = append(scans, scan)
		}
	}

	trend := diff.ComputeTrend(scans)
	writeJSON(w, http.StatusOK, trend)
}

// GET /api/v1/machines
func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Deduplicate by hostname, keeping latest scan.
	machines := make(map[string]store.ScanSummary)
	for _, ss := range summaries {
		if _, exists := machines[ss.Hostname]; !exists {
			machines[ss.Hostname] = ss
		}
	}

	list := make([]store.ScanSummary, 0, len(machines))
	for _, m := range machines {
		list = append(list, m)
	}

	writeJSON(w, http.StatusOK, list)
}

// GET /api/v1/machines/{hostname}
func (s *Server) handleMachineHistory(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{Hostname: hostname})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if summaries == nil {
		summaries = []store.ScanSummary{}
	}
	writeJSON(w, http.StatusOK, summaries)
}

// POST /api/v1/policy/evaluate
func (s *Server) handlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		ScanID     string `json:"scanID"`
		PolicyName string `json:"policyName,omitempty"`
		PolicyYAML string `json:"policyYAML,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.ScanID == "" {
		writeError(w, http.StatusBadRequest, "scanID is required")
		return
	}

	result, err := s.store.GetScan(r.Context(), req.ScanID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	var pol *policy.Policy
	switch {
	case req.PolicyYAML != "":
		pol, err = policy.Parse([]byte(req.PolicyYAML))
	case req.PolicyName != "":
		pol, err = policy.LoadBuiltin(req.PolicyName)
	default:
		writeError(w, http.StatusBadRequest, "policyName or policyYAML required")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy: "+err.Error())
		return
	}

	eval := policy.Evaluate(pol, result)
	writeJSON(w, http.StatusOK, eval)
}

// GET /api/v1/reports/{id}/{format}
func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	format := chi.URLParam(r, "format")

	result, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Group findings into systems.
	if len(result.Systems) == 0 && len(result.Findings) > 0 {
		result.Systems = report.GroupFindingsIntoSystems(result.Findings)
	}

	// Use a fixed temp directory to prevent path traversal
	dir := os.TempDir()
	gen := report.New(dir)
	ts := time.Now().Format("20060102-150405")

	var filename string
	switch format {
	case "sarif":
		filename = fmt.Sprintf("triton-report-%s.sarif", ts)
		err = gen.GenerateSARIF(result, filename)
	case "html":
		filename = fmt.Sprintf("triton-report-%s.html", ts)
		err = gen.GenerateHTML(result, filename)
	case "json":
		filename = fmt.Sprintf("triton-report-%s.json", ts)
		err = gen.GenerateTritonJSON(result, filename)
	case "cyclonedx":
		filename = fmt.Sprintf("triton-report-%s.cdx.json", ts)
		err = gen.GenerateCycloneDXBOM(result, filename)
	default:
		writeError(w, http.StatusBadRequest, "unsupported format: "+format)
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "report generation failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"file": filename})
}

// GET /api/v1/aggregate
func (s *Server) handleAggregate(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Get latest scan per hostname.
	latest := make(map[string]store.ScanSummary)
	for _, ss := range summaries {
		if _, exists := latest[ss.Hostname]; !exists {
			latest[ss.Hostname] = ss
		}
	}

	totalSafe, totalTrans, totalDepr, totalUnsafe, totalFindings := 0, 0, 0, 0, 0
	machines := make([]store.ScanSummary, 0, len(latest))
	for _, ss := range latest {
		machines = append(machines, ss)
		totalSafe += ss.Safe
		totalTrans += ss.Transitional
		totalDepr += ss.Deprecated
		totalUnsafe += ss.Unsafe
		totalFindings += ss.TotalFindings
	}

	agg := map[string]any{
		"machineCount":  len(machines),
		"machines":      machines,
		"totalFindings": totalFindings,
		"safe":          totalSafe,
		"transitional":  totalTrans,
		"deprecated":    totalDepr,
		"unsafe":        totalUnsafe,
	}

	writeJSON(w, http.StatusOK, agg)
}

// GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Helper functions

func isNotFound(err error) bool {
	var nf *store.ErrNotFound
	return errors.As(err, &nf)
}

func filterByPQCStatus(findings []model.Finding, status string) []model.Finding {
	filtered := make([]model.Finding, 0)
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.EqualFold(f.CryptoAsset.PQCStatus, status) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func filterByModule(findings []model.Finding, module string) []model.Finding {
	filtered := make([]model.Finding, 0)
	for _, f := range findings {
		if strings.EqualFold(f.Module, module) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
