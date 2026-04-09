package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/store"
)

// maxRequestBody is the maximum allowed request body size (10 MB).
const maxRequestBody = 10 << 20

// maxListLimit is the maximum number of scans that can be requested in a single list call.
const maxListLimit = 500

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("writeJSON marshal error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
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

	// Tenant org_id is stamped from the authenticated context — NEVER
	// trusted from the body. A body that lies about org_id is either a
	// bug or an attack. The Phase 2 fix silently corrected the value;
	// the Phase 3+4 review (F1) upgraded this to a hard 400 rejection
	// in the multi-tenant case. The follow-up review (D2) then tightened
	// this further: even in single-tenant mode (no Guard, no JWT, so
	// tenantOrg == ""), a non-empty body org_id is rejected — a
	// single-tenant deployment has no concept of an "org" for the caller
	// to legitimately reference, so any non-empty value is a client
	// bug and should be surfaced rather than silently discarded.
	// Legacy agents that don't set org_id (empty string) are still accepted.
	tenantOrg := TenantFromContext(r.Context())
	if result.OrgID != "" && result.OrgID != tenantOrg {
		writeError(w, http.StatusBadRequest,
			"scan org_id in body does not match authenticated tenant; omit org_id from the body or fix the agent config")
		return
	}
	result.OrgID = tenantOrg

	if err := s.store.SaveScan(r.Context(), &result); err != nil {
		log.Printf("save scan error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": result.ID, "status": "saved"})
}

// GET /api/v1/scans
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	filter := store.ScanFilter{
		Hostname: r.URL.Query().Get("hostname"),
		Profile:  r.URL.Query().Get("profile"),
		OrgID:    TenantFromContext(r.Context()),
	}

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxListLimit {
				n = maxListLimit
			}
			filter.Limit = n
		} else if err == nil {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
	}
	if v := r.URL.Query().Get("after"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'after' timestamp: use RFC3339 format")
			return
		}
		filter.After = &t
	}
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'before' timestamp: use RFC3339 format")
			return
		}
		filter.Before = &t
	}

	summaries, err := s.store.ListScans(r.Context(), filter)
	if err != nil {
		log.Printf("list scans error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
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
	orgID := TenantFromContext(r.Context())
	result, err := s.store.GetScan(r.Context(), id, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		log.Printf("get scan error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DELETE /api/v1/scans/{id}
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	orgID := TenantFromContext(r.Context())
	if err := s.store.DeleteScan(r.Context(), id, orgID); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		log.Printf("delete scan error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	s.writeAudit(r, auditScanDelete, id, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// GET /api/v1/scans/{id}/findings
func (s *Server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	orgID := TenantFromContext(r.Context())
	result, err := s.store.GetScan(r.Context(), id, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		log.Printf("get findings error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
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

	orgID := TenantFromContext(r.Context())
	base, err := s.store.GetScan(r.Context(), baseID, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "base scan not found")
		} else {
			log.Printf("diff base scan error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}
	compare, err := s.store.GetScan(r.Context(), compareID, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "compare scan not found")
		} else {
			log.Printf("diff compare scan error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
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
	if last > 100 {
		last = 100
	}

	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{
		Hostname: hostname,
		Limit:    last,
		OrgID:    TenantFromContext(r.Context()),
	})
	if err != nil {
		log.Printf("trend error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Load full results in chronological order.
	scans := make([]*model.ScanResult, 0, len(summaries))
	for i := len(summaries) - 1; i >= 0; i-- {
		if r.Context().Err() != nil {
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		scan, err := s.store.GetScan(r.Context(), summaries[i].ID, TenantFromContext(r.Context()))
		if err != nil {
			log.Printf("trend: skipping scan %s: %v", summaries[i].ID, err)
			continue
		}
		scans = append(scans, scan)
	}

	trend := diff.ComputeTrend(scans)
	writeJSON(w, http.StatusOK, trend)
}

// GET /api/v1/machines
func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{Limit: 1000, OrgID: TenantFromContext(r.Context())})
	if err != nil {
		log.Printf("list machines error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	machines := latestByHostname(summaries)
	writeJSON(w, http.StatusOK, machines)
}

// GET /api/v1/machines/{hostname}
func (s *Server) handleMachineHistory(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{Hostname: hostname, OrgID: TenantFromContext(r.Context())})
	if err != nil {
		log.Printf("machine history error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
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

	orgID := TenantFromContext(r.Context())
	result, err := s.store.GetScan(r.Context(), req.ScanID, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
		} else {
			log.Printf("policy evaluate scan error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Enforce policy licence gate
	if s.guard != nil {
		feature := license.FeaturePolicyBuiltin
		if req.PolicyYAML != "" {
			feature = license.FeaturePolicyCustom
		}
		if err := s.guard.EnforceFeature(feature); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
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
//
// Streams a generated report for a stored scan. Supported formats:
//
//	json       — Triton proprietary JSON
//	html       — standalone HTML dashboard
//	xlsx       — Malaysian government Jadual 1/2 Excel workbook
//	cyclonedx  — CycloneDX 1.7 SBOM/CBOM (alias: cdx)
//	sarif      — SARIF for IDE/CI integration (enterprise tier)
//
// Format gating is enforced through the licence guard. The scan is
// fetched tenant-scoped so one org's admin cannot download another
// org's report.
func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	format := normalizeReportFormat(chi.URLParam(r, "format"))

	// Enforce format-level licence gate. Use the normalized
	// canonical name so the guard's internal lookup doesn't care
	// whether the caller used cdx or cyclonedx in the URL.
	if s.guard != nil {
		if err := s.guard.EnforceFormat(format); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	orgID := TenantFromContext(r.Context())
	result, err := s.store.GetScan(r.Context(), id, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
		} else {
			log.Printf("generate report scan error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Group findings into systems.
	if len(result.Systems) == 0 && len(result.Findings) > 0 {
		result.Systems = model.GroupFindingsIntoSystemsWithAgility(result.Findings, crypto.AssessAssetAgility)
	}

	// Validate format before doing any work. Unknown formats
	// return 400 rather than a later 500 during generation.
	ext, contentType, ok := reportFormatMetadata(format)
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported format: "+format)
		return
	}

	// Use os.CreateTemp for a unique path that survives concurrent
	// report generation. The file is closed immediately because
	// each Generate* method reopens it internally: html/json/sarif/
	// cdx write via os.WriteFile; xlsx first overwrites the temp
	// with the embedded PQC template bytes (copyTemplate), then
	// excelize opens it to populate sheets.
	tmpFile, tmpErr := os.CreateTemp("", "triton-report-*"+ext)
	if tmpErr != nil {
		log.Printf("create temp file error: %v", tmpErr)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	fullPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(fullPath) }()

	gen := report.New(filepath.Dir(fullPath))
	switch format {
	case "sarif":
		err = gen.GenerateSARIF(result, fullPath)
	case "html":
		err = gen.GenerateHTML(result, fullPath)
	case "json":
		err = gen.GenerateTritonJSON(result, fullPath)
	case "cdx":
		err = gen.GenerateCycloneDXBOM(result, fullPath)
	case "xlsx":
		err = gen.GenerateExcel(result, fullPath)
	default:
		// Defensive default — reportFormatMetadata already rejected
		// unknown formats with a 400 above, so reaching this branch
		// means a new format was added to reportFormatMetadata but
		// NOT to this dispatch table. Better to return 500 with a
		// clear server log than to stream the zero-byte temp file
		// that os.CreateTemp left behind (Sprint 3 review F4).
		err = fmt.Errorf("format %q validated but not dispatched", format)
	}

	if err != nil {
		log.Printf("report generation error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	f, openErr := os.Open(fullPath)
	if openErr != nil {
		log.Printf("read report error: %v", openErr)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = f.Close() }()

	filename := fmt.Sprintf("triton-report-%s%s", id, ext)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// normalizeReportFormat canonicalizes URL-supplied format names so
// the rest of the handler speaks a single vocabulary. Accepts both
// "cdx" and "cyclonedx" for the CycloneDX format, and lower-cases
// everything so clients don't have to match our spelling exactly.
func normalizeReportFormat(format string) string {
	format = strings.ToLower(format)
	if format == "cyclonedx" {
		return "cdx"
	}
	return format
}

// reportFormatMetadata returns the on-disk file extension and the
// Content-Type header to use for a given canonical format name.
// The returned ok flag is false for unknown formats so the caller
// can return 400 before any work is done.
func reportFormatMetadata(format string) (ext, contentType string, ok bool) {
	switch format {
	case "sarif":
		return ".sarif", "application/json", true
	case "html":
		return ".html", "text/html; charset=utf-8", true
	case "json":
		return ".json", "application/json", true
	case "cdx":
		return ".cdx.json", "application/json", true
	case "xlsx":
		return ".xlsx",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			true
	default:
		return "", "", false
	}
}

// GET /api/v1/aggregate
func (s *Server) handleAggregate(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.store.ListScans(r.Context(), store.ScanFilter{Limit: 1000, OrgID: TenantFromContext(r.Context())})
	if err != nil {
		log.Printf("aggregate error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	machines := latestByHostname(summaries)

	totalSafe, totalTrans, totalDepr, totalUnsafe, totalFindings := 0, 0, 0, 0, 0
	for _, ss := range machines {
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

// latestByHostname deduplicates scan summaries by hostname, keeping the latest.
// Summaries must be pre-sorted newest-first (as ListScans guarantees).
func latestByHostname(summaries []store.ScanSummary) []store.ScanSummary {
	seen := make(map[string]struct{}, len(summaries))
	out := make([]store.ScanSummary, 0, len(summaries))
	for _, ss := range summaries {
		if _, exists := seen[ss.Hostname]; !exists {
			seen[ss.Hostname] = struct{}{}
			out = append(out, ss)
		}
	}
	return out
}

// Helper functions

func isNotFound(err error) bool {
	var nf *store.ErrNotFound
	return errors.As(err, &nf)
}

func filterByPQCStatus(findings []model.Finding, status string) []model.Finding {
	filtered := make([]model.Finding, 0)
	for i := range findings {
		if findings[i].CryptoAsset != nil && strings.EqualFold(findings[i].CryptoAsset.PQCStatus, status) {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}

func filterByModule(findings []model.Finding, module string) []model.Finding {
	filtered := make([]model.Finding, 0)
	for i := range findings {
		if strings.EqualFold(findings[i].Module, module) {
			filtered = append(filtered, findings[i])
		}
	}
	return filtered
}
