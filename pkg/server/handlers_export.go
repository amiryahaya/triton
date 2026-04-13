package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/export/pdf
func (s *Server) handleExportPDF(w http.ResponseWriter, r *http.Request) {
	data, orgName, err := s.gatherAnalyticsReportData(r)
	if err != nil {
		log.Printf("export pdf: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	tmpFile, err := os.CreateTemp("", "triton-report-*.pdf")
	if err != nil {
		log.Printf("export pdf: create temp: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := report.GenerateAnalyticsPDF(data, tmpPath); err != nil {
		log.Printf("export pdf: generate: %v", err)
		writeError(w, http.StatusInternalServerError, "report generation failed")
		return
	}

	streamExportFile(w, tmpPath, exportFilename(orgName, "pdf"), "application/pdf")
}

// GET /api/v1/export/xlsx
func (s *Server) handleExportExcel(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	reportData, orgName, err := s.gatherAnalyticsReportData(r)
	if err != nil {
		log.Printf("export xlsx: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	blockers, err := s.store.ListTopPriorityFindings(r.Context(), orgID, 20, store.FilterParams{})
	if err != nil {
		log.Printf("export xlsx: blockers: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	certs, err := s.store.ListExpiringCertificates(r.Context(), orgID, 100*365*24*time.Hour, store.FilterParams{})
	if err != nil {
		log.Printf("export xlsx: certs: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	statusLog, err := s.store.ListFindingStatusLog(r.Context(), orgID, 1000)
	if err != nil {
		log.Printf("export xlsx: status log: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	data := &report.AnalyticsExcelData{
		OrgName:     reportData.OrgName,
		Snapshot:    reportData.Snapshot,
		Hosts:       reportData.Hosts,
		Remediation: reportData.Remediation,
		Blockers:    blockers,
		Certs:       certs,
		StatusLog:   statusLog,
		GeneratedAt: reportData.GeneratedAt,
	}

	tmpFile, err := os.CreateTemp("", "triton-report-*.xlsx")
	if err != nil {
		log.Printf("export xlsx: create temp: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := report.GenerateAnalyticsExcel(data, tmpPath); err != nil {
		log.Printf("export xlsx: generate: %v", err)
		writeError(w, http.StatusInternalServerError, "report generation failed")
		return
	}

	streamExportFile(w, tmpPath, exportFilename(orgName, "xlsx"),
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
}

// gatherAnalyticsReportData fetches the common data for both exports.
func (s *Server) gatherAnalyticsReportData(r *http.Request) (*report.AnalyticsReportData, string, error) {
	orgID := TenantFromContext(r.Context())
	ctx := r.Context()

	org, err := s.store.GetOrg(ctx, orgID)
	orgName := "Unknown Organization"
	if err == nil && org != nil {
		orgName = org.Name
	}

	snapshot, err := s.store.GetOrgSnapshot(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("get org snapshot: %w", err)
	}

	hosts, err := s.store.ListHostSummaries(ctx, orgID, "")
	if err != nil {
		return nil, "", fmt.Errorf("list host summaries: %w", err)
	}

	remediation, err := s.store.GetRemediationSummary(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("get remediation summary: %w", err)
	}

	return &report.AnalyticsReportData{
		OrgName:     orgName,
		Snapshot:    snapshot,
		Hosts:       hosts,
		Remediation: remediation,
		GeneratedAt: time.Now().UTC(),
	}, orgName, nil
}

// streamExportFile sends a file as an HTTP download attachment.
func streamExportFile(w http.ResponseWriter, path, filename, contentType string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("export: open file: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// exportFilename builds a safe filename for the download.
func exportFilename(orgName, ext string) string {
	date := time.Now().Format("2006-01-02")
	safe := sanitizeForFilename(orgName)
	return fmt.Sprintf("triton-pqc-report-%s-%s.%s", safe, date, ext)
}

// sanitizeForFilename removes characters unsafe for filenames.
func sanitizeForFilename(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, name)
	if result == "" {
		return "report"
	}
	return result
}
