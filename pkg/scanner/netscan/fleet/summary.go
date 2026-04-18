package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SummaryInput is the immutable input to WriteSummary.
type SummaryInput struct {
	InvokedAt     time.Time
	CompletedAt   time.Time
	InventoryPath string
	Flags         map[string]interface{}
	Results       []HostResult
}

type hostLine struct {
	Device        string `json:"device"`
	State         string `json:"state"`
	Duration      string `json:"duration"`
	FindingsCount int    `json:"findings_count,omitempty"`
	JobID         string `json:"job_id,omitempty"`
	OutputPath    string `json:"output_path,omitempty"`
	Warning       string `json:"warning,omitempty"`
	Error         string `json:"error,omitempty"`
	Phase         string `json:"phase,omitempty"`
}

type summaryJSON struct {
	InvokedAt   time.Time              `json:"invoked_at"`
	CompletedAt time.Time              `json:"completed_at"`
	Duration    string                 `json:"duration"`
	Inventory   string                 `json:"inventory"`
	Flags       map[string]interface{} `json:"flags,omitempty"`
	Counts      map[string]int         `json:"counts"`
	Hosts       []hostLine             `json:"hosts"`
}

// WriteSummary writes summary.json and summary.txt into outputDir.
func WriteSummary(outputDir string, in SummaryInput) error {
	succeeded, failed := 0, 0
	hosts := make([]hostLine, len(in.Results))
	for i, r := range in.Results {
		hl := hostLine{
			Device:     r.Device,
			Duration:   r.Duration.Round(time.Second).String(),
			JobID:      r.JobID,
			OutputPath: r.OutputPath,
			Warning:    r.Warning,
		}
		if r.IsSuccess() {
			hl.State = "done"
			if r.Status != nil {
				hl.FindingsCount = r.Status.FindingsCount
			}
			succeeded++
		} else {
			hl.State = "failed"
			hl.Phase = r.Phase
			if r.Err != nil {
				hl.Error = r.Err.Error()
			}
			failed++
		}
		hosts[i] = hl
	}

	sj := summaryJSON{
		InvokedAt:   in.InvokedAt,
		CompletedAt: in.CompletedAt,
		Duration:    in.CompletedAt.Sub(in.InvokedAt).Round(time.Second).String(),
		Inventory:   in.InventoryPath,
		Flags:       in.Flags,
		Counts: map[string]int{
			"total":     len(in.Results),
			"succeeded": succeeded,
			"failed":    failed,
		},
		Hosts: hosts,
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}

	data, err := json.MarshalIndent(sj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "summary.json"), data, 0o600); err != nil {
		return fmt.Errorf("write summary.json: %w", err)
	}

	text := formatSummaryText(sj, in.Results)
	if err := os.WriteFile(filepath.Join(outputDir, "summary.txt"), []byte(text), 0o600); err != nil {
		return fmt.Errorf("write summary.txt: %w", err)
	}
	return nil
}

func formatSummaryText(sj summaryJSON, results []HostResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FLEET SCAN SUMMARY — completed %s (%s)\n",
		sj.CompletedAt.UTC().Format("2006-01-02 15:04:05 UTC"), sj.Duration)
	fmt.Fprintf(&b, "Inventory:   %s\n\n", sj.Inventory)
	fmt.Fprintf(&b, "Total hosts:      %d\n", sj.Counts["total"])
	fmt.Fprintf(&b, " ├─ Succeeded:    %d\n", sj.Counts["succeeded"])
	fmt.Fprintf(&b, " └─ Failed:       %d\n\n", sj.Counts["failed"])

	totalFindings := 0
	for _, r := range results {
		if r.IsSuccess() && r.Status != nil {
			totalFindings += r.Status.FindingsCount
		}
	}
	fmt.Fprintf(&b, "Total findings:   %d\n\n", totalFindings)

	if sj.Counts["succeeded"] > 0 {
		fmt.Fprintln(&b, "Succeeded hosts:")
		for _, r := range results {
			if r.IsSuccess() {
				n := 0
				if r.Status != nil {
					n = r.Status.FindingsCount
				}
				fmt.Fprintf(&b, "  %-24s %d findings (%s)\n",
					r.Device, n, r.Duration.Round(time.Second))
			}
		}
		fmt.Fprintln(&b)
	}

	if sj.Counts["failed"] > 0 {
		fmt.Fprintln(&b, "Failed hosts:")
		for _, r := range results {
			if !r.IsSuccess() {
				errStr := ""
				if r.Err != nil {
					errStr = r.Err.Error()
				}
				fmt.Fprintf(&b, "  %-24s %s: %s\n", r.Device, r.Phase, errStr)
			}
		}
	}
	return b.String()
}

// ExitCodeFor maps per-host results to the process exit code per spec:
//
//	0 — all hosts succeeded
//	2 — ≥1 host failed
//
// failOnAny elevates any failure to exit 1 for strict CI gates.
func ExitCodeFor(results []HostResult, failOnAny bool) int {
	failed := 0
	for _, r := range results {
		if !r.IsSuccess() {
			failed++
		}
	}
	if failed == 0 {
		return 0
	}
	if failOnAny {
		return 1
	}
	return 2
}
