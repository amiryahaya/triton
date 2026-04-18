package fleet

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

func TestSummary_ExitCode(t *testing.T) {
	cases := []struct {
		name    string
		results []HostResult
		want    int
	}{
		{
			name:    "all ok",
			results: []HostResult{{Device: "a", JobID: "j1"}, {Device: "b", JobID: "j2"}},
			want:    0,
		},
		{
			name: "some failed",
			results: []HostResult{
				{Device: "a", JobID: "j1"},
				{Device: "b", Err: errors.New("fail"), Phase: "ssh connect"},
			},
			want: 2,
		},
		{
			name: "all failed",
			results: []HostResult{
				{Device: "a", Err: errors.New("fail"), Phase: "ssh connect"},
			},
			want: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCodeFor(tc.results, false); got != tc.want {
				t.Errorf("ExitCodeFor: got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSummary_ExitCode_FailOnAny(t *testing.T) {
	results := []HostResult{
		{Device: "a", JobID: "j1"},
		{Device: "b", Err: errors.New("fail"), Phase: "ssh connect"},
	}
	if got := ExitCodeFor(results, true); got != 1 {
		t.Errorf("ExitCodeFor failOnAny: got %d, want 1", got)
	}
}

func TestSummary_WriteJSON(t *testing.T) {
	tmp := t.TempDir()
	results := []HostResult{
		{
			Device:     "web-1",
			StartedAt:  time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
			Duration:   2 * time.Minute,
			Status:     &jobrunner.Status{FindingsCount: 137},
			JobID:      "7a3f9e2c-xx",
			OutputPath: "hosts/web-1.tar.gz",
		},
		{
			Device:    "srv-03",
			StartedAt: time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
			Duration:  8 * time.Second,
			Err:       errors.New("ssh connect: handshake failed"),
			Phase:     "ssh connect",
		},
	}
	err := WriteSummary(tmp, SummaryInput{
		InvokedAt:     time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
		CompletedAt:   time.Date(2026, 4, 18, 14, 32, 8, 0, time.UTC),
		InventoryPath: "/etc/triton/devices.yaml",
		Results:       results,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["inventory"] != "/etc/triton/devices.yaml" {
		t.Errorf("inventory: got %v", parsed["inventory"])
	}
	counts, ok := parsed["counts"].(map[string]interface{})
	if !ok {
		t.Fatal("counts missing or wrong type")
	}
	if counts["total"].(float64) != 2 {
		t.Errorf("counts.total = %v, want 2", counts["total"])
	}
	if counts["succeeded"].(float64) != 1 {
		t.Errorf("counts.succeeded = %v, want 1", counts["succeeded"])
	}
	if counts["failed"].(float64) != 1 {
		t.Errorf("counts.failed = %v, want 1", counts["failed"])
	}
}

func TestSummary_WriteText(t *testing.T) {
	tmp := t.TempDir()
	results := []HostResult{
		{Device: "web-1", JobID: "j", Status: &jobrunner.Status{FindingsCount: 137}, Duration: 2 * time.Minute},
		{Device: "srv-03", Err: errors.New("ssh connect failed"), Phase: "ssh connect", Duration: 8 * time.Second},
	}
	err := WriteSummary(tmp, SummaryInput{
		InvokedAt:     time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
		CompletedAt:   time.Date(2026, 4, 18, 14, 32, 8, 0, time.UTC),
		InventoryPath: "/etc/triton/devices.yaml",
		Results:       results,
	})
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(tmp, "summary.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(text)
	if !strings.Contains(s, "Total hosts:") {
		t.Errorf("missing 'Total hosts:' header: %s", s)
	}
	if !strings.Contains(s, "web-1") {
		t.Errorf("missing web-1")
	}
	if !strings.Contains(s, "srv-03") {
		t.Errorf("missing srv-03")
	}
	if !strings.Contains(s, "Failed hosts:") {
		t.Errorf("missing failed section")
	}
}
