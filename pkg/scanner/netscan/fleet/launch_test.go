package fleet

import (
	"strings"
	"testing"
	"time"
)

func TestBuildLaunchCommand_NoSudo(t *testing.T) {
	flags := ScanFlags{Profile: "standard", Format: "all"}
	got := BuildLaunchCommand("/tmp/.triton-abc", false, "", flags)
	want := `/tmp/.triton-abc --detach --quiet --profile standard --format all`
	if got != want {
		t.Errorf("BuildLaunchCommand:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestBuildLaunchCommand_WithSudo(t *testing.T) {
	flags := ScanFlags{Profile: "quick"}
	got := BuildLaunchCommand("/tmp/.triton-abc", true, "", flags)
	if !strings.HasPrefix(got, "sudo ") {
		t.Errorf("sudo prefix missing: %s", got)
	}
}

func TestBuildLaunchCommand_WorkDirForwarded(t *testing.T) {
	got := BuildLaunchCommand("/tmp/.triton-abc", false, "/var/tmp/triton-jobs", ScanFlags{})
	if !strings.Contains(got, "--work-dir /var/tmp/triton-jobs") {
		t.Errorf("--work-dir not forwarded: %s", got)
	}
}

func TestBuildLaunchCommand_AllFlagsForwarded(t *testing.T) {
	flags := ScanFlags{
		Profile:       "comprehensive",
		Format:        "json",
		Policy:        "nacsa-2030",
		MaxMemory:     "2GB",
		MaxCPUPercent: "50",
		MaxDuration:   4 * time.Hour,
		StopAt:        "03:00",
		Nice:          10,
		LicenseKey:    "test-token-abc",
	}
	got := BuildLaunchCommand("/remote/triton", true, "", flags)
	for _, want := range []string{
		"sudo",
		"--detach", "--quiet",
		"--profile comprehensive",
		"--format json",
		"--policy nacsa-2030",
		"--max-memory 2GB",
		"--max-cpu-percent 50",
		"--max-duration 4h0m0s",
		"--stop-at 03:00",
		"--nice 10",
		"--license-key 'test-token-abc'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in command, got: %s", want, got)
		}
	}
}

func TestBuildLaunchCommand_OmitsEmpty(t *testing.T) {
	got := BuildLaunchCommand("/tmp/t", false, "", ScanFlags{})
	if strings.Contains(got, "--profile ") {
		t.Errorf("empty profile should be omitted: %s", got)
	}
	if strings.Contains(got, "--max-memory ") {
		t.Errorf("empty max-memory should be omitted: %s", got)
	}
	if strings.Contains(got, "--nice ") {
		t.Errorf("zero nice should be omitted: %s", got)
	}
	if strings.Contains(got, "--license-key ") {
		t.Errorf("empty LicenseKey should be omitted: %s", got)
	}
	if !strings.Contains(got, "--detach") {
		t.Errorf("--detach missing: %s", got)
	}
	if !strings.Contains(got, "--quiet") {
		t.Errorf("--quiet missing: %s", got)
	}
}

func TestParseJobID_SingleLine(t *testing.T) {
	out := "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e\n"
	got, err := ParseJobID(out)
	if err != nil {
		t.Fatal(err)
	}
	if got != "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e" {
		t.Errorf("got %q", got)
	}
}

func TestParseJobID_MultiLine(t *testing.T) {
	out := `Detached as job 7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e
pid 12345, work-dir /home/triton/.triton/jobs/7a3f9e2c-...
`
	got, err := ParseJobID(out)
	if err != nil {
		t.Fatal(err)
	}
	if got != "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e" {
		t.Errorf("multi-line parse: got %q", got)
	}
}

func TestParseJobID_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not a uuid",
		"no-uuid-in-output-at-all",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := ParseJobID(tc); err == nil {
				t.Errorf("ParseJobID(%q) should fail", tc)
			}
		})
	}
}
