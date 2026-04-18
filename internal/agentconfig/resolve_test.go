package agentconfig

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// newTestCmd returns a *cobra.Command with the 5 resource-limit flags
// registered as PersistentFlags (mirroring root.go's real registration).
// Tests use this to simulate the flag-inheritance that cmd/agent.go sees.
func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.PersistentFlags().String("max-memory", "", "")
	cmd.PersistentFlags().String("max-cpu-percent", "", "")
	cmd.PersistentFlags().Duration("max-duration", 0, "")
	cmd.PersistentFlags().String("stop-at", "", "")
	cmd.PersistentFlags().Int("nice", 0, "")
	return cmd
}

func TestResolveLimits_YAMLOnly(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{
			MaxMemory:     "2GB",
			MaxCPUPercent: 50,
			MaxDuration:   4 * time.Hour,
			StopAt:        "03:00",
			Nice:          10,
		},
	}
	cmd := newTestCmd()
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.MaxMemoryBytes != 2<<30 {
		t.Errorf("MaxMemoryBytes: got %d, want %d", lim.MaxMemoryBytes, int64(2)<<30)
	}
	if lim.MaxCPUPercent != 50 {
		t.Errorf("MaxCPUPercent: got %d, want 50", lim.MaxCPUPercent)
	}
	if lim.MaxDuration != 4*time.Hour {
		t.Errorf("MaxDuration: got %v, want 4h", lim.MaxDuration)
	}
	if lim.StopAtOffset <= 0 {
		t.Errorf("StopAtOffset should be positive; got %v", lim.StopAtOffset)
	}
	if lim.Nice != 10 {
		t.Errorf("Nice: got %d, want 10", lim.Nice)
	}
}

func TestResolveLimits_FlagOverride_Memory(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxMemory: "2GB"},
	}
	cmd := newTestCmd()
	_ = cmd.PersistentFlags().Set("max-memory", "4GB")
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.MaxMemoryBytes != 4<<30 {
		t.Errorf("MaxMemoryBytes: got %d, want %d (flag should override yaml)",
			lim.MaxMemoryBytes, int64(4)<<30)
	}
}

func TestResolveLimits_FlagNotChanged_UsesYAML(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxMemory: "2GB"},
	}
	cmd := newTestCmd()
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.MaxMemoryBytes != 2<<30 {
		t.Errorf("MaxMemoryBytes: got %d, want %d", lim.MaxMemoryBytes, int64(2)<<30)
	}
}

func TestResolveLimits_BothUnset_ZeroLimits(t *testing.T) {
	cfg := &Config{}
	cmd := newTestCmd()
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.Enabled() {
		t.Errorf("Enabled() = true; want false (no yaml, no flags)")
	}
}

func TestResolveLimits_InvalidMemoryString_ReturnsError(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxMemory: "bogus"},
	}
	cmd := newTestCmd()
	_, err := cfg.ResolveLimits(cmd)
	if err == nil {
		t.Error("ResolveLimits should fail on invalid max_memory")
	}
}

func TestResolveLimits_InvalidStopAt_ReturnsError(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{StopAt: "25:00"},
	}
	cmd := newTestCmd()
	_, err := cfg.ResolveLimits(cmd)
	if err == nil {
		t.Error("ResolveLimits should fail on invalid stop_at")
	}
}

func TestResolveLimits_NilCmd_UsesYAMLOnly(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxCPUPercent: 25},
	}
	lim, err := cfg.ResolveLimits(nil)
	if err != nil {
		t.Fatalf("ResolveLimits(nil): %v", err)
	}
	if lim.MaxCPUPercent != 25 {
		t.Errorf("MaxCPUPercent: got %d, want 25", lim.MaxCPUPercent)
	}
}
