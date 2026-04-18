package cmd

import (
	"testing"
)

func TestFleetScanCmd_Registered(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"fleet-scan"})
	if err != nil {
		t.Fatalf("fleet-scan should be registered: %v", err)
	}
	if cmd.Use != "fleet-scan" {
		t.Errorf("Use = %q, want fleet-scan", cmd.Use)
	}
}

func TestFleetScanCmd_RequiredFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"fleet-scan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"inventory", "credentials", "output-dir", "report-server", "dry-run",
		"group", "device", "concurrency", "device-timeout", "binary",
		"known-hosts", "insecure-host-key", "interval", "max-failures",
		"profile", "format", "policy",
		"max-memory", "max-cpu-percent", "max-duration", "stop-at", "nice"} {
		if cmd.Flags().Lookup(flag) == nil && cmd.PersistentFlags().Lookup(flag) == nil {
			t.Errorf("flag --%s not registered on fleet-scan", flag)
		}
	}
}
