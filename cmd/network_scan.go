package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

var networkScanCmd = &cobra.Command{
	Use:   "network-scan",
	Short: "Scan remote hosts and routers via SSH/NETCONF (agentless)",
	Long: `Agentless scanner for Unix hosts (Linux/macOS/AIX) and routers
(Cisco IOS-XE, Juniper Junos). Reads devices from an inventory file
and credentials from an encrypted YAML file. No binary deployed on targets.

The encryption key for credentials must be in TRITON_SCANNER_CRED_KEY
(32 hex bytes = 64 hex chars).`,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		return guard.EnforceFeature(license.FeatureNetworkScan)
	},
	RunE: runNetworkScan,
}

var (
	nsInventory    string
	nsCredentials  string
	nsGroup        string
	nsDevice       string
	nsConcurrency  int
	nsTimeout      time.Duration
	nsDryRun       bool
	nsInterval     time.Duration
	nsReportServer string
)

func init() {
	networkScanCmd.Flags().StringVar(&nsInventory, "inventory", "/etc/triton/devices.yaml", "path to devices.yaml")
	networkScanCmd.Flags().StringVar(&nsCredentials, "credentials", "/etc/triton/credentials.yaml", "path to encrypted credentials.yaml")
	networkScanCmd.Flags().StringVar(&nsGroup, "group", "", "scan only devices in this group")
	networkScanCmd.Flags().StringVar(&nsDevice, "device", "", "scan only this device (for debugging)")
	networkScanCmd.Flags().IntVar(&nsConcurrency, "concurrency", 20, "max concurrent device scans")
	networkScanCmd.Flags().DurationVar(&nsTimeout, "device-timeout", 5*time.Minute, "max time per device")
	networkScanCmd.Flags().BoolVar(&nsDryRun, "dry-run", false, "validate inventory + credentials, no scan")
	networkScanCmd.Flags().DurationVar(&nsInterval, "interval", 0, "continuous mode: repeat every interval")
	networkScanCmd.Flags().StringVar(&nsReportServer, "report-server", "", "report server URL")

	rootCmd.AddCommand(networkScanCmd)
}

func runNetworkScan(_ *cobra.Command, _ []string) error {
	inv, err := netscan.LoadInventory(nsInventory)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}

	creds, err := netscan.LoadCredentials(nsCredentials)
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	devices, err := inv.DevicesByGroup(nsGroup)
	if err != nil {
		return err
	}
	if nsDevice != "" {
		devices = filterDevicesByName(devices, nsDevice)
		if len(devices) == 0 {
			return fmt.Errorf("device not found in inventory: %s", nsDevice)
		}
	}

	fmt.Printf("Network scan: %d devices\n", len(devices))

	if nsDryRun {
		fmt.Println("Dry run — validating...")
		return runDryRun(devices, creds)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	orch := &netscan.Orchestrator{
		Inventory:        inv,
		Credentials:      creds,
		Concurrency:      nsConcurrency,
		PerDeviceTimeout: nsTimeout,
		ReportServerURL:  nsReportServer,
	}

	for {
		if err := orch.Scan(ctx, devices); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}
		if nsInterval == 0 {
			return nil
		}
		fmt.Printf("Next scan in %s\n", nsInterval)
		select {
		case <-time.After(nsInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

func filterDevicesByName(devices []netscan.Device, name string) []netscan.Device {
	for _, d := range devices {
		if d.Name == name {
			return []netscan.Device{d}
		}
	}
	return nil
}

func runDryRun(devices []netscan.Device, creds *netscan.CredentialStore) error {
	for _, d := range devices {
		if creds.Get(d.Credential) == nil {
			return fmt.Errorf("device %s: credential %q not found", d.Name, d.Credential)
		}
	}
	fmt.Printf("Validated %d devices, all credentials resolved.\n", len(devices))
	return nil
}
