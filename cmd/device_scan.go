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

var deviceScanCmd = &cobra.Command{
	Use:   "device-scan",
	Short: "Scan remote hosts and routers via SSH/NETCONF (agentless) — formerly network-scan",
	Long: `Agentless scanner for Unix hosts (Linux/macOS/AIX) and routers
(Cisco IOS-XE, Juniper Junos). Reads devices from an inventory file
and credentials from an encrypted YAML file. No binary deployed on targets.

The encryption key for credentials must be in TRITON_SCANNER_CRED_KEY
(32 hex bytes = 64 hex chars).`,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		return guard.EnforceFeature(license.FeatureDeviceScan)
	},
	RunE: runDeviceScan,
}

var (
	dsInventory       string
	dsCredentials     string
	dsGroup           string
	dsDevice          string
	dsConcurrency     int
	dsTimeout         time.Duration
	dsDryRun          bool
	dsInterval        time.Duration
	dsReportServer    string
	dsKnownHosts      string
	dsInsecureHostKey bool
)

func init() {
	deviceScanCmd.Flags().StringVar(&dsInventory, "inventory", "/etc/triton/devices.yaml", "path to devices.yaml")
	deviceScanCmd.Flags().StringVar(&dsCredentials, "credentials", "/etc/triton/credentials.yaml", "path to encrypted credentials.yaml")
	deviceScanCmd.Flags().StringVar(&dsGroup, "group", "", "scan only devices in this group")
	deviceScanCmd.Flags().StringVar(&dsDevice, "device", "", "scan only this device (for debugging)")
	deviceScanCmd.Flags().IntVar(&dsConcurrency, "concurrency", 20, "max concurrent device scans")
	deviceScanCmd.Flags().DurationVar(&dsTimeout, "device-timeout", 5*time.Minute, "max time per device")
	deviceScanCmd.Flags().BoolVar(&dsDryRun, "dry-run", false, "validate inventory + credentials, no scan")
	deviceScanCmd.Flags().DurationVar(&dsInterval, "interval", 0, "continuous mode: repeat every interval")
	deviceScanCmd.Flags().StringVar(&dsReportServer, "report-server", "", "report server URL")
	deviceScanCmd.Flags().StringVar(&dsKnownHosts, "known-hosts", "", "path to SSH known_hosts file (required unless --insecure-host-key)")
	deviceScanCmd.Flags().BoolVar(&dsInsecureHostKey, "insecure-host-key", false, "accept any host key (lab/test only; not for production)")

	rootCmd.AddCommand(deviceScanCmd)
}

func runDeviceScan(_ *cobra.Command, _ []string) error {
	inv, err := netscan.LoadInventory(dsInventory)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}

	creds, err := netscan.LoadCredentials(dsCredentials)
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	devices, err := inv.DevicesByGroup(dsGroup)
	if err != nil {
		return err
	}
	if dsDevice != "" {
		devices = filterDevicesByName(devices, dsDevice)
		if len(devices) == 0 {
			return fmt.Errorf("device not found in inventory: %s", dsDevice)
		}
	}

	fmt.Printf("Network scan: %d devices\n", len(devices))

	if dsDryRun {
		fmt.Println("Dry run — validating...")
		return runDryRun(devices, creds)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	orch := &netscan.Orchestrator{
		Inventory:        inv,
		Credentials:      creds,
		Concurrency:      dsConcurrency,
		PerDeviceTimeout: dsTimeout,
		ReportServerURL:  dsReportServer,
		KnownHostsFile:   dsKnownHosts,
		InsecureHostKey:  dsInsecureHostKey,
	}

	for {
		if err := orch.Scan(ctx, devices); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}
		if dsInterval == 0 {
			return nil
		}
		fmt.Printf("Next scan in %s\n", dsInterval)
		select {
		case <-time.After(dsInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

func filterDevicesByName(devices []netscan.Device, name string) []netscan.Device {
	for i := range devices {
		if devices[i].Name == name {
			return []netscan.Device{devices[i]}
		}
	}
	return nil
}

func runDryRun(devices []netscan.Device, creds *netscan.CredentialStore) error {
	for i := range devices {
		if creds.Get(devices[i].Credential) == nil {
			return fmt.Errorf("device %s: credential %q not found", devices[i].Name, devices[i].Credential)
		}
	}
	fmt.Printf("Validated %d devices, all credentials resolved.\n", len(devices))
	return nil
}
