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
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
	"github.com/amiryahaya/triton/pkg/scanner/netscan/fleet"
)

var fleetScanCmd = &cobra.Command{
	Use:   "fleet-scan",
	Short: "Orchestrate triton scans across a host fleet via SSH (binary push + detach)",
	Long: `Fleet-scan pushes the triton binary to each unix host in an inventory,
runs 'triton scan --detach', polls until terminal state, collects reports,
and cleans up. Reports land in --output-dir and/or --report-server.
Same inventory format as device-scan.`,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		return guard.EnforceFeature(license.FeatureFleetScan)
	},
	RunE: runFleetScan,
}

var (
	fsInventory       string
	fsCredentials     string
	fsGroup           string
	fsDevice          string
	fsConcurrency     int
	fsTimeout         time.Duration
	fsDryRun          bool
	fsInterval        time.Duration
	fsMaxFailures     int
	fsReportServer    string
	fsKnownHosts      string
	fsInsecureHostKey bool
	fsBinary          string
	fsOutputDir       string
	fsProfile         string
	fsFormat          string
	fsPolicy          string
	fsMaxMemory       string
	fsMaxCPUPercent   string
	fsMaxDuration     time.Duration
	fsStopAt          string
	fsNice            int
)

func init() {
	fleetScanCmd.Flags().StringVar(&fsInventory, "inventory", "/etc/triton/devices.yaml", "path to devices.yaml")
	fleetScanCmd.Flags().StringVar(&fsCredentials, "credentials", "/etc/triton/credentials.yaml", "path to encrypted credentials.yaml")
	fleetScanCmd.Flags().StringVar(&fsGroup, "group", "", "scan only devices in this group")
	fleetScanCmd.Flags().StringVar(&fsDevice, "device", "", "scan only this device (for debugging)")
	fleetScanCmd.Flags().IntVar(&fsConcurrency, "concurrency", 20, "max concurrent host scans")
	fleetScanCmd.Flags().DurationVar(&fsTimeout, "device-timeout", 30*time.Minute, "max time per host")
	fleetScanCmd.Flags().BoolVar(&fsDryRun, "dry-run", false, "validate inventory + SSH pre-flight only")
	fleetScanCmd.Flags().DurationVar(&fsInterval, "interval", 0, "continuous mode: repeat every interval (0 disables)")
	fleetScanCmd.Flags().IntVar(&fsMaxFailures, "max-failures", 0, "abort if this many hosts fail (0 = unlimited)")
	fleetScanCmd.Flags().StringVar(&fsKnownHosts, "known-hosts", "", "path to SSH known_hosts file (required unless --insecure-host-key)")
	fleetScanCmd.Flags().BoolVar(&fsInsecureHostKey, "insecure-host-key", false, "accept any host key (lab only)")
	fleetScanCmd.Flags().StringVar(&fsBinary, "binary", "", "override binary source (default: os.Args[0])")
	fleetScanCmd.Flags().StringVar(&fsOutputDir, "output-dir", "", "write per-host tar.gz + summary locally")
	fleetScanCmd.Flags().StringVar(&fsReportServer, "report-server", "", "upload each result.json to this report server")
	fleetScanCmd.Flags().StringVar(&fsProfile, "profile", "standard", "scan profile forwarded to each host")
	fleetScanCmd.Flags().StringVar(&fsFormat, "format", "all", "report format forwarded to each host")
	fleetScanCmd.Flags().StringVar(&fsPolicy, "policy", "", "policy forwarded to each host")
	fleetScanCmd.Flags().StringVar(&fsMaxMemory, "max-memory", "", "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().StringVar(&fsMaxCPUPercent, "max-cpu-percent", "", "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().DurationVar(&fsMaxDuration, "max-duration", 0, "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().StringVar(&fsStopAt, "stop-at", "", "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().IntVar(&fsNice, "nice", 0, "forwarded to each remote scan (PR #71)")

	fleetScanCmd.MarkFlagsOneRequired("output-dir", "report-server", "dry-run")

	rootCmd.AddCommand(fleetScanCmd)
}

func runFleetScan(_ *cobra.Command, _ []string) error {
	cfg := fleet.FleetConfig{
		InventoryPath:   fsInventory,
		CredentialsPath: fsCredentials,
		Group:           fsGroup,
		DeviceName:      fsDevice,
		Concurrency:     fsConcurrency,
		DeviceTimeout:   fsTimeout,
		DryRun:          fsDryRun,
		Interval:        fsInterval,
		MaxFailures:     fsMaxFailures,
		KnownHostsFile:  fsKnownHosts,
		InsecureHostKey: fsInsecureHostKey,
		BinaryOverride:  fsBinary,
		OutputDir:       fsOutputDir,
		ReportServerURL: fsReportServer,
		ScanFlags: fleet.ScanFlags{
			Profile:       fsProfile,
			Format:        fsFormat,
			Policy:        fsPolicy,
			MaxMemory:     fsMaxMemory,
			MaxCPUPercent: fsMaxCPUPercent,
			MaxDuration:   fsMaxDuration,
			StopAt:        fsStopAt,
			Nice:          fsNice,
		},
		Dialer: &sshDialerImpl{},
	}
	if cfg.BinaryOverride == "" {
		cfg.BinaryOverride = os.Args[0]
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	inv, err := netscan.LoadInventory(cfg.InventoryPath)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}
	creds, err := netscan.LoadCredentials(cfg.CredentialsPath)
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	devices := inv.DevicesForFleet()
	if cfg.Group != "" {
		byGroup, err := inv.DevicesByGroup(cfg.Group)
		if err != nil {
			return err
		}
		devices = filterFleetIntersection(devices, byGroup)
	}
	if cfg.DeviceName != "" {
		devices = filterFleetByName(devices, cfg.DeviceName)
		if len(devices) == 0 {
			return fmt.Errorf("device not found in inventory: %s", cfg.DeviceName)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	orch := fleet.NewOrchestrator(cfg)
	invokedAt := time.Now()
	results, runErr := orch.Run(ctx, devices, creds)
	completedAt := time.Now()

	// Write summary if OutputDir set.
	if cfg.OutputDir != "" {
		tsDir := fmt.Sprintf("%s/%s", cfg.OutputDir, invokedAt.UTC().Format("2006-01-02T15-04-05"))
		if err := fleet.WriteSummary(tsDir, fleet.SummaryInput{
			InvokedAt:     invokedAt,
			CompletedAt:   completedAt,
			InventoryPath: cfg.InventoryPath,
			Flags: map[string]interface{}{
				"profile":     cfg.ScanFlags.Profile,
				"max_memory":  cfg.ScanFlags.MaxMemory,
				"concurrency": cfg.Concurrency,
			},
			Results: results,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "warning: write summary: %v\n", err)
		}
		// Refresh `latest` symlink (best effort).
		_ = os.RemoveAll(cfg.OutputDir + "/latest")
		_ = os.Symlink(tsDir, cfg.OutputDir+"/latest")
	}

	// Print one-line summary per host to stdout.
	for _, r := range results {
		fmt.Println(r)
	}

	// Exit code.
	if runErr != nil {
		// MaxFailures circuit-breaker → exit 3.
		fmt.Fprintln(os.Stderr, "error:", runErr)
		os.Exit(3)
	}
	if code := fleet.ExitCodeFor(results, false); code != 0 {
		os.Exit(code)
	}
	return nil
}

// sshDialerImpl satisfies fleet.SSHDialer using transport.SSHClient.
type sshDialerImpl struct{}

func (*sshDialerImpl) Dial(ctx context.Context, addr, user string, key []byte, passphrase, knownHostsFile string, insecureHostKey bool) (fleet.SSHRunner, error) {
	return transport.NewSSHClient(ctx, transport.SSHConfig{
		Address:         addr,
		Username:        user,
		PrivateKey:      key,
		Passphrase:      passphrase,
		KnownHostsFile:  knownHostsFile,
		InsecureHostKey: insecureHostKey,
		DialTimeout:     15 * time.Second,
		CmdTimeout:      60 * time.Second,
	})
}

// filterFleetIntersection returns devices present in both a and b.
func filterFleetIntersection(a, b []netscan.Device) []netscan.Device {
	names := make(map[string]bool, len(b))
	for _, d := range b {
		names[d.Name] = true
	}
	out := make([]netscan.Device, 0, len(a))
	for _, d := range a {
		if names[d.Name] {
			out = append(out, d)
		}
	}
	return out
}

// filterFleetByName returns the subset of devices whose Name equals name.
func filterFleetByName(devs []netscan.Device, name string) []netscan.Device {
	for _, d := range devs {
		if d.Name == name {
			return []netscan.Device{d}
		}
	}
	return nil
}
