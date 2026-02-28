package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/model"
)

var diffCmd = &cobra.Command{
	Use:   "diff <scan-id-1> <scan-id-2>",
	Short: "Compare two scans",
	Args:  cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return guard.EnforceFeature(license.FeatureDiff)
	},
	RunE: runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

func runDiff(_ *cobra.Command, args []string) error {
	db, err := openStore()
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	base, err := db.GetScan(ctx, args[0])
	if err != nil {
		return fmt.Errorf("loading base scan: %w", err)
	}

	compare, err := db.GetScan(ctx, args[1])
	if err != nil {
		return fmt.Errorf("loading compare scan: %w", err)
	}

	d := diff.ComputeDiff(base, compare)

	fmt.Printf("Scan Diff: %s vs %s\n", d.BaseID, d.CompareID)
	fmt.Printf("  Base:    %s (%s)\n", base.Metadata.Hostname, base.Metadata.Timestamp.Format("2006-01-02 15:04"))
	fmt.Printf("  Compare: %s (%s)\n\n", compare.Metadata.Hostname, compare.Metadata.Timestamp.Format("2006-01-02 15:04"))

	fmt.Printf("Summary:\n")
	fmt.Printf("  Added:   %d findings\n", d.Summary.AddedCount)
	fmt.Printf("  Removed: %d findings\n", d.Summary.RemovedCount)
	fmt.Printf("  Changed: %d findings\n", d.Summary.ChangedCount)
	fmt.Printf("  Safe:    %+d\n", d.Summary.SafeDelta)
	fmt.Printf("  Unsafe:  %+d\n", d.Summary.UnsafeDelta)
	if d.Summary.NACSADelta != 0 {
		fmt.Printf("  NACSA:   %+.1f%%\n", d.Summary.NACSADelta)
	}

	if len(d.Added) > 0 {
		fmt.Printf("\nAdded (%d):\n", len(d.Added))
		for i := range d.Added {
			algo, status := findingAlgoStatus(&d.Added[i])
			fmt.Printf("  + [%s] %s at %s\n", status, algo, findingLoc(&d.Added[i]))
		}
	}

	if len(d.Removed) > 0 {
		fmt.Printf("\nRemoved (%d):\n", len(d.Removed))
		for i := range d.Removed {
			algo, status := findingAlgoStatus(&d.Removed[i])
			fmt.Printf("  - [%s] %s at %s\n", status, algo, findingLoc(&d.Removed[i]))
		}
	}

	if len(d.Changed) > 0 {
		fmt.Printf("\nChanged (%d):\n", len(d.Changed))
		for i := range d.Changed {
			c := &d.Changed[i]
			algo, _ := findingAlgoStatus(&c.Finding)
			fmt.Printf("  ~ %s: %s -> %s at %s\n", algo, c.OldStatus, c.NewStatus, findingLoc(&c.Finding))
		}
	}

	return nil
}

func findingAlgoStatus(f *model.Finding) (algo, status string) {
	if f.CryptoAsset != nil {
		return f.CryptoAsset.Algorithm, f.CryptoAsset.PQCStatus
	}
	return "unknown", "unknown"
}

func findingLoc(f *model.Finding) string {
	if f.Source.Path != "" {
		return f.Source.Path
	}
	if f.Source.Endpoint != "" {
		return f.Source.Endpoint
	}
	return f.Module
}
