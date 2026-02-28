package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	historyHostname string
	historyLimit    int
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "List past scans stored in the database",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return guard.EnforceFeature(license.FeatureDB)
	},
	RunE: runHistory,
}

func init() {
	historyCmd.Flags().StringVar(&historyHostname, "hostname", "", "Filter by hostname")
	historyCmd.Flags().IntVar(&historyLimit, "limit", 20, "Maximum number of scans to show")
	rootCmd.AddCommand(historyCmd)
}

func runHistory(_ *cobra.Command, _ []string) error {
	db, err := openStore()
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	summaries, err := db.ListScans(context.Background(), store.ScanFilter{
		Hostname: historyHostname,
		Limit:    historyLimit,
	})
	if err != nil {
		return fmt.Errorf("listing scans: %w", err)
	}

	if len(summaries) == 0 {
		fmt.Println("No scans found.")
		return nil
	}

	// Header
	header := fmt.Sprintf("%-38s %-20s %-20s %-14s %6s %6s %6s %6s %6s",
		"ID", "Hostname", "Timestamp", "Profile",
		"Total", "Safe", "Trans", "Depr", "Unsafe")
	divider := strings.Repeat("\u2500", len(header))
	fmt.Printf("%s\n%s\n", header, divider)

	for _, s := range summaries {
		fmt.Printf("%-38s %-20s %-20s %-14s %6d %6d %6d %6d %6d\n",
			s.ID,
			truncate(s.Hostname, 20),
			s.Timestamp.Format("2006-01-02 15:04:05"),
			s.Profile,
			s.TotalFindings,
			s.Safe,
			s.Transitional,
			s.Deprecated,
			s.Unsafe,
		)
	}

	fmt.Printf("%s\n%d scan(s) found.\n", divider, len(summaries))
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
