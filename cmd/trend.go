package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	trendLast     int
	trendHostname string
)

var trendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show PQC migration trend over recent scans",
	RunE:  runTrend,
}

func init() {
	trendCmd.Flags().IntVar(&trendLast, "last", 10, "Number of recent scans to analyze")
	trendCmd.Flags().StringVar(&trendHostname, "hostname", "", "Filter by hostname")
	rootCmd.AddCommand(trendCmd)
}

func runTrend(_ *cobra.Command, _ []string) error {
	db, err := openStore()
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	summaries, err := db.ListScans(ctx, store.ScanFilter{
		Hostname: trendHostname,
		Limit:    trendLast,
	})
	if err != nil {
		return fmt.Errorf("listing scans: %w", err)
	}

	if len(summaries) == 0 {
		fmt.Println("No scans found.")
		return nil
	}

	// Load full results (in reverse order so oldest first).
	scans := make([]*model.ScanResult, 0, len(summaries))
	for i := len(summaries) - 1; i >= 0; i-- {
		s, err := db.GetScan(ctx, summaries[i].ID)
		if err != nil {
			continue
		}
		scans = append(scans, s)
	}

	trend := diff.ComputeTrend(scans)

	fmt.Printf("PQC Migration Trend (%d scans)\n", len(trend.Points))
	fmt.Printf("Direction: %s\n\n", trend.Direction())

	// Header
	header := fmt.Sprintf("%-20s %6s %6s %6s %6s %6s %8s",
		"Timestamp", "Safe", "Trans", "Depr", "Unsafe", "Total", "NACSA%")
	divider := strings.Repeat("\u2500", len(header))
	fmt.Printf("%s\n%s\n", header, divider)

	for _, p := range trend.Points {
		fmt.Printf("%-20s %6d %6d %6d %6d %6d %7.1f%%\n",
			p.Timestamp.Format("2006-01-02 15:04"),
			p.Safe, p.Transitional, p.Deprecated, p.Unsafe,
			p.Total, p.NACSAPercent)
	}
	fmt.Println(divider)

	if len(trend.Points) >= 2 {
		first := trend.Points[0]
		last := trend.Points[len(trend.Points)-1]
		fmt.Printf("Delta:               %+6d %+6d %+6d %+6d %+6d %+7.1f%%\n",
			last.Safe-first.Safe,
			last.Transitional-first.Transitional,
			last.Deprecated-first.Deprecated,
			last.Unsafe-first.Unsafe,
			last.Total-first.Total,
			last.NACSAPercent-first.NACSAPercent)
	}

	return nil
}
