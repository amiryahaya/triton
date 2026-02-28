package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	agentServer   string
	agentAPIKey   string
	agentProfile  string
	agentInterval time.Duration
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run scan and submit results to a Triton server",
	Long: `Agent mode runs a local scan and submits the results to a remote
Triton server. Use --interval for continuous scanning.`,
	RunE: runAgent,
}

func init() {
	agentCmd.Flags().StringVar(&agentServer, "server", "", "Triton server URL (e.g., http://localhost:8080)")
	agentCmd.Flags().StringVar(&agentAPIKey, "api-key", "", "API key for authentication")
	agentCmd.Flags().StringVar(&agentProfile, "profile", "quick", "Scan profile: quick, standard, comprehensive")
	agentCmd.Flags().DurationVar(&agentInterval, "interval", 0, "Repeat interval (e.g., 24h). If unset, runs once.")
	_ = agentCmd.MarkFlagRequired("server")
	rootCmd.AddCommand(agentCmd)
}

func runAgent(_ *cobra.Command, _ []string) error {
	client := agent.New(agentServer, agentAPIKey)

	// Check server connectivity
	if err := client.Healthcheck(); err != nil {
		return fmt.Errorf("cannot reach server: %w", err)
	}
	fmt.Printf("Connected to server: %s\n", agentServer)

	for {
		if err := runAgentScan(client); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}

		if agentInterval == 0 {
			return nil
		}

		fmt.Printf("Next scan in %s...\n", agentInterval)
		time.Sleep(agentInterval)
	}
}

func runAgentScan(client *agent.Client) error {
	fmt.Printf("\nStarting scan (profile: %s)...\n", agentProfile)

	cfg := config.Load(agentProfile)
	cfg.DBUrl = config.DefaultDBUrl()

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	// Initialize store for incremental scanning
	if cfg.DBUrl != "" {
		db, err := store.NewPostgresStore(context.Background(), cfg.DBUrl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open database: %v\n", err)
		} else {
			eng.SetStore(db)
			defer func() { _ = db.Close() }()
		}
	}

	progressCh := make(chan scanner.Progress, 16)
	ctx := context.Background()

	go eng.Scan(ctx, progressCh)

	var result *scanner.Progress
	for p := range progressCh {
		if p.Error != nil {
			fmt.Fprintf(os.Stderr, "  Warning: %v\n", p.Error)
			continue
		}
		fmt.Printf("  [%3.0f%%] %s\n", p.Percent*100, p.Status)
		if p.Complete {
			result = &p
		}
	}

	if result == nil || result.Result == nil {
		return fmt.Errorf("scan produced no results")
	}

	scan := result.Result
	scan.Metadata.AgentID = fmt.Sprintf("triton-agent/%s/%s", version.Version, runtime.GOOS)

	fmt.Printf("Scan complete: %d findings\n", scan.Summary.TotalFindings)

	// Save locally
	if s := eng.Store(); s != nil {
		if err := s.SaveScan(ctx, scan); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save locally: %v\n", err)
		}
	}

	// Submit to server
	fmt.Printf("Submitting to %s...\n", agentServer)
	resp, err := client.Submit(scan)
	if err != nil {
		return fmt.Errorf("submit failed: %w", err)
	}
	fmt.Printf("Submitted: id=%s status=%s\n", resp.ID, resp.Status)
	return nil
}
