package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	agentServer   string
	agentProfile  string
	agentInterval time.Duration
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run scan and submit results to a Triton report server",
	Long: `Agent mode runs a local scan and submits the results to a remote
Triton report server. Use --interval for continuous scanning.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return guard.EnforceFeature(license.FeatureAgentMode)
	},
	RunE: runAgent,
}

func init() {
	// --report-server is the canonical Phase 4 name; --server is kept
	// as an alias for one release cycle for backward compatibility.
	// Cobra prints the MarkDeprecated message to stderr whenever the
	// user passes --server, giving operators an audible migration cue.
	agentCmd.Flags().StringVar(&agentServer, "report-server", "", "Report server URL (e.g., http://localhost:8080)")
	agentCmd.Flags().StringVar(&agentServer, "server", "", "Alias for --report-server (deprecated, will be removed)")
	if err := agentCmd.Flags().MarkDeprecated("server", "use --report-server instead"); err != nil {
		// MarkDeprecated only fails if the flag doesn't exist, which
		// would be a programmer error caught immediately by any CLI
		// test. Panic is appropriate here (init-time invariant).
		panic(fmt.Sprintf("agent cmd: MarkDeprecated(server): %v", err))
	}
	agentCmd.Flags().StringVar(&agentProfile, "profile", "quick", "Scan profile: quick, standard, comprehensive")
	agentCmd.Flags().DurationVar(&agentInterval, "interval", 0, "Repeat interval (e.g., 24h). If unset, runs once.")
	rootCmd.AddCommand(agentCmd)
}

func runAgent(_ *cobra.Command, _ []string) error {
	if agentServer == "" {
		return fmt.Errorf("--report-server (or --server) is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := agent.New(agentServer)

	// Check server connectivity
	if err := client.Healthcheck(); err != nil {
		return fmt.Errorf("cannot reach server: %w", err)
	}
	fmt.Printf("Connected to server: %s\n", agentServer)

	for {
		if err := runAgentScan(ctx, client); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}

		if agentInterval == 0 {
			return nil
		}

		fmt.Printf("Next scan in %s...\n", agentInterval)
		select {
		case <-time.After(agentInterval):
		case <-ctx.Done():
			fmt.Println("\nAgent stopped.")
			return nil
		}
	}
}

func runAgentScan(ctx context.Context, client *agent.Client) error {
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

	progressCh := make(chan scanner.Progress, progressBufferSize)

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
