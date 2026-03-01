package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

// ErrPolicyFail is returned when a policy evaluation fails,
// allowing the caller to set the appropriate exit code.
var ErrPolicyFail = errors.New("policy evaluation failed")

var (
	cfgFile       string
	outputDir     string
	outputFile    string
	scanProfile   string
	modules       []string
	format        string
	showMetrics   bool
	dbPath        string
	incremental   bool
	scanPolicyArg string
	licenseKey    string
	guard         *license.Guard

	validFormats = map[string]bool{"json": true, "cdx": true, "html": true, "xlsx": true, "sarif": true, "all": true}

	rootCmd = &cobra.Command{
		Use:     "triton",
		Short:   "SBOM/CBOM scanner for PQC compliance",
		Version: version.Version,
		Long: `Triton scans systems to generate Software Bill of Materials (SBOM)
and Cryptographic Bill of Materials (CBOM) for Post-Quantum Cryptography compliance.

Target: Malaysian government critical sectors for 2030 PQC readiness.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			guard = license.NewGuard(licenseKey)
		},
		RunE: runScan,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.triton.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "triton-report.json", "Output file for scan results (used with --format json)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "d", ".", "Output directory for reports (used with --format all)")
	rootCmd.PersistentFlags().StringVarP(&scanProfile, "profile", "p", "standard", "Scan profile: quick, standard, comprehensive")
	rootCmd.PersistentFlags().StringSliceVarP(&modules, "modules", "m", []string{}, "Specific modules to run (default: all)")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "all", "Output format: json, cdx, html, xlsx, sarif, all")
	rootCmd.PersistentFlags().BoolVar(&showMetrics, "metrics", false, "Show per-module scan metrics table")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "PostgreSQL connection URL (default: postgres://triton:triton@localhost:5434/triton?sslmode=disable)")
	rootCmd.PersistentFlags().BoolVar(&incremental, "incremental", false, "Skip unchanged files (uses hash cache)")
	rootCmd.PersistentFlags().StringVar(&scanPolicyArg, "policy", "", "Policy file or builtin name to evaluate after scan")
	rootCmd.PersistentFlags().StringVar(&licenseKey, "license-key", "", "Licence key or token")

	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("profile", rootCmd.PersistentFlags().Lookup("profile"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigName(".triton")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}

func Execute() error {
	return rootCmd.Execute()
}

type scanModel struct {
	progress   progress.Model
	result     *model.ScanResult
	err        error
	done       bool
	statusMsg  string
	progressCh chan scanner.Progress
	ctx        context.Context
	cancel     context.CancelFunc
}

type scanMsg struct {
	progress float64
	status   string
	done     bool
	result   *model.ScanResult
	err      error
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(
		m.waitForProgress(),
		m.progress.Init(),
	)
}

// waitForProgress returns a tea.Cmd that reads the next message from the progress channel.
func (m scanModel) waitForProgress() tea.Cmd {
	return func() tea.Msg {
		p, ok := <-m.progressCh
		if !ok {
			return scanMsg{done: true, status: "Scan complete"}
		}
		if p.Error != nil {
			return scanMsg{err: p.Error}
		}
		if p.Complete {
			return scanMsg{done: true, result: p.Result, status: p.Status}
		}
		return scanMsg{progress: p.Percent, status: p.Status}
	}
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.cancel()
			return m, tea.Quit
		}

	case scanMsg:
		if msg.err != nil {
			m.err = msg.err
			m.done = true
			return m, tea.Quit
		}
		if msg.done {
			m.done = true
			m.result = msg.result
			m.statusMsg = msg.status
			return m, tea.Quit
		}
		m.statusMsg = msg.status
		return m, tea.Batch(
			m.progress.SetPercent(msg.progress),
			m.waitForProgress(),
		)

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd
	}

	return m, nil
}

func (m scanModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("\nError: %v\n\n", m.err)
	}

	if m.done {
		return fmt.Sprintf("\n%s\n\n", m.statusMsg)
	}

	return fmt.Sprintf(
		"\nTriton Scanner - %s\n\n%s\n\n%s\n\nPress Ctrl+C to cancel\n",
		scanProfile,
		m.statusMsg,
		m.progress.View(),
	)
}

func runScan(cmd *cobra.Command, args []string) error {
	if !validFormats[format] {
		return fmt.Errorf("invalid format %q: must be one of json, cdx, html, xlsx, all", format)
	}

	fmt.Printf("Triton SBOM/CBOM Scanner v%s\n", version.Version)
	fmt.Printf("Platform: %s/%s | Licence: %s\n\n", runtime.GOOS, runtime.GOARCH, guard.Tier())

	// Enforce licence gates on profile and format.
	// If the user explicitly set a value, error on restriction.
	// Otherwise, silently downgrade defaults for the tier.
	if cmd.Flags().Changed("profile") {
		if err := guard.EnforceProfile(scanProfile); err != nil {
			return err
		}
	} else {
		allowed := license.AllowedProfiles(guard.Tier())
		if len(allowed) > 0 {
			scanProfile = allowed[len(allowed)-1]
		}
	}
	if cmd.Flags().Changed("format") {
		if err := guard.EnforceFormat(format); err != nil {
			return err
		}
	} else if err := guard.EnforceFormat(format); err != nil {
		format = "json"
	}

	cfg := config.Load(scanProfile)
	if len(modules) > 0 {
		cfg.Modules = modules
	}

	// Gate optional features behind licence tier.
	if showMetrics {
		if err := guard.EnforceFeature(license.FeatureMetrics); err != nil {
			return err
		}
	}
	if incremental {
		if err := guard.EnforceFeature(license.FeatureIncremental); err != nil {
			return err
		}
	}
	if dbPath != "" {
		if err := guard.EnforceFeature(license.FeatureDB); err != nil {
			return err
		}
	}
	if scanPolicyArg != "" {
		f := license.FeaturePolicyBuiltin
		if _, err := policy.LoadBuiltin(scanPolicyArg); err != nil {
			f = license.FeaturePolicyCustom
		}
		if err := guard.EnforceFeature(f); err != nil {
			return err
		}
	}

	cfg.Metrics = showMetrics
	cfg.Incremental = incremental
	if dbPath != "" {
		cfg.DBUrl = dbPath
	} else {
		cfg.DBUrl = config.DefaultDBUrl()
	}

	// Apply licence-based config filtering (restricts modules for free tier).
	guard.FilterConfig(cfg)

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	// Initialize store for incremental scanning and result persistence.
	if cfg.DBUrl != "" {
		db, err := store.NewPostgresStore(context.Background(), cfg.DBUrl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open database: %v\n", err)
		} else {
			eng.SetStore(db)
			defer func() { _ = db.Close() }()
		}
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return runScanHeadless(eng)
	}

	progressCh := make(chan scanner.Progress, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go eng.Scan(ctx, progressCh)

	sm := scanModel{
		progress:   progress.New(progress.WithDefaultGradient()),
		progressCh: progressCh,
		ctx:        ctx,
		cancel:     cancel,
	}

	p := tea.NewProgram(sm)

	finalModel, err := p.Run()
	if err != nil {
		return err
	}

	final, ok := finalModel.(scanModel)
	if !ok || final.result == nil {
		return nil
	}

	printScanMetrics(final.result)

	if err := saveScanResult(eng, final.result); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save scan to database: %v\n", err)
	}

	// Evaluate policy first so result.PolicyEvaluation is populated for HTML report.
	policyErr := evaluateScanPolicy(final.result)

	if err := generateReports(final.result); err != nil {
		return err
	}

	return policyErr
}

func runScanHeadless(eng *scanner.Engine) error {
	progressCh := make(chan scanner.Progress, 16)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go eng.Scan(ctx, progressCh)

	for p := range progressCh {
		if p.Error != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", p.Error)
			continue
		}
		fmt.Printf("[%3.0f%%] %s\n", p.Percent*100, p.Status)
		if p.Complete && p.Result != nil {
			printScanMetrics(p.Result)
			if err := saveScanResult(eng, p.Result); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save scan to database: %v\n", err)
			}
			// Evaluate policy first so result.PolicyEvaluation is populated for HTML report.
			policyErr := evaluateScanPolicy(p.Result)
			if err := generateReports(p.Result); err != nil {
				return err
			}
			return policyErr
		}
	}
	return nil
}

// saveScanResult persists a scan result using the engine's store.
func saveScanResult(eng *scanner.Engine, result *model.ScanResult) error {
	s := eng.Store()
	if s == nil {
		return nil
	}
	return s.SaveScan(context.Background(), result)
}

func generateReports(result *model.ScanResult) error {
	// Group findings into systems if not already populated
	if len(result.Systems) == 0 && len(result.Findings) > 0 {
		result.Systems = report.GroupFindingsIntoSystems(result.Findings)
		result.Summary.TotalSystems = len(result.Systems)
	}

	ts := time.Now().Format("20060102-150405")
	gen := report.New(outputDir)

	switch format {
	case "json":
		jsonFile := filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.json", ts))
		if err := gen.GenerateTritonJSON(result, jsonFile); err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", jsonFile)

	case "cdx":
		cdxFile := filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.cdx.json", ts))
		if err := gen.GenerateCycloneDXBOM(result, cdxFile); err != nil {
			return err
		}
		fmt.Printf("CycloneDX CBOM saved to: %s\n", cdxFile)

	case "html":
		htmlFile := filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.html", ts))
		if err := gen.GenerateHTML(result, htmlFile); err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", htmlFile)

	case "xlsx":
		xlsxFile := filepath.Join(outputDir, fmt.Sprintf("Triton_PQC_Report-%s.xlsx", ts))
		if err := gen.GenerateExcel(result, xlsxFile); err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", xlsxFile)

	case "sarif":
		sarifFile := filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.sarif", ts))
		if err := gen.GenerateSARIF(result, sarifFile); err != nil {
			return err
		}
		fmt.Printf("SARIF report saved to: %s\n", sarifFile)

	default: // "all"
		files, err := generateAllowedReports(gen, result, ts)
		if err != nil {
			return err
		}
		fmt.Println("Reports generated:")
		for _, f := range files {
			fmt.Printf("  - %s\n", f)
		}
	}

	return nil
}

func printScanMetrics(result *model.ScanResult) {
	if len(result.Metadata.ModuleMetrics) == 0 {
		return
	}

	// Sort a copy so we don't mutate the report data
	metrics := make([]model.ModuleMetric, len(result.Metadata.ModuleMetrics))
	copy(metrics, result.Metadata.ModuleMetrics)
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Duration > metrics[j].Duration
	})

	// Determine max target width (cap at 30 chars)
	maxTarget := 10
	for _, m := range metrics {
		if l := len(m.Target); l > maxTarget {
			maxTarget = l
		}
	}
	if maxTarget > 30 {
		maxTarget = 30
	}

	header := fmt.Sprintf("%-14s %-*s %10s %8s %8s %9s %9s",
		"Module", maxTarget, "Target", "Duration", "Files", "Matched", "Findings", "Memory")
	divider := strings.Repeat("\u2500", len(header))

	fmt.Printf("\nScan Metrics:\n%s\n%s\n", header, divider)

	var totalDuration time.Duration
	var totalScanned, totalMatched int64
	var totalFindings int
	var totalMemory float64

	for _, m := range metrics {
		target := m.Target
		if len(target) > maxTarget {
			target = "..." + target[len(target)-maxTarget+3:]
		}

		fmt.Printf("%-14s %-*s %10s %8d %8d %9d %8.1fMB",
			m.Module, maxTarget, target,
			formatDuration(m.Duration),
			m.FilesScanned, m.FilesMatched,
			m.Findings, m.MemoryDeltaMB)
		if m.Error != "" {
			fmt.Printf("  [ERR]")
		}
		fmt.Println()

		totalDuration += m.Duration
		totalScanned += m.FilesScanned
		totalMatched += m.FilesMatched
		totalFindings += m.Findings
		totalMemory += m.MemoryDeltaMB
	}

	fmt.Printf("%s\n", divider)

	// Count unique modules
	moduleSet := make(map[string]bool)
	for _, m := range metrics {
		moduleSet[m.Module] = true
	}

	summaryLabel := fmt.Sprintf("Total (%d modules, %d pairs)", len(moduleSet), len(metrics))
	padWidth := maxTarget + 10 - len(summaryLabel) - 1
	if padWidth < 1 {
		padWidth = 1
	}
	fmt.Printf("%s %*s %8d %8d %9d %8.1fMB\n",
		summaryLabel, padWidth,
		formatDuration(totalDuration),
		totalScanned, totalMatched,
		totalFindings, totalMemory)
	fmt.Printf("Peak memory: %.1fMB\n\n", result.Metadata.PeakMemoryMB)
}

// evaluateScanPolicy evaluates the --policy flag if set.
func evaluateScanPolicy(result *model.ScanResult) error {
	if scanPolicyArg == "" {
		return nil
	}

	pol, err := policy.LoadBuiltin(scanPolicyArg)
	if err != nil {
		pol, err = policy.LoadFromFile(scanPolicyArg)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
	}

	eval := policy.Evaluate(pol, result)
	result.PolicyEvaluation = eval.ToModelResult()

	fmt.Printf("\nPolicy Evaluation: %s\n", eval.PolicyName)
	fmt.Printf("Verdict: %s\n", eval.Verdict)

	if len(eval.Violations) > 0 {
		fmt.Printf("Violations: %d\n", len(eval.Violations))
		for _, v := range eval.Violations {
			icon := "!"
			if v.Action == "fail" {
				icon = "X"
			}
			fmt.Printf("  [%s] %s: %s\n", icon, v.RuleID, v.Message)
		}
	}
	for _, tv := range eval.ThresholdViolations {
		fmt.Printf("  [X] %s: %s\n", tv.Name, tv.Message)
	}

	result.Metadata.PolicyResult = string(eval.Verdict)

	if eval.Verdict == policy.VerdictFail {
		return ErrPolicyFail
	}
	return nil
}

// generateAllowedReports generates all report formats allowed by the current licence tier.
func generateAllowedReports(gen *report.Generator, result *model.ScanResult, ts string) ([]string, error) {
	allowed := license.AllowedFormats(guard.Tier())
	var files []string
	for _, fmtName := range allowed {
		var path string
		var err error
		switch fmtName {
		case "json":
			path = filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.json", ts))
			err = gen.GenerateTritonJSON(result, path)
		case "cdx":
			path = filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.cdx.json", ts))
			err = gen.GenerateCycloneDXBOM(result, path)
		case "html":
			path = filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.html", ts))
			err = gen.GenerateHTML(result, path)
		case "xlsx":
			path = filepath.Join(outputDir, fmt.Sprintf("Triton_PQC_Report-%s.xlsx", ts))
			err = gen.GenerateExcel(result, path)
		case "sarif":
			path = filepath.Join(outputDir, fmt.Sprintf("triton-report-%s.sarif", ts))
			err = gen.GenerateSARIF(result, path)
		}
		if err != nil {
			return files, err
		}
		files = append(files, path)
	}
	return files, nil
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0f\u00b5s", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Milliseconds()))
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
