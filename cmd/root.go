package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
)

var (
	cfgFile     string
	outputDir   string
	outputFile  string
	scanProfile string
	modules     []string
	format      string

	validFormats = map[string]bool{"json": true, "html": true, "xlsx": true, "all": true}

	rootCmd = &cobra.Command{
		Use:     "triton",
		Short:   "SBOM/CBOM scanner for PQC compliance",
		Version: version.Version,
		Long: `Triton scans systems to generate Software Bill of Materials (SBOM)
and Cryptographic Bill of Materials (CBOM) for Post-Quantum Cryptography compliance.

Target: Malaysian government critical sectors for 2030 PQC readiness.`,
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
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "all", "Output format: json, html, xlsx, all")

	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("profile", rootCmd.PersistentFlags().Lookup("profile"))
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
	viper.ReadInConfig()
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
		return fmt.Errorf("invalid format %q: must be one of json, html, xlsx, all", format)
	}

	fmt.Printf("Triton SBOM/CBOM Scanner v%s\n", version.Version)
	fmt.Printf("Platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	cfg := config.Load(scanProfile)
	if len(modules) > 0 {
		cfg.Modules = modules
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

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

	return generateReports(final.result)
}

func runScanHeadless(eng *scanner.Engine) error {
	progressCh := make(chan scanner.Progress, 16)
	ctx := context.Background()

	go eng.Scan(ctx, progressCh)

	for p := range progressCh {
		if p.Error != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", p.Error)
			continue
		}
		fmt.Printf("[%3.0f%%] %s\n", p.Percent*100, p.Status)
		if p.Complete && p.Result != nil {
			return generateReports(p.Result)
		}
	}
	return nil
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
		if err := gen.GenerateCycloneDX(result, jsonFile); err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", jsonFile)

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

	default: // "all"
		files, err := gen.GenerateAllReports(result, ts)
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
