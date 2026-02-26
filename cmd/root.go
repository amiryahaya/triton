package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/amiryahaya/triton/internal/config"
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

	validFormats = map[string]bool{"json": true, "html": true, "csv": true, "all": true}

	rootCmd = &cobra.Command{
		Use:   "triton",
		Short: "SBOM/CBOM scanner for PQC compliance",
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
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "all", "Output format: json, html, csv, all")

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
		return fmt.Errorf("invalid format %q: must be one of json, html, csv, all", format)
	}

	fmt.Printf("Triton SBOM/CBOM Scanner v0.1.0\n")
	fmt.Printf("Platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	cfg := config.Load(scanProfile)
	if len(modules) > 0 {
		cfg.Modules = modules
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

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

func generateReports(result *model.ScanResult) error {
	// Group findings into systems if not already populated
	if len(result.Systems) == 0 && len(result.Findings) > 0 {
		result.Systems = report.GroupFindingsIntoSystems(result.Findings)
		result.Summary.TotalSystems = len(result.Systems)
	}

	gen := report.New(outputDir)

	switch format {
	case "json":
		if err := gen.GenerateCycloneDX(result, outputFile); err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", outputFile)

	case "html":
		htmlFile := filepath.Join(outputDir, "triton-report.html")
		if err := gen.GenerateHTML(result, htmlFile); err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", htmlFile)

	case "csv":
		j1 := filepath.Join(outputDir, "Jadual_1_SBOM.csv")
		j2 := filepath.Join(outputDir, "Jadual_2_CBOM.csv")
		rr := filepath.Join(outputDir, "Risk_Register.csv")
		if err := gen.GenerateJadual1(result, j1); err != nil {
			return err
		}
		if err := gen.GenerateJadual2(result, j2); err != nil {
			return err
		}
		if err := gen.GenerateRiskRegister(result, rr); err != nil {
			return err
		}
		fmt.Printf("Reports saved to: %s, %s, %s\n", j1, j2, rr)

	default: // "all"
		files, err := gen.GenerateAllReports(result)
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
