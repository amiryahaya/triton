package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

var (
	cfgFile     string
	outputFile  string
	scanProfile string
	modules     []string

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
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "triton-report.json", "Output file for scan results")
	rootCmd.PersistentFlags().StringVarP(&scanProfile, "profile", "p", "standard", "Scan profile: quick, standard, comprehensive")
	rootCmd.PersistentFlags().StringSliceVarP(&modules, "modules", "m", []string{}, "Specific modules to run (default: all)")

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
	progress  progress.Model
	result    *model.ScanResult
	err       error
	done      bool
	statusMsg string
}

type scanMsg struct {
	progress float64
	status   string
	done     bool
	err      error
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(
		m.runScan(),
		m.progress.Init(),
	)
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
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
			m.statusMsg = msg.status
			return m, tea.Quit
		}
		m.statusMsg = msg.status
		cmd := m.progress.SetPercent(msg.progress)
		return m, cmd

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
		return fmt.Sprintf("\n%s\n\nReport saved to: %s\n\n", m.statusMsg, outputFile)
	}

	return fmt.Sprintf(
		"\nTriton Scanner - %s\n\n%s\n\n%s\n\nPress Ctrl+C to cancel\n",
		scanProfile,
		m.statusMsg,
		m.progress.View(),
	)
}

func (m scanModel) runScan() tea.Cmd {
	return func() tea.Msg {
		cfg := config.Load(scanProfile)
		if len(modules) > 0 {
			cfg.Modules = modules
		}

		eng := scanner.New(cfg)
		eng.RegisterDefaultModules()

		progressCh := make(chan scanner.Progress)
		ctx := context.Background()
		go eng.Scan(ctx, progressCh)

		for p := range progressCh {
			if p.Error != nil {
				return scanMsg{err: p.Error}
			}
			if p.Complete {
				m.result = p.Result
				return scanMsg{done: true, status: p.Status}
			}
			return scanMsg{progress: p.Percent, status: p.Status}
		}

		return scanMsg{done: true}
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	fmt.Printf("Triton SBOM/CBOM Scanner v0.1.0\n")
	fmt.Printf("Platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	p := tea.NewProgram(scanModel{
		progress: progress.New(progress.WithDefaultGradient()),
	})

	if _, err := p.Run(); err != nil {
		return err
	}

	return nil
}
