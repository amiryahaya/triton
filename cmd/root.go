package cmd

import (
	"context"
	"encoding/hex"
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

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/runtime/limits"
	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

// ErrPolicyFail is returned when a policy evaluation fails,
// allowing the caller to set the appropriate exit code.
var ErrPolicyFail = errors.New("policy evaluation failed")

// progressBufferSize is the buffer capacity for the scan progress channel.
const progressBufferSize = 16

var (
	cfgFile           string
	outputDir         string
	outputFile        string
	scanProfile       string
	modules           []string
	format            string
	showMetrics       bool
	dbPath            string
	incremental       bool
	scanPolicyArg     string
	scanExemptionsArg string
	licenseKey        string
	licenseFile       string // --license-file path override (Phase 5 Sprint 3)
	licenseServerURL  string
	licenseID         string
	guard             = license.NewGuard("") // safe default, overwritten by PersistentPreRun

	// OCI / Kubernetes scan flags (Wave 0)
	imageRefs      []string
	kubeconfigPath string
	k8sContext     string
	k8sNamespace   string
	registryAuth   string

	// OIDC/JWKS probe flags (Wave 2)
	oidcEndpoints []string

	// DNSSEC active query flags (Wave 2 §6.1)
	dnssecZones []string

	// Keystore password list (PCert parity sprint)
	keystorePasswords []string

	// Job-runner lifecycle mode flags (one-of-six; mutually exclusive).
	detachMode   bool
	statusMode   bool
	collectMode  bool
	cancelMode   bool
	listJobsMode bool
	cleanupMode  bool

	// Job-runner shared/control flags.
	detachJobID   string
	detachWorkDir string
	detachQuiet   bool

	validFormats = map[string]bool{"json": true, "cdx": true, "html": true, "xlsx": true, "sarif": true, "all": true}

	rootCmd = &cobra.Command{
		Use:     "triton",
		Short:   "SBOM/CBOM scanner for PQC compliance",
		Version: version.Version,
		Long: `Triton scans systems to generate Software Bill of Materials (SBOM)
and Cryptographic Bill of Materials (CBOM) for Post-Quantum Cryptography compliance.

Target: Malaysian government critical sectors for 2030 PQC readiness.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if licenseServerURL != "" {
				// Online validation path. Precedence on this branch
				// is narrower than the offline path: --license-key
				// wins, and if it's unset --license-file is read
				// once to seed licenseKey. TRITON_LICENSE_KEY env
				// and TRITON_LICENSE_FILE env are NOT honored on
				// this path — an operator using env vars for token
				// delivery should not be running online validation
				// because NewGuardWithServer does its own env
				// handling via the cache meta file. If you need
				// the full flag→env→file precedence, use the
				// offline path (don't pass --license-server).
				if licenseKey == "" && licenseFile != "" {
					if token := license.LoadTokenFromFile(licenseFile); token != "" {
						licenseKey = token
					}
				}
				guard = license.NewGuardWithServer(licenseKey, licenseServerURL, licenseID)
				return
			}
			// Offline validation path with full
			// flag → env → file precedence including the
			// --license-file override (Phase 5 Sprint 3).
			//
			// When REPORT_SERVER_TENANT_PUBKEY is set, use it as
			// the override pubkey for token verification so
			// multi-tenant deployments can mint licences with
			// a customer-specific key without rebuilding the
			// binary. The report server's UnifiedAuth path honors
			// the same env var (see cmd/server.go).
			//
			// D3 fix: invalid hex or wrong length is FATAL, not
			// silently ignored. An operator who intended to
			// configure a tenant-specific key but mistyped it
			// would otherwise silently fall back to the embedded
			// production pubkey and get confusing "licence
			// invalid" errors. Hard fail gives them a clear
			// message at startup.
			if pubHex := os.Getenv("REPORT_SERVER_TENANT_PUBKEY"); pubHex != "" {
				pubBytes, err := hex.DecodeString(pubHex)
				if err != nil {
					fmt.Fprintf(os.Stderr, "REPORT_SERVER_TENANT_PUBKEY is not valid hex: %v\n", err)
					os.Exit(1)
				}
				if len(pubBytes) != 32 {
					fmt.Fprintf(os.Stderr, "REPORT_SERVER_TENANT_PUBKEY: expected 32 bytes (Ed25519 public key), got %d\n", len(pubBytes))
					os.Exit(1)
				}
				// D4 fix: use the canonical resolveToken
				// precedence via NewGuardFromFlags' internals by
				// calling the library-level helper that honors
				// --license-key → TRITON_LICENSE_KEY → --license-file →
				// TRITON_LICENSE_FILE → default. We can't use
				// NewGuardFromFlags directly because it embeds the
				// default pubkey; instead we pre-resolve the token
				// using the shared helper and then apply the
				// override pubkey.
				token := license.ResolveToken(licenseKey, licenseFile)
				guard = license.NewGuardFromToken(token, pubBytes)
				return
			}
			guard = license.NewGuardFromFlags(licenseKey, licenseFile)
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
	rootCmd.PersistentFlags().StringVar(&scanExemptionsArg, "exemptions", "",
		"Exemptions YAML file for known-accepted findings (env: TRITON_EXEMPTIONS_FILE)")
	rootCmd.PersistentFlags().StringVar(&licenseKey, "license-key", "", "Licence key or token (literal)")
	rootCmd.PersistentFlags().StringVar(&licenseFile, "license-file", "", "Path to a file containing the licence token (overrides the default ~/.triton/license.key)")
	rootCmd.PersistentFlags().StringVar(&licenseServerURL, "license-server", "", "License server URL for online validation")
	rootCmd.PersistentFlags().StringVar(&licenseID, "license-id", "", "License ID for server activation")
	rootCmd.PersistentFlags().StringSliceVar(&imageRefs, "image", nil,
		"OCI image reference to scan (repeatable, e.g. --image nginx:1.25 --image redis:7)")
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "",
		"Path to kubeconfig for live Kubernetes cluster scan (Sprint 1b)")
	rootCmd.PersistentFlags().StringVar(&k8sContext, "k8s-context", "",
		"Kubeconfig context name (used with --kubeconfig)")
	rootCmd.PersistentFlags().StringVar(&k8sNamespace, "k8s-namespace", "",
		"Kubernetes namespace to scan (default: all namespaces)")
	rootCmd.PersistentFlags().StringVar(&registryAuth, "registry-auth", "",
		"Path to docker config.json override for image registry auth")
	rootCmd.PersistentFlags().StringSliceVar(&oidcEndpoints, "oidc-endpoint", nil,
		"OIDC identity provider URL to probe (repeatable, e.g. --oidc-endpoint https://auth.example.com)")
	rootCmd.PersistentFlags().StringSliceVar(&dnssecZones, "dnssec-zone", nil,
		"DNS zone to query via dig for DNSSEC algorithm inventory (repeatable, e.g. --dnssec-zone example.com)")
	rootCmd.PersistentFlags().StringSliceVar(&keystorePasswords, "keystore-passwords", nil,
		"Passwords to try on PKCS#12/JKS/JCEKS keystores (comma-separated, env: TRITON_KEYSTORE_PASSWORDS)")

	// eBPF trace flags (Linux-only; other platforms emit a skipped-finding).
	rootCmd.PersistentFlags().Duration("ebpf-window", 60*time.Second,
		"observation window for the ebpf_trace module (Linux only); clamped to [1s, 30m]")
	rootCmd.PersistentFlags().Bool("ebpf-skip-uprobes", false,
		"skip userspace uprobes in ebpf_trace (Linux only)")
	rootCmd.PersistentFlags().Bool("ebpf-skip-kprobes", false,
		"skip kernel kprobes in ebpf_trace (Linux only)")

	// Pcap / TLS observer flags
	rootCmd.PersistentFlags().String("pcap-file", "",
		"path to .pcap file for offline TLS observation (pcapng not yet supported; convert with editcap -F pcap)")
	rootCmd.PersistentFlags().String("pcap-interface", "",
		"network interface for live TLS capture (Linux only, requires CAP_NET_RAW)")
	rootCmd.PersistentFlags().Duration("pcap-window", 30*time.Second,
		"live capture duration for tls_observer (clamped to [1s, 5m])")
	rootCmd.PersistentFlags().String("pcap-filter", "tcp port 443",
		"BPF filter for tls_observer (default: tcp port 443)")
	rootCmd.MarkFlagsMutuallyExclusive("pcap-file", "pcap-interface")

	// Resource limits (applies to foreground scans, future agent-supervised
	// scans, and future ssh-agentless orchestrator invocations).
	rootCmd.PersistentFlags().String("max-memory", "",
		"soft memory cap (e.g. 2GB, 512MB); hard watchdog triggers self-kill at 1.5x")
	rootCmd.PersistentFlags().String("max-cpu-percent", "",
		"cap GOMAXPROCS to this percentage of NumCPU (1-100; caps parallelism, not CPU time)")
	rootCmd.PersistentFlags().Duration("max-duration", 0,
		"wall-clock budget for the scan (e.g. 4h); scan returns partial results on timeout")
	rootCmd.PersistentFlags().String("stop-at", "",
		"stop the scan at this local clock time (HH:MM); if past, rolls to tomorrow")
	rootCmd.PersistentFlags().Int("nice", 0,
		"scheduling priority adjustment (unix only; higher = lower priority; 0 = no change)")

	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("profile", rootCmd.PersistentFlags().Lookup("profile"))

	// Job-runner lifecycle flags (wired to runScan via dispatch switch).
	rootCmd.PersistentFlags().BoolVar(&detachMode, "detach", false,
		"run scan as a detached background job (returns job-id, survives SSH disconnect)")
	rootCmd.PersistentFlags().BoolVar(&statusMode, "status", false,
		"print status of a detached scan (requires --job-id)")
	rootCmd.PersistentFlags().BoolVar(&collectMode, "collect", false,
		"retrieve reports from a detached scan (requires --job-id)")
	rootCmd.PersistentFlags().BoolVar(&cancelMode, "cancel", false,
		"cancel a running detached scan (requires --job-id)")
	rootCmd.PersistentFlags().BoolVar(&listJobsMode, "list-jobs", false,
		"list all detached scan jobs under the work-dir")
	rootCmd.PersistentFlags().BoolVar(&cleanupMode, "cleanup", false,
		"remove finished job(s) from the work-dir (requires --job-id or --all)")

	rootCmd.PersistentFlags().StringVar(&detachJobID, "job-id", "",
		"explicit job id (default: auto-generated UUID for --detach)")
	rootCmd.PersistentFlags().StringVar(&detachWorkDir, "work-dir", "",
		"work-dir root for job state (default: ~/.triton/jobs)")
	rootCmd.PersistentFlags().BoolVar(&detachQuiet, "quiet", false,
		"print only the job-id on --detach (for scripting)")
	rootCmd.PersistentFlags().Bool("wait", false,
		"block until daemon terminates (only with --cancel)")
	rootCmd.PersistentFlags().Duration("timeout", 30*time.Second,
		"timeout for --cancel --wait")
	rootCmd.PersistentFlags().Bool("keep", false,
		"do not auto-remove the work-dir after --collect")
	rootCmd.PersistentFlags().Bool("all", false,
		"remove all finished jobs (only with --cleanup)")
	rootCmd.PersistentFlags().Bool("json", false,
		"machine-readable output for --status / --list-jobs")

	rootCmd.MarkFlagsMutuallyExclusive(
		"detach", "status", "collect", "cancel", "list-jobs", "cleanup",
	)
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
		return fmt.Errorf("invalid format %q: must be one of json, cdx, html, xlsx, sarif, all", format)
	}

	// Daemon mode: started by a parent via TRITON_DETACHED=1.
	if isDaemonMode() {
		return runScanDaemon(cmd, args)
	}
	// Lifecycle modes: mutually exclusive, dispatched to scan_jobs.go.
	switch {
	case detachMode:
		return runScanDetached(cmd, args)
	case statusMode:
		return runJobStatus(cmd, args)
	case collectMode:
		return runJobCollect(cmd, args)
	case cancelMode:
		return runJobCancel(cmd, args)
	case listJobsMode:
		return runJobList(cmd, args)
	case cleanupMode:
		return runJobCleanup(cmd, args)
	}

	fmt.Printf("Triton SBOM/CBOM Scanner v%s\n", version.Version)
	fmt.Printf("Platform: %s/%s | Licence: %s\n\n", runtime.GOOS, runtime.GOARCH, guard.Tier())

	// Enforce licence gates on profile/format and feature flags. Shared
	// with runScanDetached so the two paths can't drift. Profile-downgrade
	// for defaults must happen before BuildConfig so the downgraded
	// profile is reflected in the resulting config.
	if err := enforceScanLicense(cmd); err != nil {
		return err
	}

	cfg, buildErr := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile:       scanProfile,
		Modules:       modules,
		ImageRefs:     imageRefs,
		Kubeconfig:    kubeconfigPath,
		K8sContext:    k8sContext,
		K8sNamespace:  k8sNamespace,
		RegistryAuth:  registryAuth,
		DBUrl:         dbPath,
		Metrics:       showMetrics,
		Incremental:   incremental,
		OIDCEndpoints: oidcEndpoints,
		DNSSECZones:   dnssecZones,
	})
	if buildErr != nil {
		fmt.Fprintln(os.Stderr, "error:", buildErr)
		os.Exit(1)
	}

	// Apply eBPF trace flag overrides. Window is clamped to [1s, 30m] so a
	// user-supplied zero or absurd value cannot hang or spam the kernel.
	if v, err := cmd.Flags().GetDuration("ebpf-window"); err == nil && v > 0 {
		if v < time.Second {
			v = time.Second
		}
		if v > 30*time.Minute {
			v = 30 * time.Minute
		}
		cfg.EBPFWindow = v
	}
	if v, err := cmd.Flags().GetBool("ebpf-skip-uprobes"); err == nil {
		cfg.EBPFSkipUprobes = v
	}
	if v, err := cmd.Flags().GetBool("ebpf-skip-kprobes"); err == nil {
		cfg.EBPFSkipKprobes = v
	}

	// Apply pcap / TLS observer flag overrides.
	if v, _ := cmd.Flags().GetString("pcap-file"); v != "" {
		cfg.PcapFile = v
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type: model.TargetPcap, Value: v,
		})
	}
	if v, _ := cmd.Flags().GetString("pcap-interface"); v != "" {
		cfg.PcapInterface = v
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type: model.TargetPcap, Value: "iface:" + v,
		})
	}
	if v, err := cmd.Flags().GetDuration("pcap-window"); err == nil && v > 0 {
		if v < time.Second {
			v = time.Second
		}
		if v > 5*time.Minute {
			v = 5 * time.Minute
		}
		cfg.PcapWindow = v
	}
	if v, _ := cmd.Flags().GetString("pcap-filter"); v != "" {
		cfg.PcapFilter = v
	}

	// Keystore passwords: CLI flag → env var → empty (built-in defaults only).
	if len(keystorePasswords) > 0 {
		cfg.KeystorePasswords = keystorePasswords
	} else if envPW := os.Getenv("TRITON_KEYSTORE_PASSWORDS"); envPW != "" {
		cfg.KeystorePasswords = strings.Split(envPW, ",")
	}

	// Feature-gate checks (metrics/incremental/db/policy) live in
	// enforceScanLicense above; nothing more to do here before the engine.

	if cfg.DBUrl == "" {
		cfg.DBUrl = scannerconfig.DefaultDBUrl()
	}

	// Apply licence-based config filtering (restricts modules for free tier).
	guard.FilterConfig(cfg)

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	// Initialize store for incremental scanning and result persistence.
	if cfg.DBUrl != "" {
		dbCtx, dbCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dbCancel()
		db, err := store.NewPostgresStore(dbCtx, cfg.DBUrl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open database: %v\n", err)
		} else {
			eng.SetStore(db)
			defer func() { _ = db.Close() }()
		}
	}

	maxMem, _ := cmd.Flags().GetString("max-memory")
	maxCPU, _ := cmd.Flags().GetString("max-cpu-percent")
	maxDur, _ := cmd.Flags().GetDuration("max-duration")
	stopAt, _ := cmd.Flags().GetString("stop-at")
	niceVal, _ := cmd.Flags().GetInt("nice")
	lim, err := buildLimits(maxMem, maxCPU, maxDur, stopAt, niceVal)
	if err != nil {
		return err
	}
	if lim.Enabled() {
		fmt.Printf("Resource %s\n", lim.String())
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()
	limitedCtx, limitsCleanup := lim.Apply(baseCtx)
	defer limitsCleanup()

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return runScanHeadless(eng, limitedCtx)
	}

	progressCh := make(chan scanner.Progress, progressBufferSize)
	// Preserve `cancel` as a name — the BubbleTea scanModel captures it.
	// Cancelling it cancels baseCtx, which propagates to limitedCtx.
	cancel := baseCancel

	go eng.Scan(limitedCtx, progressCh)

	// Ensure the scan goroutine can always drain after cancel to prevent goroutine leak.
	// The BubbleTea program stops reading on Ctrl+C, but the goroutine may still be
	// sending to progressCh. Draining ensures it can exit.
	defer func() {
		cancel()
		for range progressCh {
		}
	}()

	sm := scanModel{
		progress:   progress.New(progress.WithDefaultGradient()),
		progressCh: progressCh,
		cancel:     cancel,
	}

	p := tea.NewProgram(sm)

	finalModel, err := p.Run()
	if err != nil {
		return err
	}

	final, ok := finalModel.(scanModel)
	if !ok {
		return nil
	}
	if final.err != nil {
		return final.err
	}
	if final.result == nil {
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

func runScanHeadless(eng *scanner.Engine, parentCtx context.Context) error {
	progressCh := make(chan scanner.Progress, progressBufferSize)
	ctx, stop := signal.NotifyContext(parentCtx, os.Interrupt)
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

// buildLimits converts raw CLI flag values into a validated Limits struct.
// Returns an error if any flag value is malformed. time.Now() is called
// inline so --stop-at resolves against the actual clock at scan start.
func buildLimits(maxMemory, maxCPUPercent string, maxDuration time.Duration, stopAt string, nice int) (limits.Limits, error) {
	memBytes, err := limits.ParseSize(maxMemory)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("--max-memory: %w", err)
	}
	cpuPct, err := limits.ParsePercent(maxCPUPercent)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("--max-cpu-percent: %w", err)
	}
	stopOffset, err := limits.ParseStopAt(stopAt, time.Now())
	if err != nil {
		return limits.Limits{}, fmt.Errorf("--stop-at: %w", err)
	}
	return limits.Limits{
		MaxMemoryBytes: memBytes,
		MaxCPUPercent:  cpuPct,
		MaxDuration:    maxDuration,
		StopAtOffset:   stopOffset,
		Nice:           nice,
	}, nil
}

// saveScanResult persists a scan result using the engine's store.
func saveScanResult(eng *scanner.Engine, result *model.ScanResult) error {
	s := eng.Store()
	if s == nil {
		return nil
	}
	return s.SaveScan(context.Background(), result)
}

// generateSingleReport generates one report file for the given format.
func generateSingleReport(gen *report.Generator, result *model.ScanResult, fmtName, ts string) (string, error) {
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
	return path, err
}

func generateReports(result *model.ScanResult) error {
	if len(result.Systems) == 0 && len(result.Findings) > 0 {
		result.Systems = model.GroupFindingsIntoSystemsWithAgility(result.Findings, crypto.AssessAssetAgility)
		result.Summary.TotalSystems = len(result.Systems)
	}

	ts := time.Now().Format("20060102-150405")
	gen := report.New(outputDir)

	if format != "all" {
		path, err := generateSingleReport(gen, result, format, ts)
		if err != nil {
			return err
		}
		fmt.Printf("Report saved to: %s\n", path)
		return nil
	}

	// "all" — generate all allowed formats
	files, err := generateAllowedReports(gen, result, ts)
	if err != nil {
		return err
	}
	fmt.Println("Reports generated:")
	for _, f := range files {
		fmt.Printf("  - %s\n", f)
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

	var exemptions *policy.ExemptionList
	exemptionsPath := scanExemptionsArg
	if exemptionsPath == "" {
		exemptionsPath = os.Getenv("TRITON_EXEMPTIONS_FILE")
	}
	if exemptionsPath != "" {
		exemptions, err = policy.LoadExemptionsFile(exemptionsPath)
		if err != nil {
			return fmt.Errorf("loading exemptions: %w", err)
		}
	}

	eval := policy.Evaluate(pol, result, exemptions)
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
	if len(eval.ExemptionsApplied) > 0 {
		fmt.Printf("Exemptions applied: %d\n", len(eval.ExemptionsApplied))
	}
	if len(eval.ExemptionsExpired) > 0 {
		fmt.Printf("⚠ Expired exemptions: %d\n", len(eval.ExemptionsExpired))
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
		path, err := generateSingleReport(gen, result, fmtName, ts)
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
