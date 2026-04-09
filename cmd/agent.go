package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/agentconfig"
	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

// Agent CLI flags. All are optional — agent.yaml (see
// internal/agentconfig) can provide every setting. Flags override
// agent.yaml when both are set so an operator can temporarily
// redirect a scheduled run without editing the config file.
var (
	agentServer      string
	agentProfile     string
	agentInterval    time.Duration
	agentCheckConfig bool   // --check-config: validate then exit without scanning
	agentConfigDir   string // test hook: override the exe-dir search
)

// Tunables surfaced as package variables so tests can shrink the
// retry/wait windows without waiting the production durations.
var (
	// healthCheckMaxAttempts bounds the initial-reachability retry
	// loop in continuous mode. Set to 1 to make healthcheck failures
	// immediately fatal (useful for one-shot CI runs).
	healthCheckMaxAttempts = 5
	// healthCheckBackoff is the initial wait between healthcheck
	// attempts; each retry doubles up to healthCheckMaxBackoff.
	healthCheckBackoff    = 2 * time.Second
	healthCheckMaxBackoff = 30 * time.Second
)

// intervalJitterFn is swappable in tests so jitter is deterministic.
// Production uses the package-global rand source; tests inject a
// seeded source to assert on exact outputs.
var intervalJitterFn = defaultIntervalJitter

// defaultIntervalJitter returns a value in [-0.1×base, +0.1×base],
// i.e. ±10% of the interval. Kept as a package-level var so the
// package init stays trivial and tests can call it directly.
func defaultIntervalJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	// Range is one-fifth of base (±10%). rand.Int63n is exclusive
	// of its upper bound, so the max is "just under +10%".
	maxJitter := int64(base / 5)
	if maxJitter <= 0 {
		return 0
	}
	//nolint:gosec // G404: non-cryptographic jitter is intentional
	return time.Duration(rand.Int63n(maxJitter) - maxJitter/2)
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run a scan and either submit to a report server or write local reports",
	Long: `Agent mode runs a Triton scan and either submits the results to a
remote report server OR generates local reports in ./reports/,
depending on whether a report_server URL is configured.

The fool-proof deployment is to drop the triton binary plus an
agent.yaml file in a folder and run it — no CLI flags required.
Everything is read from agent.yaml. Run ` + "`triton agent --help`" + ` for
an annotated list of overrides.

Use --interval for repeated scans (e.g., 24h) or leave it unset
for one-shot.`,
	PreRunE: agentPreRun,
	RunE:    runAgent,
}

func init() {
	// --report-server is the canonical Phase 4 name; --server is kept
	// as an alias for one release cycle for backward compatibility.
	agentCmd.Flags().StringVar(&agentServer, "report-server", "", "Report server URL (e.g., http://localhost:8080). Overrides agent.yaml.")
	agentCmd.Flags().StringVar(&agentServer, "server", "", "Alias for --report-server (deprecated, will be removed)")
	if err := agentCmd.Flags().MarkDeprecated("server", "use --report-server instead"); err != nil {
		panic(fmt.Sprintf("agent cmd: MarkDeprecated(server): %v", err))
	}
	agentCmd.Flags().StringVar(&agentProfile, "profile", "", "Scan profile: quick | standard | comprehensive. Overrides agent.yaml.")
	agentCmd.Flags().DurationVar(&agentInterval, "interval", 0, "Repeat interval (e.g., 24h). If unset, runs once.")
	agentCmd.Flags().BoolVar(&agentCheckConfig, "check-config", false, "Validate agent.yaml, probe the report server, print the effective config, then exit without scanning.")
	rootCmd.AddCommand(agentCmd)
}

// agentPreRun defers feature gating until after agent.yaml is
// loaded, because the gate depends on whether we're in server-submit
// mode (enterprise-only) or local-report mode (all tiers, no gate).
// The actual check runs inside runAgent.
func agentPreRun(_ *cobra.Command, _ []string) error {
	return nil
}

// resolvedAgentConfig merges CLI flags on top of agent.yaml and
// records every source so the startup banner can be explicit.
//
// The banner distinguishes "requested" (what the operator asked for)
// from "effective" (what the tier actually permits) so the user can
// see at a glance why a standard-profile request became a quick
// scan on a free-tier licence.
type resolvedAgentConfig struct {
	source             *agentconfig.Config // file (zero-value if no file)
	licenseToken       string              // effective token after flag/env/file resolution
	reportServer       string              // effective server URL
	requestedProfile   string              // what the operator asked for
	effectiveProfile   string              // after tier filtering
	outputDir          string              // absolute path for local reports
	requestedFormats   []string            // what the operator asked for (nil = every tier-allowed)
	effectiveFormats   []string            // after tier filtering
	profileDowngraded  bool                // true when requested != effective
	formatsFilteredOut []string            // formats the tier rejected
}

// validProfiles is the closed set of scan profiles the scanner
// engine knows about. Any other value in --profile or agent.yaml
// is a typo and should produce a hard error (Sprint 3 full-review
// F3) rather than silently degrading to quick or upgrading to
// comprehensive via applyTierFiltering's fallback loop.
var validProfiles = map[string]bool{
	"quick":         true,
	"standard":      true,
	"comprehensive": true,
}

// resolveAgentConfig walks agent.yaml + CLI flags + license
// resolution chain and returns the effective settings. Errors on:
//   - malformed agent.yaml (any parse error)
//   - invalid profile value (typo in --profile or agent.yaml)
//
// Missing files are NOT an error — the loader returns a
// zero-value Config in that case and the agent proceeds with
// built-in defaults.
//
// Tier filtering: when the licence cannot satisfy the requested
// profile or formats, applyTierFiltering silently rewrites them to
// what the tier allows AND records the downgrade so
// printStartupBanner can surface it. Silent downgrade prevents the
// scan from failing on a tier mismatch; explicit banner prevents
// the operator from being surprised.
func resolveAgentConfig() (*resolvedAgentConfig, error) {
	fileCfg, err := agentconfig.Load(agentConfigDir)
	if err != nil {
		return nil, err
	}

	// Report server: CLI flag wins, then agent.yaml, then empty
	// (→ local report mode).
	server := agentServer
	if server == "" {
		server = fileCfg.ReportServer
	}

	// Profile: CLI flag wins, then agent.yaml, then "quick" as
	// the fool-proof default.
	requestedProfile := agentProfile
	if requestedProfile == "" {
		requestedProfile = fileCfg.Profile
	}
	if requestedProfile == "" {
		requestedProfile = "quick"
	}
	// Reject typos before the scan even starts — otherwise
	// applyTierFiltering's fallback loop would silently pick
	// the first allowed profile on enterprise tier (comprehensive)
	// and an operator with `standdard:` in agent.yaml would run
	// the slowest possible scan without realizing why.
	if !validProfiles[requestedProfile] {
		return nil, fmt.Errorf(
			"unknown profile %q in %s — valid profiles are: quick, standard, comprehensive",
			requestedProfile, profileSource(fileCfg.LoadedFrom(), agentProfile != ""),
		)
	}

	return &resolvedAgentConfig{
		source:           fileCfg,
		licenseToken:     fileCfg.LicenseKey,
		reportServer:     server,
		requestedProfile: requestedProfile,
		effectiveProfile: requestedProfile, // updated by applyTierFiltering
		outputDir:        fileCfg.ResolveOutputDir(),
		requestedFormats: fileCfg.Formats,
	}, nil
}

// profileSource returns a human-readable location for the invalid
// profile value so the error message points at the exact file or
// flag the operator should fix.
func profileSource(yamlPath string, cliFlagSet bool) string {
	if cliFlagSet {
		return "--profile flag"
	}
	if yamlPath != "" {
		return yamlPath
	}
	return "built-in default"
}

// applyTierFiltering downgrades the resolved config's profile and
// formats to what the active guard's tier actually allows. Must run
// AFTER the active guard reflects the full license resolution chain
// (flag → env → agent.yaml → ~/.triton), because the tier it reads
// is the source of truth for what the scanner will actually do.
//
// Takes an explicit guard argument (not the package global) so the
// caller controls guard identity — avoids the Sprint 3 full-review
// SF4 concern about mutating the global mid-run.
//
// Records downgrades on the resolvedAgentConfig so printStartupBanner
// can show them explicitly.
//
// Note: resolveAgentConfig already rejected unknown profile names,
// so this function only sees profiles from the valid closed set
// (quick | standard | comprehensive). The fallback picks the
// highest allowed profile that is <= the requested one, not a
// blind "first allowed" which would silently upgrade on enterprise
// if the valid-profile check ever regressed.
func applyTierFiltering(g *license.Guard, r *resolvedAgentConfig) {
	allowedProfiles := license.AllowedProfiles(g.Tier())
	if !contains(allowedProfiles, r.requestedProfile) {
		// Downgrade order: walk from the requested profile
		// downward, picking the first one the tier allows.
		// This ensures we never silently upgrade (comprehensive
		// on free tier should fall to quick, not to itself).
		downgradeOrder := profileDowngradeChain(r.requestedProfile)
		for _, p := range downgradeOrder {
			if contains(allowedProfiles, p) {
				r.effectiveProfile = p
				break
			}
		}
		r.profileDowngraded = true
	}

	// Format filtering: intersect requested formats with
	// tier-allowed formats. An empty requested list means "every
	// tier-allowed format", which is a non-downgrade.
	tierAllowed := license.AllowedFormats(g.Tier())
	if len(r.requestedFormats) == 0 {
		r.effectiveFormats = tierAllowed
		return
	}

	allowedSet := make(map[string]bool)
	for _, f := range tierAllowed {
		allowedSet[f] = true
	}

	effective := make([]string, 0, len(r.requestedFormats))
	var filteredOut []string
	seen := make(map[string]bool)
	for _, f := range r.requestedFormats {
		if seen[f] {
			continue
		}
		seen[f] = true
		if allowedSet[f] {
			effective = append(effective, f)
		} else {
			filteredOut = append(filteredOut, f)
		}
	}
	r.effectiveFormats = effective
	r.formatsFilteredOut = filteredOut
}

// contains is a trivial slice membership helper — Go 1.21's
// slices.Contains would do the same but keeps the import list small.
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// profileDowngradeChain returns the walk order for tier-based
// profile downgrade, starting from the requested profile and
// stepping DOWN to cheaper profiles. Ensures
// applyTierFiltering never silently upgrades a profile (e.g., a
// "standard" request on a tier that only allows "quick" should
// produce "quick", not "comprehensive" just because comprehensive
// happens to be listed first).
func profileDowngradeChain(requested string) []string {
	full := []string{"comprehensive", "standard", "quick"}
	// Find the requested profile's index and return the tail from
	// there — that gives us [requested, lower, lower-still].
	for i, p := range full {
		if p == requested {
			return full[i:]
		}
	}
	// Unknown profile (shouldn't happen because resolveAgentConfig
	// validates) — return the full chain so we at least end up on
	// "quick" as a conservative fallback rather than "comprehensive".
	return full
}

func runAgent(_ *cobra.Command, _ []string) error {
	resolved, err := resolveAgentConfig()
	if err != nil {
		return fmt.Errorf("loading agent config: %w", err)
	}

	// Use a LOCAL guard variable — never mutate the package-global
	// `guard` from root.go (Sprint 3 full-review SF4). Start with
	// whatever PersistentPreRun already resolved from flag/env/
	// default file.
	activeGuard := guard

	// If agent.yaml carries a license_key AND the CLI-level guard
	// hasn't already picked up a stronger token, rebuild the local
	// guard from the yaml value. This is how "drop agent.yaml next
	// to the exe, run it" works without any flags or env vars.
	if resolved.licenseToken != "" && activeGuard.License() == nil {
		activeGuard = license.NewGuard(resolved.licenseToken)
	}

	// F1 conflict warning: if the operator set --license-key on
	// the CLI AND agent.yaml also carries a license_key, the CLI
	// flag wins (documented precedence) but the operator may not
	// have realized agent.yaml was also supplying one. Warn loudly
	// so a misconfigured deployment doesn't silently use the wrong
	// token for an entire interval loop.
	if licenseKey != "" && resolved.licenseToken != "" {
		fmt.Fprintf(os.Stderr,
			"warning: --license-key flag overrides license_key in %s\n",
			resolved.source.LoadedFrom())
	}

	// Now that activeGuard reflects the final tier, tier-filter
	// the resolved settings so the banner and the scan loop see
	// the effective profile and format list rather than the raw
	// user-requested values.
	applyTierFiltering(activeGuard, resolved)

	// Print the startup banner BEFORE feature gating so operators
	// always see what mode they're about to run in, even if the
	// gate then refuses them.
	printStartupBanner(activeGuard, resolved)

	// Feature gating. Server submission is enterprise-only; local
	// report mode is allowed on every tier — it's just running the
	// scanner and writing files, no coordination cost.
	if resolved.reportServer != "" {
		if err := activeGuard.EnforceFeature(license.FeatureAgentMode); err != nil {
			return fmt.Errorf("server submission mode: %w", err)
		}
	}
	// Local mode: no feature gate. Tier still caps profile and
	// formats via activeGuard.FilterConfig and tierAllowedFormats below.

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var client *agent.Client
	if resolved.reportServer != "" {
		client = agent.New(resolved.reportServer)
		client.LicenseToken = resolved.licenseToken
		// In continuous (--interval) mode, retry the initial
		// healthcheck with backoff instead of exiting: a brief
		// server restart during the systemd timer firing is the
		// common case and deserves to be absorbed silently. In
		// one-shot mode we fall back to a single attempt so CI
		// pipelines fail fast on misconfiguration.
		attempts := healthCheckMaxAttempts
		if agentInterval == 0 {
			attempts = 1
		}
		if err := waitForServerReady(ctx, client, attempts); err != nil {
			return fmt.Errorf("cannot reach report server: %w", err)
		}
		fmt.Printf("Connected to report server: %s\n", resolved.reportServer)
	}

	// --check-config: report what we would have done and exit. The
	// scan is NOT run — this is intended for deployment smoke tests
	// ("did I drop the file in the right place?") without waiting
	// for a full comprehensive scan.
	if agentCheckConfig {
		fmt.Println("Config check passed — agent would run successfully with the settings above.")
		return nil
	}

	for {
		if err := runAgentScan(ctx, activeGuard, resolved, client); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}

		if agentInterval == 0 {
			return nil
		}

		// Jitter the sleep by ±10% so a fleet of agents rebooted
		// simultaneously (e.g., after a patch window) does not
		// dog-pile the report server at the same second every
		// interval. Logged as the effective wait, not the raw
		// interval, so operators can see what actually happened.
		wait := agentInterval + intervalJitterFn(agentInterval)
		if wait < 0 {
			wait = agentInterval // belt-and-braces: never sleep negative
		}
		fmt.Printf("Next scan in %s...\n", wait.Round(time.Second))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			fmt.Println("\nAgent stopped.")
			return nil
		}
	}
}

// waitForServerReady retries the report server healthcheck with
// exponential backoff so a brief server restart during the agent's
// timer firing does not crash the process. Honors ctx cancellation
// between attempts and the HTTP-layer timeout within each attempt
// (see pkg/agent.Client.HealthcheckWithContext).
//
// When maxAttempts == 1 this degrades to a single-shot check —
// exactly the original behavior, kept for one-shot runs and tests.
func waitForServerReady(ctx context.Context, client *agent.Client, maxAttempts int) error {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	backoff := healthCheckBackoff
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := client.HealthcheckWithContext(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt == maxAttempts {
			break
		}
		fmt.Fprintf(os.Stderr,
			"report server not ready (attempt %d/%d): %v — retrying in %s\n",
			attempt, maxAttempts, lastErr, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff *= 2
		if backoff > healthCheckMaxBackoff {
			backoff = healthCheckMaxBackoff
		}
	}
	return fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

// printStartupBanner tells the user in plain English which config
// sources were picked up and which mode they're about to run in.
// The banner is written to stdout (not stderr) because it's a
// success path: the agent IS starting, even if in degraded mode.
//
// Tier downgrades are called out explicitly: if the user asked
// for "standard" but got "quick", or asked for "xlsx" and it was
// filtered out, the banner says so. Silent downgrades hidden in
// the noise lead to "my reports are wrong!" support tickets.
//
// Takes the active guard explicitly (not the package global) so
// the banner reflects the same guard runAgent will actually use.
func printStartupBanner(g *license.Guard, r *resolvedAgentConfig) {
	fmt.Println("Triton Agent starting...")
	if r.source.LoadedFrom() != "" {
		fmt.Printf("  config file: %s\n", r.source.LoadedFrom())
	} else {
		fmt.Println("  config file: (none — using built-in defaults)")
	}

	// License banner — the user-visible effect of the tier.
	tier := g.Tier()
	if g.License() == nil {
		fmt.Println("  license:     NONE — running in FREE tier (quick profile, JSON report only)")
		fmt.Println("               To unlock standard/comprehensive profiles and HTML/XLSX reports,")
		fmt.Println("               place your license in agent.yaml next to this binary.")
	} else {
		fmt.Printf("  license:     %s tier (org=%s)\n", tier, g.OrgName())
		// Pre-warn the operator when the embedded license token is
		// within 30 days of expiry (or already expired under
		// guard's grace window). An agent on a 24h interval has
		// a whole month to regenerate agent.yaml from the license
		// server admin UI — we just need to surface the deadline
		// in a place they're already looking.
		if msg := licenseExpiryWarning(g.License(), time.Now()); msg != "" {
			fmt.Printf("               %s\n", msg)
		}
	}

	// Mode banner.
	if r.reportServer != "" {
		fmt.Printf("  mode:        submit to report server %s\n", r.reportServer)
	} else {
		fmt.Printf("  mode:        local reports → %s\n", r.outputDir)
	}

	// Effective profile, with a downgrade callout when it differs
	// from what was requested.
	if r.profileDowngraded {
		fmt.Printf("  profile:     %s  (requested %q, downgraded by licence tier)\n",
			r.effectiveProfile, r.requestedProfile)
	} else {
		fmt.Printf("  profile:     %s\n", r.effectiveProfile)
	}

	// Effective formats (only meaningful in local-report mode).
	// Surfaced so the operator knows which files to expect on
	// disk. A filtered-out list is shown alongside so they can
	// see what their tier would need to produce the missing
	// formats.
	if r.reportServer == "" {
		if len(r.effectiveFormats) > 0 {
			fmt.Printf("  formats:     %s\n", strings.Join(r.effectiveFormats, ", "))
		}
		if len(r.formatsFilteredOut) > 0 {
			fmt.Printf("               (tier-blocked: %s — upgrade your licence to enable)\n",
				strings.Join(r.formatsFilteredOut, ", "))
		}
	}

	fmt.Println()
}

// runAgentScan executes one scan iteration. When client is non-nil
// the result is submitted via the existing server path; otherwise
// it's written to disk as json/html/xlsx/cdx/sarif (tier-allowed).
//
// Takes the active guard as an argument so the whole runAgent call
// chain uses one identity and never touches the package global
// (Sprint 3 full-review SF4).
func runAgentScan(ctx context.Context, g *license.Guard, r *resolvedAgentConfig, client *agent.Client) error {
	fmt.Printf("Starting scan (profile: %s)...\n", r.effectiveProfile)

	// Load the config from the EFFECTIVE profile (post-tier-filter)
	// so depth / workers / module defaults match what the user's
	// tier permits. Otherwise a free-tier user who asked for
	// standard would get quick modules at standard's depth — not
	// obviously wrong but inconsistent with the banner.
	cfg := scannerconfig.Load(r.effectiveProfile)
	cfg.DBUrl = scannerconfig.DefaultDBUrl()

	// Guard filtering is still applied as a belt-and-braces step:
	// it also drops the DB URL on free tier and narrows the module
	// list to AllowedModules. Idempotent after the profile-level
	// downgrade above.
	g.FilterConfig(cfg)

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	// Initialize store for incremental scanning (best-effort).
	if cfg.DBUrl != "" {
		db, err := store.NewPostgresStore(context.Background(), cfg.DBUrl)
		if err != nil {
			// This is common on non-server deployments — don't
			// frighten the operator, just carry on without the
			// incremental cache.
			_ = err
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

	// Save incremental-scan state locally if the store is available.
	if s := eng.Store(); s != nil {
		if err := s.SaveScan(ctx, scan); err != nil {
			// Non-fatal. The scan already produced a result and the
			// user's primary output (server submit or local reports)
			// is what matters.
			_ = err
		}
	}

	if client != nil {
		return submitToServer(ctx, client, r.reportServer, scan)
	}
	return writeLocalReports(r, scan)
}

// submitToServer is the existing Phase 4 path, factored out so the
// dual-mode runAgentScan stays readable. Takes ctx so a SIGTERM
// during a large upload exits promptly instead of hanging until the
// HTTP client timeout. The retry loop inside Client.Submit also
// honors ctx, so cancel-during-backoff stops the retry chain
// deterministically.
func submitToServer(ctx context.Context, client *agent.Client, serverURL string, scan *model.ScanResult) error {
	fmt.Printf("Submitting to %s...\n", serverURL)
	resp, err := client.Submit(ctx, scan)
	if err != nil {
		return fmt.Errorf("submit failed: %w", err)
	}
	fmt.Printf("Submitted: id=%s status=%s\n", resp.ID, resp.Status)
	return nil
}

// writeLocalReports generates reports into <outputDir>/<timestamp>/
// in every format that survived tier filtering. The timestamped
// subdirectory keeps historical runs from clobbering each other.
// r.effectiveFormats has already been computed by applyTierFiltering.
func writeLocalReports(r *resolvedAgentConfig, scan *model.ScanResult) error {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	runDir := filepath.Join(r.outputDir, timestamp)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("creating report directory %s: %w", runDir, err)
	}

	if len(r.effectiveFormats) == 0 {
		// Should be impossible — every tier allows at least JSON —
		// but guard against a future tier-table change that
		// accidentally zeros it out.
		return fmt.Errorf("no report formats allowed by current license tier")
	}

	gen := report.New(runDir)
	fmt.Printf("Writing reports to %s:\n", runDir)
	for _, format := range r.effectiveFormats {
		filename := reportFilename(format, timestamp)
		path := filepath.Join(runDir, filename)
		if err := generateByFormat(gen, format, scan, path); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: FAILED (%v)\n", format, err)
			continue
		}
		fmt.Printf("  %s: %s\n", format, filename)
	}
	return nil
}

// reportFilename maps a format tag to the on-disk filename. The
// prefixes match what cmd/root.go::generateReports produces so an
// operator moving between `triton scan` and `triton agent` gets
// consistent file naming.
func reportFilename(format, timestamp string) string {
	switch format {
	case "json":
		return fmt.Sprintf("triton-report-%s.json", timestamp)
	case "cdx":
		return fmt.Sprintf("triton-report-%s.cdx.json", timestamp)
	case "html":
		return fmt.Sprintf("triton-report-%s.html", timestamp)
	case "xlsx":
		return fmt.Sprintf("Triton_PQC_Report-%s.xlsx", timestamp)
	case "sarif":
		return fmt.Sprintf("triton-report-%s.sarif", timestamp)
	default:
		return fmt.Sprintf("triton-report-%s.%s", timestamp, format)
	}
}

// licenseExpiryWarning returns a human-readable message when the
// license is within 30 days of expiry, or already expired within
// the guard's grace window. Returns "" when the license has more
// than 30 days of runway — no banner noise in the common case.
//
// Pure function: takes an explicit now so the unit test doesn't
// need to freeze time.Now().
func licenseExpiryWarning(lic *license.License, now time.Time) string {
	if lic == nil {
		return ""
	}
	expiry := time.Unix(lic.ExpiresAt, 0)
	remaining := expiry.Sub(now)
	switch {
	case remaining < 0:
		return fmt.Sprintf(
			"WARNING: license EXPIRED on %s — regenerate agent.yaml from the license server admin UI before the next scan",
			expiry.Format("2006-01-02"))
	case remaining < 7*24*time.Hour:
		return fmt.Sprintf(
			"WARNING: license expires in %s (%s) — regenerate agent.yaml soon",
			remaining.Round(time.Hour), expiry.Format("2006-01-02"))
	case remaining < 30*24*time.Hour:
		days := int(remaining.Hours() / 24)
		return fmt.Sprintf(
			"notice: license expires in %d days (%s) — plan to regenerate agent.yaml",
			days, expiry.Format("2006-01-02"))
	}
	return ""
}

// generateByFormat dispatches to the right Generator method. The
// cases match pkg/report/generator.go's public API.
func generateByFormat(gen *report.Generator, format string, scan *model.ScanResult, path string) error {
	switch format {
	case "json":
		return gen.GenerateTritonJSON(scan, path)
	case "cdx":
		return gen.GenerateCycloneDXBOM(scan, path)
	case "html":
		return gen.GenerateHTML(scan, path)
	case "xlsx":
		return gen.GenerateExcel(scan, path)
	case "sarif":
		return gen.GenerateSARIF(scan, path)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
