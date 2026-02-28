package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	policyFile string
	policyScan string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy compliance commands",
}

var policyCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Evaluate a policy against the latest or specified scan",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		f := license.FeaturePolicyBuiltin
		if _, err := policy.LoadBuiltin(policyFile); err != nil {
			f = license.FeaturePolicyCustom
		}
		return guard.EnforceFeature(f)
	},
	RunE: runPolicyCheck,
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available builtin policies",
	RunE:  runPolicyList,
}

func init() {
	policyCheckCmd.Flags().StringVar(&policyFile, "policy", "", "Policy file path or builtin name (nacsa-2030, cnsa-2.0)")
	policyCheckCmd.Flags().StringVar(&policyScan, "scan", "", "Scan ID to evaluate (default: latest)")
	_ = policyCheckCmd.MarkFlagRequired("policy")

	policyCmd.AddCommand(policyCheckCmd)
	policyCmd.AddCommand(policyListCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyCheck(_ *cobra.Command, _ []string) error {
	// Load policy: try builtin first, then file.
	pol, err := policy.LoadBuiltin(policyFile)
	if err != nil {
		pol, err = policy.LoadFromFile(policyFile)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
	}

	// Load scan result from database.
	db, err := openStore()
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}

	result, err := loadTargetScan(db, policyScan)
	if err != nil {
		_ = db.Close()
		return err
	}

	// Evaluate policy.
	eval := policy.Evaluate(pol, result)
	_ = db.Close()

	// Print results.
	fmt.Printf("Policy: %s\n", eval.PolicyName)
	fmt.Printf("Scan:   %s (%s)\n", result.ID, result.Metadata.Hostname)
	fmt.Printf("Verdict: %s\n\n", eval.Verdict)

	if len(eval.Violations) > 0 {
		fmt.Printf("Rule Violations (%d):\n", len(eval.Violations))
		for _, v := range eval.Violations {
			icon := "!"
			if v.Action == "fail" {
				icon = "X"
			}
			fmt.Printf("  [%s] %s (%s): %s\n", icon, v.RuleID, v.Severity, v.Message)
		}
		fmt.Println()
	}

	if len(eval.ThresholdViolations) > 0 {
		fmt.Printf("Threshold Violations (%d):\n", len(eval.ThresholdViolations))
		for _, tv := range eval.ThresholdViolations {
			fmt.Printf("  [X] %s: %s (expected %s, got %s)\n", tv.Name, tv.Message, tv.Expected, tv.Actual)
		}
		fmt.Println()
	}

	if eval.Verdict == policy.VerdictPass {
		fmt.Println("All policy checks passed.")
	}

	// Return sentinel error for CI/CD exit code.
	if eval.Verdict == policy.VerdictFail {
		return ErrPolicyFail
	}

	return nil
}

func runPolicyList(_ *cobra.Command, _ []string) error {
	names := policy.ListBuiltin()
	fmt.Println("Available builtin policies:")
	for _, name := range names {
		pol, err := policy.LoadBuiltin(name)
		if err != nil {
			continue
		}
		fmt.Printf("  %-14s  %s (%d rules)\n", name, pol.Name, len(pol.Rules))
	}
	fmt.Printf("\nUsage: triton policy check --policy <name-or-file>\n")
	return nil
}

// loadTargetScan loads a specific scan by ID, or the most recent scan if no ID is given.
func loadTargetScan(db *store.PostgresStore, scanID string) (*model.ScanResult, error) {
	ctx := context.Background()

	if scanID != "" {
		return db.GetScan(ctx, scanID)
	}

	// Get the most recent scan.
	summaries, err := db.ListScans(ctx, store.ScanFilter{Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}
	if len(summaries) == 0 {
		return nil, fmt.Errorf("no scans found in database — run a scan first")
	}

	return db.GetScan(ctx, summaries[0].ID)
}
