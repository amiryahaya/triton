package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/amiryahaya/triton/pkg/scanner"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system readiness for scanning",
	Long: `Run pre-flight checks to verify that your system has the tools and
permissions needed for a successful scan. Checks are filtered by the
selected scan profile (--profile flag).`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

// errDoctorFailed is a sentinel error used to signal a non-zero exit code.
var errDoctorFailed = fmt.Errorf("system readiness check found failures")

func runDoctor(cmd *cobra.Command, args []string) error {
	report := scanner.RunDoctorChecks(scanProfile)

	isTerminal := term.IsTerminal(int(os.Stdout.Fd()))
	printDoctorReport(report, isTerminal)

	if report.HasFailures() {
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		return errDoctorFailed
	}
	return nil
}

func printDoctorReport(report *scanner.DoctorReport, color bool) {
	fmt.Println("Triton Doctor — System Readiness Check")
	fmt.Printf("Platform: %s\n", report.Platform)
	fmt.Printf("Profile:  %s\n\n", report.Profile)

	// Compute column widths
	moduleW := len("Module")
	checkW := len("Check")
	for _, c := range report.Checks {
		if len(c.Module) > moduleW {
			moduleW = len(c.Module)
		}
		if len(c.CheckName) > checkW {
			checkW = len(c.CheckName)
		}
	}

	// Header
	header := fmt.Sprintf("%-*s  %-*s  %-6s  %s", moduleW, "Module", checkW, "Check", "Status", "Message")
	divider := strings.Repeat("\u2500", len(header))

	fmt.Println(header)
	fmt.Println(divider)

	// ANSI escape codes add invisible bytes; use wider padding to compensate
	statusW := 6
	if color {
		statusW = 15 // 4 visible chars + 9 ANSI bytes + 2 padding
	}

	for _, c := range report.Checks {
		status := c.Status.String()
		if color {
			status = colorStatus(c.Status)
		}
		fmt.Printf("%-*s  %-*s  %-*s  %s\n", moduleW, c.Module, checkW, c.CheckName, statusW, status, c.Message)
	}

	fmt.Println(divider)
	fmt.Printf("Results: %d passed, %d warnings, %d failures\n\n", report.PassCount, report.WarnCount, report.FailCount)

	if report.HasFailures() {
		if color {
			fmt.Println("\033[31m✗ System has issues that will affect scan results\033[0m")
		} else {
			fmt.Println("✗ System has issues that will affect scan results")
		}
		printSuggestions(report)
	} else if report.WarnCount > 0 {
		if color {
			fmt.Println("\033[33m✓ System is ready for scanning (warnings are advisory)\033[0m")
		} else {
			fmt.Println("✓ System is ready for scanning (warnings are advisory)")
		}
		printSuggestions(report)
	} else {
		if color {
			fmt.Println("\033[32m✓ System is fully ready for scanning\033[0m")
		} else {
			fmt.Println("✓ System is fully ready for scanning")
		}
	}
}

func colorStatus(s scanner.CheckStatus) string {
	switch s {
	case scanner.CheckPass:
		return "\033[32mPASS\033[0m"
	case scanner.CheckWarn:
		return "\033[33mWARN\033[0m"
	case scanner.CheckFail:
		return "\033[31mFAIL\033[0m"
	default:
		return s.String()
	}
}

func printSuggestions(report *scanner.DoctorReport) {
	fmt.Println("\nSuggestions:")
	for _, c := range report.Checks {
		if c.Suggestion != "" {
			fmt.Printf("  • [%s] %s: %s\n", c.Module, c.CheckName, c.Suggestion)
		}
	}
}
