package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Licence management commands",
}

var licenseShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current licence information",
	RunE:  runLicenseShow,
}

var licenseVerifyCmd = &cobra.Command{
	Use:   "verify <token>",
	Short: "Verify a licence token and show details",
	Args:  cobra.ExactArgs(1),
	RunE:  runLicenseVerify,
}

func init() {
	licenseCmd.AddCommand(licenseShowCmd)
	licenseCmd.AddCommand(licenseVerifyCmd)
	rootCmd.AddCommand(licenseCmd)
}

func runLicenseShow(_ *cobra.Command, _ []string) error {
	fmt.Printf("Licence Tier: %s\n", guard.Tier())
	fmt.Printf("Seats:        %d\n", guard.Seats())

	if lic := guard.License(); lic != nil {
		fmt.Printf("Licence ID:   %s\n", lic.ID)
		fmt.Printf("Organisation: %s\n", lic.Org)
		fmt.Printf("Issued:       %s\n", time.Unix(lic.IssuedAt, 0).UTC().Format(time.RFC3339))
		fmt.Printf("Expires:      %s\n", time.Unix(lic.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}

	fmt.Printf("\nAllowed profiles: %v\n", license.AllowedProfiles(guard.Tier()))
	fmt.Printf("Allowed formats:  %v\n", license.AllowedFormats(guard.Tier()))

	mods := license.AllowedModules(guard.Tier())
	if mods == nil {
		fmt.Printf("Allowed modules:  all\n")
	} else {
		fmt.Printf("Allowed modules:  %v\n", mods)
	}

	return nil
}

func runLicenseVerify(_ *cobra.Command, args []string) error {
	// Create a new guard from the provided token to verify it
	g := license.NewGuard(args[0])

	fmt.Printf("Tier: %s\n", g.Tier())
	fmt.Printf("Seats: %d\n", g.Seats())

	if lic := g.License(); lic != nil {
		fmt.Printf("Licence ID:   %s\n", lic.ID)
		fmt.Printf("Organisation: %s\n", lic.Org)
		fmt.Printf("Issued:       %s\n", time.Unix(lic.IssuedAt, 0).UTC().Format(time.RFC3339))
		fmt.Printf("Expires:      %s\n", time.Unix(lic.ExpiresAt, 0).UTC().Format(time.RFC3339))
		fmt.Println("\nLicence is valid.")
	} else {
		fmt.Println("\nLicence validation failed — displaying free tier defaults.")
	}

	return nil
}
