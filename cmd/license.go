package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

var licenseActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Activate this machine with the license server",
	Long:  `Registers this machine with the license server, consuming one seat. Requires --license-server and --license-id flags.`,
	RunE:  runLicenseActivate,
}

var licenseDeactivateCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate this machine from the license server",
	Long:  `Unregisters this machine from the license server, freeing a seat.`,
	RunE:  runLicenseDeactivate,
}

func init() {
	licenseCmd.AddCommand(licenseShowCmd)
	licenseCmd.AddCommand(licenseVerifyCmd)
	licenseCmd.AddCommand(licenseActivateCmd)
	licenseCmd.AddCommand(licenseDeactivateCmd)
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

	// Show server metadata if available
	metaPath := license.DefaultCacheMetaPath()
	if meta, err := license.LoadCacheMeta(metaPath); err == nil {
		fmt.Printf("\nLicense Server:   %s\n", meta.ServerURL)
		fmt.Printf("Server Tier:      %s\n", meta.Tier)
		fmt.Printf("Seats:            %d/%d used\n", meta.SeatsUsed, meta.Seats)
		fmt.Printf("Last Validated:   %s\n", meta.LastValidated.Format(time.RFC3339))
		if meta.IsFresh() {
			fmt.Printf("Cache Status:     fresh\n")
		} else {
			fmt.Printf("Cache Status:     stale (>%d days)\n", license.GracePeriodDays)
		}
	}

	return nil
}

func runLicenseVerify(_ *cobra.Command, args []string) error {
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

func runLicenseActivate(_ *cobra.Command, _ []string) error {
	if licenseServerURL == "" {
		return fmt.Errorf("--license-server is required for activation")
	}
	if licenseID == "" {
		return fmt.Errorf("--license-id is required for activation")
	}

	// Normalize server URL
	serverURL := strings.TrimRight(licenseServerURL, "/")

	client := license.NewServerClient(serverURL)

	fmt.Printf("Activating machine with license server at %s...\n", serverURL)
	fmt.Printf("Machine fingerprint: %s\n", license.MachineFingerprint())

	resp, err := client.Activate(licenseID, license.ActivationTypeAgent, "")
	if err != nil {
		return fmt.Errorf("activation failed: %w", err)
	}

	// Save token to ~/.triton/license.key
	tokenPath := license.DefaultLicensePath()
	dir := filepath.Dir(tokenPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	if err := os.WriteFile(tokenPath, []byte(resp.Token), 0o600); err != nil {
		return fmt.Errorf("writing token: %w", err)
	}

	// Save metadata
	meta := &license.CacheMeta{
		ServerURL:     serverURL,
		LicenseID:     licenseID,
		Tier:          resp.Tier,
		Seats:         resp.Seats,
		SeatsUsed:     resp.SeatsUsed,
		ExpiresAt:     resp.ExpiresAt,
		LastValidated: time.Now().UTC(),
	}
	metaPath := license.DefaultCacheMetaPath()
	if err := meta.Save(metaPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save cache metadata: %v\n", err)
	}

	fmt.Printf("\nActivation successful!\n")
	fmt.Printf("  Tier:       %s\n", resp.Tier)
	fmt.Printf("  Seats:      %d/%d used\n", resp.SeatsUsed, resp.Seats)
	fmt.Printf("  Expires:    %s\n", resp.ExpiresAt)
	fmt.Printf("  Token:      %s\n", tokenPath)

	return nil
}

func runLicenseDeactivate(_ *cobra.Command, _ []string) error {
	// Try to load metadata for server URL and license ID
	serverURL := licenseServerURL
	lid := licenseID

	metaPath := license.DefaultCacheMetaPath()
	if meta, err := license.LoadCacheMeta(metaPath); err == nil {
		if serverURL == "" {
			serverURL = meta.ServerURL
		}
		if lid == "" {
			lid = meta.LicenseID
		}
	}

	// Read the stored activation token from the license key file so the
	// server can verify the caller is the machine that originally activated.
	var activationToken string
	if data, err := os.ReadFile(license.DefaultLicensePath()); err == nil {
		activationToken = strings.TrimSpace(string(data))
	}

	if serverURL == "" {
		return fmt.Errorf("--license-server is required (or cached from activation)")
	}
	if lid == "" {
		return fmt.Errorf("--license-id is required (or cached from activation)")
	}

	serverURL = strings.TrimRight(serverURL, "/")
	client := license.NewServerClient(serverURL)

	fmt.Printf("Deactivating machine from license server at %s...\n", serverURL)

	if err := client.Deactivate(lid, activationToken); err != nil {
		return fmt.Errorf("deactivation failed: %w (you can retry later)", err)
	}

	// Remove local files
	tokenPath := license.DefaultLicensePath()
	_ = os.Remove(tokenPath)
	license.RemoveCacheMeta(metaPath)

	fmt.Println("Deactivation successful. Seat freed.")
	return nil
}
