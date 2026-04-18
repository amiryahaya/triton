package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// networkScanAliasCmd is a deprecation shim that forwards to device-scan.
// Existing scripts/systemd-units that run `triton network-scan` continue
// to work for one release cycle with a stderr warning.
var networkScanAliasCmd = &cobra.Command{
	Use:        "network-scan",
	Short:      "DEPRECATED: use 'triton device-scan' instead",
	Deprecated: "use 'triton device-scan' instead",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr,
			"warning: 'triton network-scan' is deprecated; use 'triton device-scan' instead")
		if deviceScanCmd.PreRunE != nil {
			return deviceScanCmd.PreRunE(cmd, args)
		}
		return nil
	},
	RunE: runDeviceScan,
}

func init() {
	// Mirror every flag on deviceScanCmd so the alias is functionally
	// identical. The flag variables are package-level so state is
	// shared between deviceScanCmd and networkScanAliasCmd.
	networkScanAliasCmd.Flags().AddFlagSet(deviceScanCmd.Flags())
	rootCmd.AddCommand(networkScanAliasCmd)
}
