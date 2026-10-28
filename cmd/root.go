package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "cert-cli",
	Short:         "Generate, validate, and view GovWifi CA certificates",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the cert-cli command and exits the process on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
