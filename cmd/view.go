package cmd

import (
	"fmt"

	"certcli/pki"

	"github.com/spf13/cobra"
)

var viewCmd = &cobra.Command{
	Use:   "view [certificate]",
	Short: "Decode a PEM certificate into OpenSSL-style details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cert, err := pki.LoadCertificate(args[0])
		if err != nil {
			return fmt.Errorf("invalid certificate: %w", err)
		}
		fmt.Print(pki.CertificateText(cert))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(viewCmd)
}
