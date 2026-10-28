package cmd

import (
	"fmt"

	"certcli/pki"

	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate [certificate]",
	Short: "Check that a certificate is signed by the given root CA",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCertPath, err := cmd.Flags().GetString("root")
		if err != nil {
			return err
		}

		if err := pki.ValidateSignedBy(args[0], rootCertPath); err != nil {
			return fmt.Errorf("certificate is not signed by %s: %w", rootCertPath, err)
		}

		fmt.Printf("%s is signed by %s\n", args[0], rootCertPath)
		return nil
	},
}

func init() {
	validateCmd.Flags().String("root", "", "path to the root CA certificate")
	if err := validateCmd.MarkFlagRequired("root"); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(validateCmd)
}
