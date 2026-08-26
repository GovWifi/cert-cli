package cmd

import (
	"github.com/spf13/cobra"
)

var genRootCmd = &cobra.Command{
	Use:   "root",
	Short: "Generate a root CA key pair and self-signed certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, err := cmd.Flags().GetString("cert")
		if err != nil {
			return err
		}
		keyPath, err := cmd.Flags().GetString("key")
		if err != nil {
			return err
		}

		if _, err := generateRoot(keyPath, certPath); err != nil {
			return err
		}

		writeGeneratedFiles(keyPath, certPath)
		return nil
	},
}

func init() {
	genRootCmd.Flags().String("cert", defaultRootCert, "output path for the root certificate")
	genRootCmd.Flags().String("key", defaultRootKey, "output path for the root private key")
}
