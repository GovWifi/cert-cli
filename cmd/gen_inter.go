package cmd

import (
	"certcli/pki"

	"github.com/spf13/cobra"
)

var genInterCmd = &cobra.Command{
	Use:   "inter",
	Short: "Generate an intermediate CA key pair and certificate signed by a root CA",
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCertPath, err := cmd.Flags().GetString("root")
		if err != nil {
			return err
		}
		rootKeyPath, err := cmd.Flags().GetString("root-key")
		if err != nil {
			return err
		}
		certPath, err := cmd.Flags().GetString("cert")
		if err != nil {
			return err
		}
		keyPath, err := cmd.Flags().GetString("key")
		if err != nil {
			return err
		}

		rootCert, err := pki.LoadCertificate(rootCertPath)
		if err != nil {
			return err
		}
		rootKey, err := pki.LoadRSAPrivateKey(rootKeyPath)
		if err != nil {
			return err
		}

		if err := generateIntermediate(rootCert, rootKey, keyPath, certPath); err != nil {
			return err
		}

		writeGeneratedFiles(keyPath, certPath)
		return nil
	},
}

func init() {
	genInterCmd.Flags().String("root", "", "path to the root CA certificate")
	genInterCmd.Flags().String("root-key", defaultRootKey, "path to the root CA private key")
	genInterCmd.Flags().String("cert", defaultInterCert, "output path for the intermediate certificate")
	genInterCmd.Flags().String("key", defaultInterKey, "output path for the intermediate private key")
	if err := genInterCmd.MarkFlagRequired("root"); err != nil {
		panic(err)
	}
}
