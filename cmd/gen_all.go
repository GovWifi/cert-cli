package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var genAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Generate a root CA and an intermediate CA signed by that root",
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCertPath, err := cmd.Flags().GetString("root-cert")
		if err != nil {
			return err
		}
		rootKeyPath, err := cmd.Flags().GetString("root-key")
		if err != nil {
			return err
		}
		interCertPath, err := cmd.Flags().GetString("inter-cert")
		if err != nil {
			return err
		}
		interKeyPath, err := cmd.Flags().GetString("inter-key")
		if err != nil {
			return err
		}

		root, err := generateRoot(rootKeyPath, rootCertPath)
		if err != nil {
			return err
		}

		if err := generateIntermediate(root.Cert, root.Key, interKeyPath, interCertPath); err != nil {
			return err
		}

		writeGeneratedFiles(rootKeyPath, rootCertPath)
		writeGeneratedFiles(interKeyPath, interCertPath)
		fmt.Println("generated root and intermediate CA")
		return nil
	},
}

func init() {
	genAllCmd.Flags().String("root-cert", defaultRootCert, "output path for the root certificate")
	genAllCmd.Flags().String("root-key", defaultRootKey, "output path for the root private key")
	genAllCmd.Flags().String("inter-cert", defaultInterCert, "output path for the intermediate certificate")
	genAllCmd.Flags().String("inter-key", defaultInterKey, "output path for the intermediate private key")
}
