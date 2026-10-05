package cmd

import (
	"certcli/pki"
	"time"

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

		keyStart, err := cmd.Flags().GetString("start")
		if err != nil {
			return err
		}
		notBefore, err := pki.ResolveExpiryDate(keyStart, time.Now())
		if err != nil {
			return err
		}

		keyExpiry, err := cmd.Flags().GetString("expiry")
		if err != nil {
			return err
		}
		notAfter, err := pki.ResolveExpiryDate(keyExpiry, notBefore)
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

		if err := generateIntermediate(rootCert, rootKey, keyPath, certPath, notBefore, notAfter); err != nil {
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
	genInterCmd.Flags().String("start", time.Now().Format(pki.DateLayout), "certificate start date (YYYY-MM-DD); defaults to today. If start date is bigger than expiry date, the certificate is invalid")
	genInterCmd.Flags().String("expiry", pki.IntermediateExpiry.Format(pki.DateLayout), "certificate expiry date (YYYY-MM-DD); defaults to 10 years from today. A past date generates an expired certificate")
	if err := genInterCmd.MarkFlagRequired("root"); err != nil {
		panic(err)
	}
}
