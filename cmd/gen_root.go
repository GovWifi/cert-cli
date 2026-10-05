package cmd

import (
	"certcli/pki"
	"time"

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

		if _, err := generateRoot(keyPath, certPath, notBefore, notAfter); err != nil {
			return err
		}

		writeGeneratedFiles(keyPath, certPath)
		return nil
	},
}

func init() {
	genRootCmd.Flags().String("cert", defaultRootCert, "output path for the root certificate")
	genRootCmd.Flags().String("key", defaultRootKey, "output path for the root private key")
	genRootCmd.Flags().String("start", time.Now().Format(pki.DateLayout), "certificate start date (YYYY-MM-DD); defaults to today. If start date is bigger than expiry date, the certificate is invalid")
	genRootCmd.Flags().String("expiry", pki.RootExpiry.Format(pki.DateLayout), "certificate expiry date (YYYY-MM-DD); defaults to 10 years from today. A past date generates an expired certificate")
}
