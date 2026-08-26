package cmd

import (
	"github.com/spf13/cobra"
)

const (
	defaultRootCert  = "rootcert.pem"
	defaultRootKey   = "root-key.pem"
	defaultInterCert = "intermediate.pem"
	defaultInterKey  = "intermediate-key.pem"
)

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate CA keys and certificates",
}

func init() {
	genCmd.AddCommand(genAllCmd)
	genCmd.AddCommand(genRootCmd)
	genCmd.AddCommand(genInterCmd)
}
