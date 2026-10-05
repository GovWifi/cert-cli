package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"certcli/pki"

	"github.com/spf13/cobra"
)

var genChainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Generate a root CA, an intermediate CA, and leaf certificates signed by the intermediate",
	RunE: func(cmd *cobra.Command, args []string) error {
		leaves, err := cmd.Flags().GetInt("leaves")
		if err != nil {
			return err
		}
		save, err := cmd.Flags().GetBool("save")
		if err != nil {
			return err
		}
		outDir, err := cmd.Flags().GetString("out")
		if err != nil {
			return err
		}
		return runGenChain(leaves, save, outDir)
	},
}

func init() {
	genChainCmd.Flags().Int("leaves", 0, "number of leaf certificates to sign with the intermediate (required, 1-100)")
	genChainCmd.Flags().Bool("save", false, "write every certificate, private key, and public key to files")
	genChainCmd.Flags().String("out", ".", "directory for --save")
	if err := genChainCmd.MarkFlagRequired("leaves"); err != nil {
		panic(err)
	}
}

func runGenChain(leaves int, save bool, outDir string) error {
	chain, err := pki.CreateChain(leaves, time.Now())
	if err != nil {
		return err
	}

	if !save {
		fmt.Printf("generated root, intermediate, and %s\n", leafCountPhrase(leaves))
		fmt.Println("certificates were not written; pass --save to write certificates and keys to files")
		printChain(chain)
		return nil
	}

	if err := saveChain(chain, outDir); err != nil {
		return err
	}
	fmt.Printf("generated root, intermediate, and %s\n", leafCountPhrase(leaves))
	return nil
}

func saveChain(chain *pki.Chain, outDir string) error {
	outDir = strings.TrimSpace(outDir)
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	if err := writeMaterial(chain.Root, filepath.Join(outDir, defaultRootKey), filepath.Join(outDir, defaultRootCert)); err != nil {
		return err
	}
	if err := writeMaterial(chain.Intermediate, filepath.Join(outDir, defaultInterKey), filepath.Join(outDir, defaultInterCert)); err != nil {
		return err
	}
	for i, leaf := range chain.Leaves {
		n := i + 1
		keyPath := filepath.Join(outDir, fmt.Sprintf("leaf-%d-key.pem", n))
		certPath := filepath.Join(outDir, fmt.Sprintf("leaf-%d.pem", n))
		if err := writeMaterial(leaf, keyPath, certPath); err != nil {
			return err
		}
	}
	return nil
}

func writeMaterial(material *pki.CADetails, keyPath, certPath string) error {
	if err := pki.SaveCADetails(material, keyPath, certPath); err != nil {
		return err
	}
	writeGeneratedFiles(keyPath, certPath)
	return nil
}

func printChain(chain *pki.Chain) {
	printMaterial("root", chain.Root)
	printMaterial("intermediate", chain.Intermediate)
	for i, leaf := range chain.Leaves {
		printMaterial(fmt.Sprintf("leaf %d", i+1), leaf)
	}
}

func printMaterial(label string, material *pki.CADetails) {
	fmt.Printf("# %s certificate\n%s\n", label, material.CertPEM)
	fmt.Printf("# %s private key\n%s\n", label, material.PrivateKeyPEM)
	fmt.Printf("# %s public key\n%s\n", label, material.PublicKeyPEM)
}

func leafCountPhrase(n int) string {
	if n == 1 {
		return "1 leaf certificate"
	}
	return fmt.Sprintf("%d leaf certificates", n)
}
