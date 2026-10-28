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

const (
	defaultRootCert  = "rootcert.pem"
	defaultRootKey   = "root.key"
	defaultInterCert = "intermediate.pem"
	defaultInterKey  = "intermediate.key"
)

var generateCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"gen"},
	Short:   "Generate a root CA, intermediate CA, and leaf certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		leaves, err := cmd.Flags().GetInt("leaves")
		if err != nil {
			return err
		}
		organization, err := cmd.Flags().GetString("organization")
		if err != nil {
			return err
		}
		rootCN, err := cmd.Flags().GetString("root-cn")
		if err != nil {
			return err
		}
		intermediateCN, err := cmd.Flags().GetString("intermediate-cn")
		if err != nil {
			return err
		}
		rootStart, err := cmd.Flags().GetString("root-start")
		if err != nil {
			return err
		}
		rootExpiry, err := cmd.Flags().GetString("root-expiry")
		if err != nil {
			return err
		}
		intermediateStart, err := cmd.Flags().GetString("intermediate-start")
		if err != nil {
			return err
		}
		intermediateExpiry, err := cmd.Flags().GetString("intermediate-expiry")
		if err != nil {
			return err
		}
		leafStart, err := cmd.Flags().GetString("leaf-start")
		if err != nil {
			return err
		}
		leafExpiry, err := cmd.Flags().GetString("leaf-expiry")
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
		prefix, err := cmd.Flags().GetString("prefix")
		if err != nil {
			return err
		}
		return runGenerate(generateOptions{
			Leaves:             leaves,
			Organization:       organization,
			RootCN:             rootCN,
			IntermediateCN:     intermediateCN,
			RootStart:          rootStart,
			RootExpiry:         rootExpiry,
			IntermediateStart:  intermediateStart,
			IntermediateExpiry: intermediateExpiry,
			LeafStart:          leafStart,
			LeafExpiry:         leafExpiry,
			Save:               save,
			OutDir:             outDir,
			Prefix:             prefix,
		})
	},
}

type generateOptions struct {
	Leaves             int
	Organization       string
	RootCN             string
	IntermediateCN     string
	RootStart          string
	RootExpiry         string
	IntermediateStart  string
	IntermediateExpiry string
	LeafStart          string
	LeafExpiry         string
	Save               bool
	OutDir             string
	Prefix             string
}

func init() {
	generateCmd.Flags().Int("leaves", 1, "number of leaf certificates to sign with the intermediate (1-100)")
	generateCmd.Flags().String("organization", "GovWifi", "organization name for every certificate subject")
	generateCmd.Flags().String("root-cn", pki.RootCN, "root CA common name")
	generateCmd.Flags().String("intermediate-cn", pki.IntermediateCN, "intermediate CA common name")
	generateCmd.Flags().String("root-start", "", "root start date (YYYY-MM-DD); defaults to today")
	generateCmd.Flags().String("root-expiry", "", "root expiry date (YYYY-MM-DD); defaults to 10 years from today")
	generateCmd.Flags().String("intermediate-start", "", "intermediate start date (YYYY-MM-DD); defaults to today")
	generateCmd.Flags().String("intermediate-expiry", "", "intermediate expiry date (YYYY-MM-DD); defaults to 5 years from today")
	generateCmd.Flags().String("leaf-start", "", "leaf start date (YYYY-MM-DD); defaults to today")
	generateCmd.Flags().String("leaf-expiry", "", "leaf expiry date (YYYY-MM-DD); defaults to 1 year from today")
	generateCmd.Flags().Bool("save", false, "write every certificate, private key, and public key to files")
	generateCmd.Flags().String("out", "test", "directory for --save")
	generateCmd.Flags().String("prefix", "", "optional prefix prepended to every saved file name")
	rootCmd.AddCommand(generateCmd)
}

func runGenerate(opts generateOptions) error {
	if err := validateNamePrefix(opts.Prefix); err != nil {
		return err
	}

	now := time.Now()
	rootStart, err := pki.ResolveStartDate(opts.RootStart, now)
	if err != nil {
		return fmt.Errorf("root start: %w", err)
	}
	rootExpiry, err := pki.ResolveExpiryDate(opts.RootExpiry, now)
	if err != nil {
		return fmt.Errorf("root expiry: %w", err)
	}
	interStart, err := pki.ResolveStartDate(opts.IntermediateStart, now)
	if err != nil {
		return fmt.Errorf("intermediate start: %w", err)
	}
	interExpiry, err := pki.ResolveExpiryInYears(opts.IntermediateExpiry, now, 5)
	if err != nil {
		return fmt.Errorf("intermediate expiry: %w", err)
	}
	leafStart, err := pki.ResolveStartDate(opts.LeafStart, now)
	if err != nil {
		return fmt.Errorf("leaf start: %w", err)
	}
	leafExpiry, err := pki.ResolveExpiryInYears(opts.LeafExpiry, now, 1)
	if err != nil {
		return fmt.Errorf("leaf expiry: %w", err)
	}

	chain, err := pki.CreateCustomChain(pki.ChainOptions{
		Organization:   opts.Organization,
		RootCN:         opts.RootCN,
		IntermediateCN: opts.IntermediateCN,
		LeafCount:      opts.Leaves,
		RootNotBefore:  rootStart,
		RootNotAfter:   rootExpiry,
		InterNotBefore: interStart,
		InterNotAfter:  interExpiry,
		LeafNotBefore:  leafStart,
		LeafNotAfter:   leafExpiry,
	})
	if err != nil {
		return err
	}

	if !opts.Save {
		fmt.Printf("generated root, intermediate, and %s\n", leafCountPhrase(opts.Leaves))
		fmt.Println("certificates were not written; pass --save to write certificates and keys to files")
		printChain(chain)
		return nil
	}

	if err := saveChain(chain, opts.OutDir, opts.Prefix); err != nil {
		return err
	}
	fmt.Printf("generated root, intermediate, and %s\n", leafCountPhrase(opts.Leaves))
	return nil
}

func validateNamePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if strings.Contains(prefix, "/") || strings.Contains(prefix, `\`) || strings.Contains(prefix, "..") {
		return fmt.Errorf("prefix must not contain path separators")
	}
	return nil
}

func saveChain(chain *pki.Chain, outDir, prefix string) error {
	outDir = strings.TrimSpace(outDir)
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	if err := writeMaterial(chain.Root, filepath.Join(outDir, prefix+defaultRootKey), filepath.Join(outDir, prefix+defaultRootCert)); err != nil {
		return err
	}
	if err := writeMaterial(chain.Intermediate, filepath.Join(outDir, prefix+defaultInterKey), filepath.Join(outDir, prefix+defaultInterCert)); err != nil {
		return err
	}
	for i, leaf := range chain.Leaves {
		n := i + 1
		keyPath := filepath.Join(outDir, fmt.Sprintf("%sleaf-%d.key", prefix, n))
		certPath := filepath.Join(outDir, fmt.Sprintf("%sleaf-%d.pem", prefix, n))
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

func writeGeneratedFiles(keyPath, certPath string) {
	fmt.Printf("wrote %s, %s, and %s\n", keyPath, publicKeyPath(keyPath), certPath)
}

func publicKeyPath(privateKeyPath string) string {
	ext := filepath.Ext(privateKeyPath)
	return strings.TrimSuffix(privateKeyPath, ext) + ".pub"
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
