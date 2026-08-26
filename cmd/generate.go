package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"certcli/pki"
)

func publicKeyPath(privateKeyPath string) string {
	ext := filepath.Ext(privateKeyPath)
	return strings.TrimSuffix(privateKeyPath, ext) + ".pub"
}

func generateRoot(keyPath, certPath string) (*pki.CADetails, error) {
	material, err := pki.CreateRootCA()
	if err != nil {
		return nil, err
	}
	if err := pki.SaveCADetails(material, keyPath, certPath); err != nil {
		return nil, err
	}
	return material, nil
}

func generateIntermediate(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, keyPath, certPath string) error {
	material, err := pki.CreateIntermediateCA(rootCert, rootKey)
	if err != nil {
		return err
	}
	return pki.SaveCADetails(material, keyPath, certPath)
}

func writeGeneratedFiles(keyPath, certPath string) {
	fmt.Printf("wrote %s, %s, and %s\n", keyPath, publicKeyPath(keyPath), certPath)
}
