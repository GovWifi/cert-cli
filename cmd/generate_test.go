package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certcli/pki"
)

func TestGenerateCommandRegistered(t *testing.T) {
	found := false
	for _, command := range rootCmd.Commands() {
		if command.Name() == "generate" {
			found = true
			if !command.HasAlias("gen") {
				t.Fatal("generate is missing gen alias")
			}
		}
	}
	if !found {
		t.Fatal("generate is not registered")
	}
	for _, name := range []string{
		"leaves",
		"organization",
		"root-cn",
		"intermediate-cn",
		"root-start",
		"root-expiry",
		"intermediate-start",
		"intermediate-expiry",
		"leaf-start",
		"leaf-expiry",
		"save",
		"out",
		"prefix",
	} {
		if generateCmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing --%s", name)
		}
	}
}

func TestRunGenerateRejectsLeafCount(t *testing.T) {
	err := runGenerate(generateOptions{Leaves: 0})
	if err == nil || !strings.Contains(err.Error(), "at least 1") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunGenerateRejectsPrefix(t *testing.T) {
	err := runGenerate(generateOptions{Leaves: 1, Prefix: "bad/prefix"})
	if err == nil || !strings.Contains(err.Error(), "path separators") {
		t.Fatalf("err = %v", err)
	}
}

func TestSaveChainWritesCertsAndKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 10, 1, 23, 59, 59, 0, time.UTC)
	certPEM, err := pki.CreateSelfSignedCertificate(key, "saved", nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	material, err := materialFrom(key, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	chain := &pki.Chain{
		Root:         material,
		Intermediate: material,
		Leaves:       []*pki.CADetails{material, material},
	}

	dir := t.TempDir()
	if err := saveChain(chain, dir, "valid_"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"valid_rootcert.pem",
		"valid_root.key",
		"valid_root.pub",
		"valid_intermediate.pem",
		"valid_intermediate.key",
		"valid_intermediate.pub",
		"valid_leaf-1.pem",
		"valid_leaf-1.key",
		"valid_leaf-1.pub",
		"valid_leaf-2.pem",
		"valid_leaf-2.key",
		"valid_leaf-2.pub",
	}
	for _, name := range want {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
	}

	loaded, err := pki.LoadRSAPrivateKey(filepath.Join(dir, "valid_leaf-2.key"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("saved leaf private key does not match")
	}
	pub, err := os.ReadFile(filepath.Join(dir, "valid_leaf-2.pub"))
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := pki.RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(wantPub) {
		t.Fatal("saved leaf public key does not match")
	}
}

func materialFrom(key *rsa.PrivateKey, certPEM []byte) (*pki.CADetails, error) {
	cert, err := pki.PemToCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	pub, err := pki.RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &pki.CADetails{
		Key:           key,
		Cert:          cert,
		PrivateKeyPEM: pki.RSAPrivateKey2Pem(key),
		PublicKeyPEM:  pub,
		CertPEM:       certPEM,
	}, nil
}
