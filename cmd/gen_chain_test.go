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

func TestGenChainCommandRegistered(t *testing.T) {
	found := false
	for _, command := range genCmd.Commands() {
		if command.Name() == "chain" {
			found = true
		}
	}
	if !found {
		t.Fatal("gen chain is not registered")
	}
	for _, name := range []string{"leaves", "save", "out"} {
		if genChainCmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing --%s", name)
		}
	}
}

func TestRunGenChainRejectsLeafCount(t *testing.T) {
	err := runGenChain(0, false, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "at least 1") {
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
	if err := saveChain(chain, dir); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"rootcert.pem",
		"root-key.pem",
		"root-key.pub",
		"intermediate.pem",
		"intermediate-key.pem",
		"intermediate-key.pub",
		"leaf-1.pem",
		"leaf-1-key.pem",
		"leaf-1-key.pub",
		"leaf-2.pem",
		"leaf-2-key.pem",
		"leaf-2-key.pub",
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

	loaded, err := pki.LoadRSAPrivateKey(filepath.Join(dir, "leaf-2-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("saved leaf private key does not match")
	}
	pub, err := os.ReadFile(filepath.Join(dir, "leaf-2-key.pub"))
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
