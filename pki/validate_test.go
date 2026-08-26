package pki

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const defaultTestValidFor = 24 * time.Hour

func TestValidateSignedBy(t *testing.T) {
	dir := t.TempDir()

	rootKey, err := GenerateRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := CreateSelfSignedCertificate(rootKey, "test-root", nil, defaultTestValidFor)
	if err != nil {
		t.Fatal(err)
	}

	otherRootKey, err := GenerateRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherRootPEM, err := CreateSelfSignedCertificate(otherRootKey, "other-root", nil, defaultTestValidFor)
	if err != nil {
		t.Fatal(err)
	}

	interKey, err := GenerateRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	interPEM, err := CreateIntermediateCertificate(rootCert, rootKey, interKey, "test-inter", defaultTestValidFor)
	if err != nil {
		t.Fatal(err)
	}

	rootPath := filepath.Join(dir, "rootcert.pem")
	otherRootPath := filepath.Join(dir, "other-root.pem")
	interPath := filepath.Join(dir, "intermediate.pem")
	mustWrite(t, rootPath, rootPEM)
	mustWrite(t, otherRootPath, otherRootPEM)
	mustWrite(t, interPath, interPEM)

	if err := ValidateSignedBy(interPath, rootPath); err != nil {
		t.Fatalf("expected intermediate to be signed by root: %v", err)
	}

	if err := ValidateSignedBy(interPath, otherRootPath); err == nil {
		t.Fatal("expected validation against a different root to fail")
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
