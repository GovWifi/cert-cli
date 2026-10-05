package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSignedBy(t *testing.T) {
	dir := t.TempDir()

	rootKey := testRSAKey(t)
	rootPEM, err := CreateSelfSignedCertificate(rootKey, "test-root", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}

	otherRootKey := testRSAKey(t)
	otherRootPEM, err := CreateSelfSignedCertificate(otherRootKey, "other-root", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}

	interKey := testRSAKey(t)
	rootCert, err := PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	interPEM, err := CreateIntermediateCertificate(rootCert, rootKey, interKey, "test-inter", testNotBefore, testNotAfter)
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
	if err := ValidateSignedByPEM(interPEM, rootPEM); err != nil {
		t.Fatalf("expected PEM validation to succeed: %v", err)
	}

	interCert, err := PemToCertificate(interPEM)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := PemToCertificate(otherRootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSignedBy(interCert, rootCert); err != nil {
		t.Fatal(err)
	}
	if err := CheckSignedBy(interCert, otherRoot); err == nil {
		t.Fatal("expected signature check against a different root to fail")
	}

	if err := ValidateSignedBy(interPath, otherRootPath); err == nil {
		t.Fatal("expected validation against a different root to fail")
	}
	if err := ValidateSignedByPEM(interPEM, otherRootPEM); err == nil {
		t.Fatal("expected PEM validation against a different root to fail")
	}
}

func TestValidateSignedByMissingFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	present := filepath.Join(dir, "present.pem")
	mustWrite(t, present, []byte("not a certificate"))

	if err := ValidateSignedBy(missing, present); err == nil {
		t.Fatal("expected error for missing certificate")
	}
	if err := ValidateSignedBy(present, missing); err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestValidateSignedByRejectsInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	issuerPath := filepath.Join(dir, "issuer.pem")
	mustWrite(t, certPath, []byte("nope"))
	mustWrite(t, issuerPath, []byte("nope"))

	if err := ValidateSignedBy(certPath, issuerPath); err == nil {
		t.Fatal("expected error for invalid certificate PEM")
	}
	if err := ValidateSignedByPEM([]byte("nope"), []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")); err == nil {
		t.Fatal("expected error for invalid certificate PEM")
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
