package pki

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateSelfSignedCertificate(t *testing.T) {
	key := testRSAKey(t)
	dnsNames := []string{"wifi.example"}
	certPEM, err := CreateSelfSignedCertificate(key, "test-root", dnsNames, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := PemToCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	assertCACert(t, cert, "test-root", 1)
	if !cert.NotBefore.Equal(testNotBefore) || !cert.NotAfter.Equal(testNotAfter) {
		t.Fatalf("validity %s – %s, want %s – %s", cert.NotBefore, cert.NotAfter, testNotBefore, testNotAfter)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "wifi.example" {
		t.Fatalf("DNSNames = %v", cert.DNSNames)
	}
	if err := CheckSignedBy(cert, cert); err != nil {
		t.Fatal(err)
	}
}

func TestCreateSelfSignedCertificateAllowsInvertedWindow(t *testing.T) {
	key := testRSAKey(t)
	certPEM, err := CreateSelfSignedCertificate(key, "inverted", nil, testNotAfter, testNotBefore)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := PemToCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotBefore.Equal(testNotAfter) || !cert.NotAfter.Equal(testNotBefore) {
		t.Fatalf("validity %s – %s", cert.NotBefore, cert.NotAfter)
	}
}

func TestCreateIntermediateCertificate(t *testing.T) {
	rootKey := testRSAKey(t)
	rootPEM, err := CreateSelfSignedCertificate(rootKey, "root", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}

	interKey := testRSAKey(t)
	interPEM, err := CreateIntermediateCertificate(rootCert, rootKey, interKey, "inter", testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := PemToCertificate(interPEM)
	if err != nil {
		t.Fatal(err)
	}
	assertCACert(t, interCert, "inter", 0)
	if err := CheckSignedBy(interCert, rootCert); err != nil {
		t.Fatal(err)
	}
	if interCert.Issuer.CommonName != "root" {
		t.Fatalf("issuer CN = %q", interCert.Issuer.CommonName)
	}
}

func TestCreateIntermediateCertificateRejectsMismatchedRootKey(t *testing.T) {
	rootKey := testRSAKey(t)
	rootPEM, err := CreateSelfSignedCertificate(rootKey, "root", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CreateIntermediateCertificate(rootCert, testRSAKey(t), testRSAKey(t), "inter", testNotBefore, testNotAfter)
	if err == nil {
		t.Fatal("expected error when the root key does not match the root certificate")
	}
}

func TestCreateRootCA(t *testing.T) {
	material, err := CreateRootCA(testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	if material.Key == nil || material.Cert == nil {
		t.Fatal("expected key and certificate")
	}
	if material.Key.N.BitLen() != 4096 {
		t.Fatalf("key size = %d, want 4096", material.Key.N.BitLen())
	}
	assertCACert(t, material.Cert, RootCN, 1)
	if err := CheckSignedBy(material.Cert, material.Cert); err != nil {
		t.Fatal(err)
	}

	parsedKey, err := PemToRSAPrivateKey(material.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if parsedKey.N.Cmp(material.Key.N) != 0 {
		t.Fatal("private key PEM does not match the generated key")
	}
	wantPub, err := RSAPublicKey2Pem(&material.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(material.PublicKeyPEM, wantPub) {
		t.Fatal("public key PEM does not match the generated key")
	}
	parsedCert, err := PemToCertificate(material.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if parsedCert.Subject.CommonName != RootCN {
		t.Fatalf("CN = %q", parsedCert.Subject.CommonName)
	}
}

func TestCreateIntermediateCA(t *testing.T) {
	rootKey := testRSAKey(t)
	rootPEM, err := CreateSelfSignedCertificate(rootKey, "root", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}

	material, err := CreateIntermediateCA(rootCert, rootKey, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	assertCACert(t, material.Cert, IntermediateCN, 0)
	if material.Key.N.BitLen() != 4096 {
		t.Fatalf("key size = %d, want 4096", material.Key.N.BitLen())
	}
	if err := CheckSignedBy(material.Cert, rootCert); err != nil {
		t.Fatal(err)
	}
}

func TestPemToCertificateRejectsInvalidPEM(t *testing.T) {
	if _, err := PemToCertificate(nil); err == nil {
		t.Fatal("expected error for empty input")
	}
	if _, err := PemToCertificate([]byte("not a pem")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}

	keyPEM := RSAPrivateKey2Pem(testRSAKey(t))
	if _, err := PemToCertificate(keyPEM); err == nil {
		t.Fatal("expected error when the PEM is a private key")
	}
}

func TestLoadCertificate(t *testing.T) {
	key := testRSAKey(t)
	certPEM, err := CreateSelfSignedCertificate(key, "loaded", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := SaveCertificate(certPEM, path); err != nil {
		t.Fatal(err)
	}

	cert, err := LoadCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "loaded" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}

	if _, err := LoadCertificate(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for a missing file")
	}
	bad := filepath.Join(dir, "bad.pem")
	mustWrite(t, bad, []byte("nope"))
	if _, err := LoadCertificate(bad); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestSaveCertificate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := SaveCertificate([]byte("first"), path); err != nil {
		t.Fatal(err)
	}
	if err := SaveCertificate([]byte("second"), path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("second")) {
		t.Fatalf("got %q", got)
	}

	if err := SaveCertificate([]byte("pem"), dir); err == nil {
		t.Fatal("expected error when the path is a directory")
	}
}

func TestSaveCADetails(t *testing.T) {
	key := testRSAKey(t)
	certPEM, err := CreateSelfSignedCertificate(key, "saved", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	material := &CADetails{Key: key, CertPEM: certPEM}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca-key.pem")
	certPath := filepath.Join(dir, "ca.pem")
	if err := SaveCADetails(material, keyPath, certPath); err != nil {
		t.Fatal(err)
	}

	loadedKey, err := LoadRSAPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedKey.N.Cmp(key.N) != 0 {
		t.Fatal("saved private key does not match")
	}
	pub, err := os.ReadFile(filepath.Join(dir, "ca-key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, wantPub) {
		t.Fatal("saved public key does not match")
	}
	cert, err := LoadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "saved" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
}

func TestSaveCADetailsMissingCertDirectory(t *testing.T) {
	key := testRSAKey(t)
	certPEM, err := CreateSelfSignedCertificate(key, "saved", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	err = SaveCADetails(&CADetails{Key: key, CertPEM: certPEM}, filepath.Join(dir, "ca-key.pem"), filepath.Join(dir, "missing", "ca.pem"))
	if err == nil {
		t.Fatal("expected error when the certificate directory is missing")
	}
}

func assertCACert(t *testing.T, cert *x509.Certificate, cn string, pathLen int) {
	t.Helper()
	if cert.Subject.CommonName != cn {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, cn)
	}
	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "GB" {
		t.Fatalf("country = %v", cert.Subject.Country)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "GovWifi" {
		t.Fatalf("organization = %v", cert.Subject.Organization)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatal("expected a CA certificate")
	}
	if cert.MaxPathLen != pathLen || cert.MaxPathLenZero != (pathLen == 0) {
		t.Fatalf("pathlen = %d (zero=%v), want %d", cert.MaxPathLen, cert.MaxPathLenZero, pathLen)
	}
	wantUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage != wantUsage {
		t.Fatalf("key usage = %v, want %v", cert.KeyUsage, wantUsage)
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("signature algorithm = %s", cert.SignatureAlgorithm)
	}
}
