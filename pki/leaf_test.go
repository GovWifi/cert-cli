package pki

import (
	"crypto/x509"
	"testing"
)

func TestLeafCommonName(t *testing.T) {
	if got := LeafCommonName(1); got != "GovWifi Leaf 1" {
		t.Fatalf("LeafCommonName(1) = %q", got)
	}
	if got := LeafCommonName(12); got != "GovWifi Leaf 12" {
		t.Fatalf("LeafCommonName(12) = %q", got)
	}
}

func TestCreateLeafCertificate(t *testing.T) {
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

	leafKey := testRSAKey(t)
	leafPEM, err := CreateLeafCertificate(interCert, interKey, leafKey, LeafCommonName(2), testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := PemToCertificate(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	assertLeafCert(t, leaf, "GovWifi Leaf 2")
	if !leaf.NotBefore.Equal(testNotBefore) || !leaf.NotAfter.Equal(testNotAfter) {
		t.Fatalf("validity %s – %s", leaf.NotBefore, leaf.NotAfter)
	}
	if err := CheckSignedBy(leaf, interCert); err != nil {
		t.Fatal(err)
	}
	if err := CheckSignedBy(leaf, rootCert); err == nil {
		t.Fatal("expected the leaf to be signed by the intermediate, not the root")
	}
	if leaf.Issuer.CommonName != "inter" {
		t.Fatalf("issuer CN = %q", leaf.Issuer.CommonName)
	}
}

func TestCreateLeafCertificateRejectsMismatchedIssuerKey(t *testing.T) {
	issuerKey := testRSAKey(t)
	issuerPEM, err := CreateSelfSignedCertificate(issuerKey, "issuer", nil, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := PemToCertificate(issuerPEM)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CreateLeafCertificate(issuer, testRSAKey(t), testRSAKey(t), "leaf", testNotBefore, testNotAfter)
	if err == nil {
		t.Fatal("expected error when the issuer key does not match the issuer certificate")
	}
}

func TestCreateChainRejectsLeafCount(t *testing.T) {
	for _, count := range []int{-1, 0, MaxLeafCount + 1} {
		if _, err := CreateChain(count, testNotBefore); err == nil {
			t.Fatalf("count %d: expected error", count)
		}
	}
}

func TestCreateCustomChainUsesSubjectAndValidity(t *testing.T) {
	rootStart := testNotBefore
	rootExpiry := testNotBefore.AddDate(10, 0, 0)
	interStart := testNotBefore.AddDate(0, 1, 0)
	interExpiry := testNotBefore.AddDate(5, 0, 0)
	leafStart := testNotBefore.AddDate(0, 2, 0)
	leafExpiry := testNotBefore.AddDate(1, 0, 0)

	chain, err := CreateCustomChain(ChainOptions{
		Organization:   "Test Org",
		RootCN:         "Test Root",
		IntermediateCN: "Test Intermediate",
		LeafCount:      1,
		RootNotBefore:  rootStart,
		RootNotAfter:   rootExpiry,
		InterNotBefore: interStart,
		InterNotAfter:  interExpiry,
		LeafNotBefore:  leafStart,
		LeafNotAfter:   leafExpiry,
	})
	if err != nil {
		t.Fatal(err)
	}

	if chain.Root.Cert.Subject.CommonName != "Test Root" {
		t.Fatalf("root CN = %q", chain.Root.Cert.Subject.CommonName)
	}
	if len(chain.Root.Cert.Subject.Organization) != 1 || chain.Root.Cert.Subject.Organization[0] != "Test Org" {
		t.Fatalf("root organization = %v", chain.Root.Cert.Subject.Organization)
	}
	if !chain.Root.Cert.NotBefore.Equal(rootStart) || !chain.Root.Cert.NotAfter.Equal(rootExpiry) {
		t.Fatalf("root validity %s – %s", chain.Root.Cert.NotBefore, chain.Root.Cert.NotAfter)
	}

	if chain.Intermediate.Cert.Subject.CommonName != "Test Intermediate" {
		t.Fatalf("intermediate CN = %q", chain.Intermediate.Cert.Subject.CommonName)
	}
	if !chain.Intermediate.Cert.NotBefore.Equal(interStart) || !chain.Intermediate.Cert.NotAfter.Equal(interExpiry) {
		t.Fatalf("intermediate validity %s – %s", chain.Intermediate.Cert.NotBefore, chain.Intermediate.Cert.NotAfter)
	}
	if err := CheckSignedBy(chain.Intermediate.Cert, chain.Root.Cert); err != nil {
		t.Fatal(err)
	}

	leaf := chain.Leaves[0].Cert
	if leaf.Subject.CommonName != LeafCommonName(1) {
		t.Fatalf("leaf CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != "Test Org" {
		t.Fatalf("leaf organization = %v", leaf.Subject.Organization)
	}
	if !leaf.NotBefore.Equal(leafStart) || !leaf.NotAfter.Equal(leafExpiry) {
		t.Fatalf("leaf validity %s – %s", leaf.NotBefore, leaf.NotAfter)
	}
	if err := CheckSignedBy(leaf, chain.Intermediate.Cert); err != nil {
		t.Fatal(err)
	}
}

func assertLeafCert(t *testing.T, cert *x509.Certificate, cn string) {
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
	if cert.IsCA {
		t.Fatal("expected an end-entity certificate")
	}
	if !cert.BasicConstraintsValid {
		t.Fatal("expected basic constraints")
	}
	wantUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if cert.KeyUsage != wantUsage {
		t.Fatalf("key usage = %v, want %v", cert.KeyUsage, wantUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ext key usage = %v", cert.ExtKeyUsage)
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("signature algorithm = %s", cert.SignatureAlgorithm)
	}
}
