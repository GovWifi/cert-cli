package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
)

func TestCertificateText(t *testing.T) {
	key := testRSAKey(t)
	certPEM, err := CreateSelfSignedCertificate(key, "text-root", []string{"wifi.example"}, testNotBefore, testNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := PemToCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	text := CertificateText(cert)
	for _, want := range []string{
		"Certificate:",
		"Serial Number:",
		"sha256WithRSAEncryption",
		"C = GB",
		"O = GovWifi",
		"CN = text-root",
		"Not Before: Oct  1 00:00:00 2026 GMT",
		"Not After : Oct  1 23:59:59 2027 GMT",
		"Public Key Algorithm: rsaEncryption",
		"Public-Key: (2048 bit)",
		"Digital Signature, Certificate Sign, CRL Sign",
		"CA:TRUE, pathlen:1",
		"DNS:wifi.example",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("certificate text missing %q\n%s", want, text)
		}
	}
}

func TestCertificateTextNonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	text := CertificateText(&x509.Certificate{
		Version:            3,
		SerialNumber:       big.NewInt(15),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          &ecKey.PublicKey,
		NotBefore:          testNotBefore,
		NotAfter:           testNotAfter,
		Subject:            pkix.Name{CommonName: "leaf", OrganizationalUnit: []string{"Ops"}},
		Issuer:             pkix.Name{CommonName: "issuer"},
	})

	for _, want := range []string{
		"0F",
		"OU = Ops",
		"CN = leaf",
		"CN = issuer",
		"(unsupported public key type)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("certificate text missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "X509v3 Key Usage:") {
		t.Fatal("did not expect key usage for an empty usage set")
	}
}
